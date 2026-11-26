//! Thin JNI boundary over `bitaid-node` and `bitaid-tor` for the Android app (M4).
//!
//! Design invariants:
//! - Every `extern "system"` entry point is wrapped in `catch_unwind`; no panic crosses FFI.
//! - The Tor SOCKS secret (`BITAID_SOCKS`) never crosses JNI into Kotlin and is never logged:
//!   `startRole` injects `tor.listener.socks("main")` directly into `bitaid_node::config` in Rust.
//! - Fail-closed networking: `startRole` refuses to start unless `Tor` is running, and refuses any
//!   `BITAID_RPC` or `--peer` host that is not `.onion`.
//! - `SecretStore::get` distinguishes `Ok(None)` (absent) from `Err` (unreadable / decrypt failure).
//! - Single-threaded ordered event delivery: the role thread stores its exit code and calls
//!   `events::clear_sink()`, and the `bitaid-events` pump emits `RoleExited` only after draining
//!   every buffered `Event`.

use bitaid_node::commands::{self, Command};
use bitaid_node::events::{self, Event};
use bitaid_node::secrets::{self, SecretStore};
use bitaid_tor::Tor;
use jni::objects::{GlobalRef, JByteArray, JClass, JObject, JString, JValue};
use jni::sys::{jboolean, jdouble, jstring, JNI_FALSE, JNI_TRUE};
use jni::{JNIEnv, JavaVM};
use serde::Serialize;
use std::collections::HashMap;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::{Arc, Mutex};

static TOR: Mutex<Option<Arc<Tor>>> = Mutex::new(None);
static ROLE_RUNNING: AtomicBool = AtomicBool::new(false);

fn get_string(env: &mut JNIEnv, s: &JString) -> Option<String> {
    if s.is_null() {
        return None;
    }
    env.get_string(s).ok().map(Into::into)
}

fn to_jstring(env: &mut JNIEnv, s: &str) -> jstring {
    env.new_string(s)
        .map(JString::into_raw)
        .unwrap_or(std::ptr::null_mut())
}

fn clear_exc(env: &mut JNIEnv) -> bool {
    if env.exception_check().unwrap_or(false) {
        let _ = env.exception_clear();
        true
    } else {
        false
    }
}

/// Checks that a URL (`http://user:pass@host:port/path`) or `host:port` targets a `.onion` host.
fn is_onion_target(raw: &str) -> bool {
    let after_scheme = raw.split("://").nth(1).unwrap_or(raw);
    let authority = after_scheme.split('/').next().unwrap_or("");
    let host_port = authority.rsplit('@').next().unwrap_or("");
    let host = host_port.split(':').next().unwrap_or("");
    host.ends_with(".onion") && host.len() > ".onion".len()
}

/// Bridges `bitaid_node::secrets::SecretStore` to Kotlin's Tink/Keystore implementation.
struct JniSecretStore {
    vm: JavaVM,
    obj: GlobalRef,
}

impl SecretStore for JniSecretStore {
    fn get(&self, name: &str) -> std::io::Result<Option<Vec<u8>>> {
        let mut env = self
            .vm
            .attach_current_thread()
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        env.with_local_frame(16, |env| -> jni::errors::Result<std::io::Result<Option<Vec<u8>>>> {
            let jname = env.new_string(name)?;
            let res = env.call_method(
                &self.obj,
                "get",
                "(Ljava/lang/String;)[B",
                &[JValue::Object(&jname)],
            );
            if clear_exc(env) {
                return Ok(Err(std::io::Error::other(format!(
                    "SecretStore.get({name}) threw an exception"
                ))));
            }
            let obj = res?.l()?;
            if obj.is_null() {
                return Ok(Ok(None));
            }
            let arr = JByteArray::from(obj);
            Ok(Ok(Some(env.convert_byte_array(arr)?)))
        })
        .map_err(|e| std::io::Error::other(e.to_string()))?
    }

    fn put(&self, name: &str, data: &[u8]) -> std::io::Result<()> {
        let mut env = self
            .vm
            .attach_current_thread()
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        let ok = env
            .with_local_frame(16, |env| -> jni::errors::Result<bool> {
                let jname = env.new_string(name)?;
                let jdata = env.byte_array_from_slice(data)?;
                let res = env.call_method(
                    &self.obj,
                    "put",
                    "(Ljava/lang/String;[B)Z",
                    &[JValue::Object(&jname), JValue::Object(&jdata)],
                );
                if clear_exc(env) {
                    return Ok(false);
                }
                res?.z()
            })
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        if ok {
            Ok(())
        } else {
            Err(std::io::Error::other("SecretStore.put failed"))
        }
    }

    fn append(&self, name: &str, line: &str) -> std::io::Result<()> {
        let mut env = self
            .vm
            .attach_current_thread()
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        let ok = env
            .with_local_frame(16, |env| -> jni::errors::Result<bool> {
                let jname = env.new_string(name)?;
                let jline = env.new_string(line)?;
                let res = env.call_method(
                    &self.obj,
                    "append",
                    "(Ljava/lang/String;Ljava/lang/String;)Z",
                    &[JValue::Object(&jname), JValue::Object(&jline)],
                );
                if clear_exc(env) {
                    return Ok(false);
                }
                res?.z()
            })
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        if ok {
            Ok(())
        } else {
            Err(std::io::Error::other("SecretStore.append failed"))
        }
    }
}

/// JSON wire shape delivered to Kotlin's `EventCallback.onEvent(String)`.
#[derive(Serialize)]
#[serde(tag = "type")]
enum WireEvent {
    Log {
        node: String,
        text: String,
    },
    Check {
        node: String,
        what: String,
        ok: bool,
        detail: String,
    },
    Summary {
        node: String,
        passed: u32,
        failed: u32,
    },
    Fatal {
        node: String,
        text: String,
    },
    Alert {
        node: String,
        case: String,
        cell: String,
        deposit: u64,
        reward: u64,
        bounty: u64,
    },
    Location {
        node: String,
        case: String,
        lat: f64,
        lon: f64,
    },
    BallotDue {
        node: String,
        case: String,
        seats: usize,
        my_seat: usize,
    },
    ReadyToAlert {
        node: String,
    },
    Listening {
        node: String,
        home: String,
        cells: usize,
    },
    RoleExited {
        code: i32,
    },
}

impl From<Event> for WireEvent {
    fn from(e: Event) -> Self {
        match e {
            Event::Log { node, text } => WireEvent::Log { node, text },
            Event::Check {
                node,
                what,
                ok,
                detail,
            } => WireEvent::Check {
                node,
                what,
                ok,
                detail,
            },
            Event::Summary {
                node,
                passed,
                failed,
            } => WireEvent::Summary {
                node,
                passed,
                failed,
            },
            Event::Fatal { node, text } => WireEvent::Fatal { node, text },
            Event::Alert {
                node,
                case,
                cell,
                deposit,
                reward,
                bounty,
            } => WireEvent::Alert {
                node,
                case,
                cell,
                deposit,
                reward,
                bounty,
            },
            Event::Location {
                node,
                case,
                lat,
                lon,
            } => WireEvent::Location {
                node,
                case,
                lat,
                lon,
            },
            Event::BallotDue {
                node,
                case,
                seats,
                my_seat,
            } => WireEvent::BallotDue {
                node,
                case,
                seats,
                my_seat,
            },
            Event::ReadyToAlert { node } => WireEvent::ReadyToAlert { node },
            Event::Listening { node, home, cells } => WireEvent::Listening { node, home, cells },
            // an event this build does not know yet (Event is non_exhaustive): shown as a log line
            other => WireEvent::Log { node: String::new(), text: format!("{other:?}") },
        }
    }
}

fn deliver_event(vm: &JavaVM, cb: &GlobalRef, ev: &WireEvent) {
    let Ok(json) = serde_json::to_string(ev) else {
        return;
    };
    let Ok(mut env) = vm.attach_current_thread() else {
        return;
    };
    let _ = env.with_local_frame(16, |env| -> jni::errors::Result<()> {
        let jstr = env.new_string(&json)?;
        let _ = env.call_method(
            cb,
            "onEvent",
            "(Ljava/lang/String;)V",
            &[JValue::Object(&jstr)],
        );
        let _ = clear_exc(env);
        Ok(())
    });
}

struct RunningGuard;
impl Drop for RunningGuard {
    fn drop(&mut self) {
        events::clear_sink();
        ROLE_RUNNING.store(false, Ordering::Release);
    }
}

/// Installs Kotlin's Tink/Keystore `SecretStore`. Must be called before `startRole`.
#[no_mangle]
pub extern "system" fn Java_com_bitaid_app_NativeBridge_installSecretStore(
    env: JNIEnv,
    _class: JClass,
    store: JObject,
) -> jboolean {
    catch_unwind(AssertUnwindSafe(|| {
        if store.is_null() {
            return JNI_FALSE;
        }
        let Ok(vm) = env.get_java_vm() else {
            return JNI_FALSE;
        };
        let Ok(obj) = env.new_global_ref(store) else {
            return JNI_FALSE;
        };
        secrets::set_store(Arc::new(JniSecretStore { vm, obj }));
        JNI_TRUE
    }))
    .unwrap_or(JNI_FALSE)
}

/// Starts in-process Arti Tor. Returns `""` on success or an error message on failure.
/// The SOCKS secret is kept inside Rust and never returned to Kotlin.
#[no_mangle]
pub extern "system" fn Java_com_bitaid_app_NativeBridge_startTor(
    mut env: JNIEnv,
    _class: JClass,
    state_dir: JString,
    cache_dir: JString,
) -> jstring {
    catch_unwind(AssertUnwindSafe(|| {
        let Some(state) = get_string(&mut env, &state_dir) else {
            return to_jstring(&mut env, "invalid state_dir");
        };
        let Some(cache) = get_string(&mut env, &cache_dir) else {
            return to_jstring(&mut env, "invalid cache_dir");
        };
        {
            let guard = TOR.lock().unwrap_or_else(|e| e.into_inner());
            if guard.is_some() {
                return to_jstring(&mut env, "");
            }
        }
        match Tor::start(&state, &cache) {
            Ok(tor) => {
                *TOR.lock().unwrap_or_else(|e| e.into_inner()) = Some(Arc::new(tor));
                to_jstring(&mut env, "")
            }
            Err(e) => to_jstring(&mut env, &e),
        }
    }))
    .unwrap_or(std::ptr::null_mut())
}

#[no_mangle]
pub extern "system" fn Java_com_bitaid_app_NativeBridge_stopTor(_env: JNIEnv, _class: JClass) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        let _old = TOR.lock().unwrap_or_else(|e| e.into_inner()).take();
    }));
}

#[no_mangle]
pub extern "system" fn Java_com_bitaid_app_NativeBridge_setTorDormant(
    _env: JNIEnv,
    _class: JClass,
    soft: jboolean,
) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if let Some(tor) = TOR.lock().unwrap_or_else(|e| e.into_inner()).clone() {
            tor.set_dormant(soft != JNI_FALSE);
        }
    }));
}

#[no_mangle]
pub extern "system" fn Java_com_bitaid_app_NativeBridge_torNetworkChanged(
    _env: JNIEnv,
    _class: JClass,
) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if let Some(tor) = TOR.lock().unwrap_or_else(|e| e.into_inner()).clone() {
            tor.network_changed();
        }
    }));
}

/// Starts one `bitaid-node` role on a background thread.
/// Returns `""` on success, or a human-readable refusal reason on failure.
/// Fail-closed: refuses to start unless `Tor` is running and every `BITAID_RPC` and `--peer`
/// targets a `.onion` host.
#[no_mangle]
pub extern "system" fn Java_com_bitaid_app_NativeBridge_startRole(
    mut env: JNIEnv,
    _class: JClass,
    settings_json: JString,
    args_json: JString,
    listener: JObject,
) -> jstring {
    catch_unwind(AssertUnwindSafe(|| {
        if listener.is_null() {
            return to_jstring(&mut env, "missing event listener");
        }
        let Some(tor) = TOR.lock().unwrap_or_else(|e| e.into_inner()).clone() else {
            return to_jstring(&mut env, "Tor is not running");
        };
        let Some(s_json) = get_string(&mut env, &settings_json) else {
            return to_jstring(&mut env, "invalid settings JSON");
        };
        let Some(a_json) = get_string(&mut env, &args_json) else {
            return to_jstring(&mut env, "invalid args JSON");
        };
        let Ok(mut settings) = serde_json::from_str::<HashMap<String, String>>(&s_json) else {
            return to_jstring(&mut env, "malformed settings JSON");
        };
        let Ok(args) = serde_json::from_str::<Vec<String>>(&a_json) else {
            return to_jstring(&mut env, "malformed args JSON");
        };

        // Fail closed against clearnet leaks: RPC and every peer must be .onion.
        if let Some(rpc) = settings.get("BITAID_RPC") {
            if !rpc.is_empty() && !is_onion_target(rpc) {
                return to_jstring(&mut env, "RPC URL must be .onion");
            }
        }
        let mut iter = args.iter();
        while let Some(a) = iter.next() {
            if a == "--peer" {
                match iter.next() {
                    Some(p) if is_onion_target(p) => {}
                    _ => return to_jstring(&mut env, "peer address must be .onion"),
                }
            }
        }

        let Ok(vm_events) = env.get_java_vm() else {
            return to_jstring(&mut env, "JVM unavailable");
        };
        let Ok(cb_events) = env.new_global_ref(listener) else {
            return to_jstring(&mut env, "failed to retain listener");
        };
        if ROLE_RUNNING
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return to_jstring(&mut env, "role still running");
        }

        // Inject the authenticated loopback SOCKS proxy directly in Rust so the secret never
        // crosses JNI or appears in Kotlin strings/logs.
        settings.insert("BITAID_SOCKS".into(), tor.listener.socks("main"));
        // and the node itself refuses every non-onion address, whatever it is given (the checks
        // above cover BITAID_RPC and --peer only)
        settings.insert("BITAID_ONION_ONLY".into(), "1".into());
        bitaid_node::config::set(settings);

        let (tx, rx) = std::sync::mpsc::channel::<Event>();
        events::set_sink(tx);

        let exit_code = Arc::new(AtomicI32::new(101));
        let exit_code_role = exit_code.clone();

        // Single event-delivering thread: drains every buffered event in order, then emits
        // RoleExited once the role thread calls events::clear_sink().
        let pump_res = std::thread::Builder::new()
            .name("bitaid-events".into())
            .spawn(move || {
                while let Ok(ev) = rx.recv() {
                    deliver_event(&vm_events, &cb_events, &WireEvent::from(ev));
                }
                let code = exit_code.load(Ordering::Acquire);
                deliver_event(&vm_events, &cb_events, &WireEvent::RoleExited { code });
            });
        if pump_res.is_err() {
            events::clear_sink();
            ROLE_RUNNING.store(false, Ordering::Release);
            return to_jstring(&mut env, "failed to start event thread");
        }

        let role_res = std::thread::Builder::new()
            .name("bitaid-role".into())
            .spawn(move || {
                let _guard = RunningGuard;
                let code = bitaid_node::roles::run(args);
                exit_code_role.store(code, Ordering::Release);
            });

        if role_res.is_err() {
            events::clear_sink();
            ROLE_RUNNING.store(false, Ordering::Release);
            return to_jstring(&mut env, "failed to start role thread");
        }
        to_jstring(&mut env, "")
    }))
    // never null: Kotlin reads the result as a non-null String
    .unwrap_or_else(|_| to_jstring(&mut env, "internal error starting the role"))
}

#[no_mangle]
pub extern "system" fn Java_com_bitaid_app_NativeBridge_sendRaiseAlert(
    _env: JNIEnv,
    _class: JClass,
    has_loc: jboolean,
    lat: jdouble,
    lon: jdouble,
) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        let at = if has_loc != JNI_FALSE {
            Some((lat, lon))
        } else {
            None
        };
        commands::send(Command::RaiseAlert { at });
    }));
}

#[no_mangle]
pub extern "system" fn Java_com_bitaid_app_NativeBridge_sendAccept(
    mut env: JNIEnv,
    _class: JClass,
    case_id: JString,
) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if let Some(case) = get_string(&mut env, &case_id) {
            commands::send(Command::Accept { case });
        }
    }));
}

#[no_mangle]
pub extern "system" fn Java_com_bitaid_app_NativeBridge_sendDecline(
    mut env: JNIEnv,
    _class: JClass,
    case_id: JString,
) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if let Some(case) = get_string(&mut env, &case_id) {
            commands::send(Command::Decline { case });
        }
    }));
}

#[no_mangle]
pub extern "system" fn Java_com_bitaid_app_NativeBridge_sendVote(
    mut env: JNIEnv,
    _class: JClass,
    case_id: JString,
    classes_json: JString,
    achieved: jboolean,
    misuse: jboolean,
) -> jboolean {
    catch_unwind(AssertUnwindSafe(|| {
        let Some(case) = get_string(&mut env, &case_id) else {
            return JNI_FALSE;
        };
        let Some(cj) = get_string(&mut env, &classes_json) else {
            return JNI_FALSE;
        };
        let Ok(classes) = serde_json::from_str::<Vec<String>>(&cj) else {
            return JNI_FALSE;
        };
        if classes.is_empty() {
            return JNI_FALSE;
        }
        commands::send(Command::Vote {
            case,
            classes,
            achieved: achieved != JNI_FALSE,
            misuse: misuse != JNI_FALSE,
        });
        JNI_TRUE
    }))
    .unwrap_or(JNI_FALSE)
}

#[no_mangle]
pub extern "system" fn Java_com_bitaid_app_NativeBridge_sendOffDuty(
    _env: JNIEnv,
    _class: JClass,
) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        commands::send(Command::OffDuty);
    }));
}

#[cfg(test)]
mod tests {
    use super::is_onion_target;

    #[test]
    fn onion_target_check() {
        assert!(is_onion_target("http://user:pass@abc123.onion:38332/wallet/w"));
        assert!(is_onion_target("abc123.onion:7470"));
        assert!(!is_onion_target("http://user:pass@127.0.0.1:38332"));
        assert!(!is_onion_target("example.com:7470"));
        assert!(!is_onion_target(".onion:7470"));
    }
}
