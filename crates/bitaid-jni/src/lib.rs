//! Thin JNI boundary over `bitaid-node` and `bitaid-tor` for the Android app (M4).
//!
//! Design invariants:
//! - Every `extern "system"` entry point is wrapped in `catch_unwind`; no panic crosses FFI.
//! - The Tor SOCKS secret (`BITAID_SOCKS`) never crosses JNI into Kotlin and is never logged:
//!   `startRole` injects `tor.listener.socks("main")` directly into `bitaid_node::config` in Rust.
//! - `SecretStore` calls back into Kotlin's Tink/Keystore store, so no secret touches flash in
//!   plaintext.
//! - At most one role runs at a time (`ROLE_RUNNING`), matching `bitaid-node`'s process-wide
//!   `config`/`commands`/`events` state.

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
use std::sync::atomic::{AtomicBool, Ordering};
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

/// Bridges `bitaid_node::secrets::SecretStore` to Kotlin's Tink/Keystore implementation.
struct JniSecretStore {
    vm: JavaVM,
    obj: GlobalRef,
}

impl SecretStore for JniSecretStore {
    fn get(&self, name: &str) -> Option<Vec<u8>> {
        let mut env = self.vm.attach_current_thread().ok()?;
        env.with_local_frame(16, |env| -> jni::errors::Result<Option<Vec<u8>>> {
            let jname = env.new_string(name)?;
            let res = env.call_method(
                &self.obj,
                "get",
                "(Ljava/lang/String;)[B",
                &[JValue::Object(&jname)],
            );
            if clear_exc(env) {
                return Ok(None);
            }
            let obj = res?.l()?;
            if obj.is_null() {
                return Ok(None);
            }
            let arr = JByteArray::from(obj);
            Ok(Some(env.convert_byte_array(arr)?))
        })
        .ok()
        .flatten()
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
/// `settings_json`: JSON object `{"KEY":"VAL"}`. `BITAID_SOCKS` is injected from in-process `Tor`.
/// `args_json`: JSON array of CLI args, starting with `"bitaid-node"`.
/// Returns `true` if started, `false` if another role is already running or inputs are invalid.
#[no_mangle]
pub extern "system" fn Java_com_bitaid_app_NativeBridge_startRole(
    mut env: JNIEnv,
    _class: JClass,
    settings_json: JString,
    args_json: JString,
    listener: JObject,
) -> jboolean {
    catch_unwind(AssertUnwindSafe(|| {
        if listener.is_null() {
            return JNI_FALSE;
        }
        let Some(s_json) = get_string(&mut env, &settings_json) else {
            return JNI_FALSE;
        };
        let Some(a_json) = get_string(&mut env, &args_json) else {
            return JNI_FALSE;
        };
        let Ok(mut settings) = serde_json::from_str::<HashMap<String, String>>(&s_json) else {
            return JNI_FALSE;
        };
        let Ok(args) = serde_json::from_str::<Vec<String>>(&a_json) else {
            return JNI_FALSE;
        };
        let Ok(vm) = env.get_java_vm() else {
            return JNI_FALSE;
        };
        let Ok(cb) = env.new_global_ref(listener) else {
            return JNI_FALSE;
        };
        if ROLE_RUNNING
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return JNI_FALSE;
        }

        // Inject the authenticated loopback SOCKS proxy directly in Rust so the secret never
        // crosses JNI or appears in Kotlin strings/logs.
        if let Some(tor) = TOR.lock().unwrap_or_else(|e| e.into_inner()).clone() {
            settings.insert("BITAID_SOCKS".into(), tor.listener.socks("main"));
        }
        bitaid_node::config::set(settings);

        let (tx, rx) = std::sync::mpsc::channel::<Event>();
        events::set_sink(tx);

        let cb_events = cb.clone();
        let vm_events = match env.get_java_vm() {
            Ok(v) => v,
            Err(_) => {
                ROLE_RUNNING.store(false, Ordering::Release);
                return JNI_FALSE;
            }
        };

        // Dedicated event pump: drains events until the role exits and drops its Sender.
        let _ = std::thread::Builder::new()
            .name("bitaid-events".into())
            .spawn(move || {
                while let Ok(ev) = rx.recv() {
                    deliver_event(&vm_events, &cb_events, &WireEvent::from(ev));
                }
            });

        let spawn_res = std::thread::Builder::new()
            .name("bitaid-role".into())
            .spawn(move || {
                let _guard = RunningGuard;
                let code = bitaid_node::roles::run(args);
                deliver_event(&vm, &cb, &WireEvent::RoleExited { code });
            });

        if spawn_res.is_err() {
            ROLE_RUNNING.store(false, Ordering::Release);
            return JNI_FALSE;
        }
        JNI_TRUE
    }))
    .unwrap_or(JNI_FALSE)
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
) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        let Some(case) = get_string(&mut env, &case_id) else {
            return;
        };
        let Some(cj) = get_string(&mut env, &classes_json) else {
            return;
        };
        let Ok(classes) = serde_json::from_str::<Vec<String>>(&cj) else {
            return;
        };
        commands::send(Command::Vote {
            case,
            classes,
            achieved: achieved != JNI_FALSE,
            misuse: misuse != JNI_FALSE,
        });
    }));
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
