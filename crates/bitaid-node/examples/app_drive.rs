//! Drives a role the way the Android app will (M4): settings passed in, not read from the
//! environment; the role run on its own thread through `bitaid_node::roles::run`; events read from
//! the library and answered with commands. Stands in for the app in the regtest suites (`APP=1`).
//!
//!   app_drive <the role's arguments, as for bitaid-node> --ask-accept --ask-vote
//!   app_drive ... --role caller ... --ask-alert
//!
//! It answers as a user would: accepts every alert, presses the alert once the pool is ready, and
//! votes the classes in APP_BALLOT (e.g. "I,D", one per seat). Prints every event on stderr, and the
//! role's checks and summary on stdout as the binary does.
use bitaid_node::commands::{self, Command};
use bitaid_node::events::{self, Event};
use std::collections::HashMap;

/// The app's secret store, as a stand-in: a folder of its own (the real app encrypts under the
/// Keystore). Installing it shows every secret the role makes goes through the store, none to the
/// node's own files.
struct DirStore(std::path::PathBuf);
impl bitaid_node::secrets::SecretStore for DirStore {
    fn get(&self, name: &str) -> Option<Vec<u8>> {
        std::fs::read(self.0.join(name)).ok()
    }
    fn put(&self, name: &str, data: &[u8]) -> std::io::Result<()> {
        std::fs::create_dir_all(&self.0)?;
        std::fs::write(self.0.join(name), data)
    }
    fn append(&self, name: &str, line: &str) -> std::io::Result<()> {
        use std::io::Write;
        std::fs::create_dir_all(&self.0)?;
        std::fs::OpenOptions::new().create(true).append(true).open(self.0.join(name))?.write_all(line.as_bytes())
    }
}

fn main() {
    // the settings, as the app would hand them over (here from this process's environment, once,
    // before any role thread exists)
    let settings: HashMap<String, String> =
        std::env::vars().filter(|(k, _)| k.starts_with("BITAID_") || k == "HOME").collect();
    let ballot: Vec<String> = settings
        .get("BITAID_APP_BALLOT")
        .cloned()
        .unwrap_or_else(|| "I,D".into())
        .split(',')
        .map(|x| x.trim().to_string())
        .collect();
    let store = settings
        .get("BITAID_LINK_DIR")
        .cloned()
        .unwrap_or_else(|| format!("{}/.bitaid", settings.get("HOME").cloned().unwrap_or(".".into())));
    bitaid_node::secrets::set_store(std::sync::Arc::new(DirStore(std::path::Path::new(&store).join("app-store"))));
    bitaid_node::config::set(settings);
    let (tx, rx) = std::sync::mpsc::channel();
    events::set_sink(tx);
    let args: Vec<String> = std::env::args().collect();
    let role = std::thread::spawn(move || bitaid_node::roles::run(args));
    let mut alerts = 0;
    loop {
        match rx.recv_timeout(std::time::Duration::from_secs(1)) {
            Ok(e) => {
                match &e {
                    Event::Log { .. } | Event::Check { .. } => {}
                    other => eprintln!("[app] event {other:?}"),
                }
                match e {
                    Event::ReadyToAlert { .. } => commands::send(Command::RaiseAlert { at: None }),
                    Event::Alert { case, .. } => {
                        alerts += 1;
                        commands::send(Command::Accept { case });
                    }
                    Event::BallotDue { case, .. } => {
                        commands::send(Command::Vote { case, classes: ballot.clone(), achieved: true, misuse: false })
                    }
                    // shown, never hidden: a real app would mark the node down until it restarts it
                    Event::Fatal { text, .. } => eprintln!("[app] FATAL: {text}"),
                    _ => {}
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                if role.is_finished() {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    let code = role.join().unwrap_or(101);
    eprintln!("[app] role ended with {code} after {alerts} alert(s)");
    std::process::exit(code);
}
