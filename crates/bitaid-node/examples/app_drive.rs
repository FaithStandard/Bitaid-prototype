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
                    Event::ReadyToAlert { .. } => commands::send(Command::RaiseAlert),
                    Event::Alert { case, .. } => {
                        alerts += 1;
                        commands::send(Command::Accept { case });
                    }
                    Event::BallotDue { case, .. } => {
                        commands::send(Command::Vote { case, classes: ballot.clone(), achieved: true })
                    }
                    Event::Fatal { text, .. } => {
                        eprintln!("[app] the role died: {text}");
                        std::process::exit(101);
                    }
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
