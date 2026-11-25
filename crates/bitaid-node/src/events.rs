//! What a running role reports, for an app that drives it (M4): every log line, every check with its
//! verdict, the role's summary, and a fatal end. The binary prints these; an app also receives them
//! through the sink it sets, so its screen never shows a role "on duty" after the role has died.

use std::sync::mpsc::Sender;
use std::sync::Mutex;

#[derive(Clone, Debug, PartialEq)]
pub enum Event {
    /// a line of the role's log
    Log { node: String, text: String },
    /// a check the role made, passed or failed, with its detail
    Check { node: String, what: String, ok: bool, detail: String },
    /// the role finished: its checks passed and failed
    Summary { node: String, passed: u32, failed: u32 },
    /// the role stopped on a fault (a panic in its thread): whatever the app showed is no longer true
    Fatal { node: String, text: String },
}

static SINK: Mutex<Option<Sender<Event>>> = Mutex::new(None);

/// Where the events go, besides the console: set once by the app before it starts a role.
pub fn set_sink(tx: Sender<Event>) {
    if let Ok(mut s) = SINK.lock() {
        *s = Some(tx);
    }
}

/// Sends an event to the app's sink, if one is set (the binary sets none).
pub fn emit(e: Event) {
    if let Ok(s) = SINK.lock() {
        if let Some(tx) = s.as_ref() {
            let _ = tx.send(e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sink_receives() {
        let (tx, rx) = std::sync::mpsc::channel();
        set_sink(tx);
        emit(Event::Log { node: "n".into(), text: "hello".into() });
        assert_eq!(rx.recv().unwrap(), Event::Log { node: "n".into(), text: "hello".into() });
    }
}
