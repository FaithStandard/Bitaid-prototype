//! What a running role reports, for an app that drives it (M4): every log line, every check with its
//! verdict, the role's summary, and a fatal end. The binary prints these; an app also receives them
//! through the sink it sets, so its screen never shows a role "on duty" after the role has died.

use std::sync::mpsc::Sender;
use std::sync::Mutex;

#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub enum Event {
    /// a line of the role's log
    Log { node: String, text: String },
    /// a check the role made, passed or failed, with its detail
    Check { node: String, what: String, ok: bool, detail: String },
    /// the role finished: its checks passed and failed
    Summary { node: String, passed: u32, failed: u32 },
    /// the role stopped on a fault (a panic in its thread): whatever the app showed is no longer true
    Fatal { node: String, text: String },
    /// a non-fatal security or operational warning (e.g. Core distrusted; signing disabled while alerts stay active)
    Warning { node: String, text: String },
    /// an alert in the responder's cells passed its checks: the app shows it, and with
    /// `--ask-accept` the role waits for Accept or Decline
    Alert { node: String, case: String, cell: String, deposit: u64, reward: u64, bounty: u64 },
    /// an alert matched the responder's `--auto-accept` policy and was accepted without prompting
    AutoAccepted {
        node: String,
        case: String,
        cell: String,
        max_distance_m: u32,
        deposit: u64,
        reward: u64,
        bounty: u64,
    },
    /// the exact location, opened the moment it arrives (§13): what the responder drives to
    Location { node: String, case: String, lat: f64, lon: f64 },
    /// with `--ask-vote`, the role waits for the attendee's ballot on this case until the commit window closes
    BallotDue {
        node: String,
        case: String,
        seats: usize,
        my_seat: usize,
        remaining_blocks: u32,
        remaining_secs: u64,
    },
    /// the ballot commit window closed without a vote (or after the prompt ended)
    BallotClosed { node: String, case: String },
    /// the caller's pool is ready: with `--ask-alert` the role waits for RaiseAlert
    ReadyToAlert { node: String },
    /// the responder has found the pool, posted its bond and now listens for alerts in these cells:
    /// what an app shows as on duty (before it, the node is still connecting)
    Listening { node: String, home: String, cells: usize },
}

static SINK: Mutex<Option<Sender<Event>>> = Mutex::new(None);

/// Where the events go, besides the console: set once by the app before it starts a role.
pub fn set_sink(tx: Sender<Event>) {
    APP.store(true, std::sync::atomic::Ordering::Release);
    *SINK.lock().unwrap_or_else(|e| e.into_inner()) = Some(tx);
}

/// Set for good once an app attaches a sink: a thread left over from an earlier role must not
/// exit the app's process after the sink is cleared.
static APP: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Whether an app has ever attached a sink in this process (the binary never does).
pub fn attached() -> bool {
    APP.load(std::sync::atomic::Ordering::Acquire)
}

/// Drops the app's sink: once the events already sent are read, its receiver ends. For an app to
/// learn a role has ended after its last event, not before it (review of M4 steps 3-5).
pub fn clear_sink() {
    *SINK.lock().unwrap_or_else(|e| e.into_inner()) = None;
}

/// Sends an event to the app's sink, if one is set (the binary sets none).
pub fn emit(e: Event) {
    if let Some(tx) = SINK.lock().unwrap_or_else(|e| e.into_inner()).as_ref() {
        let _ = tx.send(e);
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
