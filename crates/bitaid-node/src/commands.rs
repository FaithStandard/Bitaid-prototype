//! What an app (M4) tells a running role: raise the alert, accept or decline an alert, vote, go off
//! duty. The binary sends none: its roles act on their flags as before. A role started with the
//! matching flag (`--ask-alert`, `--ask-accept`, `--ask-vote`) waits for the command instead.

use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

#[derive(Clone, Debug, PartialEq)]
pub enum Command {
    /// the caller presses the alert
    RaiseAlert,
    /// the responder takes the alert of this case
    Accept { case: String },
    /// the responder passes on it
    Decline { case: String },
    /// the attendee's ballot: the class it gives each seat in order, its own included (`I` intervened,
    /// `D` documented, `N` neither), and whether the outcome was achieved
    Vote { case: String, classes: Vec<String>, achieved: bool },
    /// stop listening for new alerts (a case already accepted runs to its end)
    OffDuty,
}

static QUEUE: Mutex<Vec<Command>> = Mutex::new(Vec::new());
static READY: Condvar = Condvar::new();

/// The app sends a command; the role takes it when it reaches the point that waits for it.
pub fn send(c: Command) {
    if let Ok(mut q) = QUEUE.lock() {
        q.push(c);
        READY.notify_all();
    }
}

/// Takes the first queued command that `want` accepts, waiting up to `timeout` for one.
pub fn take(timeout: Duration, want: impl Fn(&Command) -> bool) -> Option<Command> {
    let until = Instant::now() + timeout;
    let mut q = QUEUE.lock().ok()?;
    loop {
        if let Some(i) = q.iter().position(&want) {
            return Some(q.remove(i));
        }
        let left = until.checked_duration_since(Instant::now())?;
        q = READY.wait_timeout(q, left).ok()?.0;
    }
}

/// Whether a command `want` accepts is queued, without taking it (OffDuty is looked at this way).
pub fn pending(want: impl Fn(&Command) -> bool) -> bool {
    QUEUE.lock().map(|q| q.iter().any(want)).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn take_waits_and_filters() {
        send(Command::Decline { case: "a".into() });
        let t = std::thread::spawn(|| take(Duration::from_secs(5), |c| matches!(c, Command::Accept { case } if case == "b")));
        std::thread::sleep(Duration::from_millis(100));
        send(Command::Accept { case: "b".into() });
        assert_eq!(t.join().unwrap(), Some(Command::Accept { case: "b".into() }));
        assert!(pending(|c| matches!(c, Command::Decline { .. })));
        assert_eq!(take(Duration::from_millis(10), |c| matches!(c, Command::RaiseAlert)), None);
    }
}
