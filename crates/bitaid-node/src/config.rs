//! The node's settings: every `BITAID_*` value (and `HOME`, the data folder) is read through here.
//!
//! The command-line binary takes them from its environment, as the test harness sets them. An app
//! (M4) passes them in with `set` before starting a role: setting a process's environment while other
//! threads run is unsound, so the library never does, and once `set` has been called the
//! environment is not read at all (review of M4, 2026-11-25).

use std::collections::HashMap;
use std::env::VarError;
use std::sync::RwLock;

static SETTINGS: RwLock<Option<HashMap<String, String>>> = RwLock::new(None);

/// The app's settings, replacing the environment for this process. Keys are the same names the
/// binary reads from its environment (`BITAID_RPC`, `BITAID_SOCKS`, `HOME`, ...).
pub fn set(settings: HashMap<String, String>) {
    *SETTINGS.write().unwrap_or_else(|e| e.into_inner()) = Some(settings);
}

/// One setting: from the app's settings if it gave them, else from the environment. Same contract as
/// `std::env::var`, so a call site reads as before.
pub fn var(key: &str) -> Result<String, VarError> {
    if let Some(m) = SETTINGS.read().unwrap_or_else(|e| e.into_inner()).as_ref() {
        return m.get(key).cloned().ok_or(VarError::NotPresent);
    }
    std::env::var(key)
}

#[cfg(test)]
mod tests {
    #[test]
    fn app_settings_replace_the_environment() {
        // (the only test that sets them: the settings are process-wide)
        let before = super::var("PATH").is_ok();
        super::set([("BITAID_X".to_string(), "1".to_string())].into());
        assert_eq!(super::var("BITAID_X").as_deref(), Ok("1"));
        assert!(super::var("PATH").is_err(), "the environment is not read once settings are set");
        let _ = before;
    }
}
