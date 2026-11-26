//! Where the node keeps the secrets it makes while it runs: link credentials, per-case keys, the
//! keys of bonds and funding outputs kept for `--role reclaim` (test chains only).
//!
//! The command-line binary writes them as files, as it always has, and the regtest suites read them
//! there. An app (M4) installs a `SecretStore` first, and then none of these is written to disk in
//! plain form: on Android the store encrypts under a Keystore key (requested by Neon, 2026-11-26;
//! `design/m4_android.md`, "Keys"). Every secret has a `name` (a plain file name, no folders) for the
//! store and a path for the file fallback.

use std::sync::{Arc, RwLock};

/// An app's encrypted store. `name` is a flat file name such as `link_r1.json`.
pub trait SecretStore: Send + Sync {
    /// `Ok(None)`: no such secret. `Err`: it may exist but cannot be read (a Keystore key gone, a
    /// corrupt file); the node then stops rather than making a new one in its place (review of M4
    /// steps 3-5: a new identity or a new link stake, silently).
    fn get(&self, name: &str) -> std::io::Result<Option<Vec<u8>>>;
    fn put(&self, name: &str, data: &[u8]) -> std::io::Result<()>;
    /// Adds `line` (which ends in a newline) at the end of `name`, creating it.
    fn append(&self, name: &str, line: &str) -> std::io::Result<()>;
}

static STORE: RwLock<Option<Arc<dyn SecretStore>>> = RwLock::new(None);

/// Installs the app's store, before any role starts. From then on no secret goes to a file.
pub fn set_store(store: Arc<dyn SecretStore>) {
    *STORE.write().unwrap_or_else(|e| e.into_inner()) = Some(store);
}

fn store() -> Option<Arc<dyn SecretStore>> {
    STORE.read().unwrap_or_else(|e| e.into_inner()).clone()
}

/// Whether an app's store is installed.
pub fn in_store() -> bool {
    store().is_some()
}

/// `Ok(None)` when the secret does not exist; `Err` when it may but cannot be read.
pub fn read(name: &str, path: &str) -> std::io::Result<Option<String>> {
    let bytes = match store() {
        Some(s) => s.get(name)?,
        None => match std::fs::read(path) {
            Ok(b) => Some(b),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(e),
        },
    };
    bytes
        .map(|b| String::from_utf8(b).map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("{name}: not text"))))
        .transpose()
}

pub fn write(name: &str, path: &str, data: &str) -> std::io::Result<()> {
    match store() {
        Some(s) => s.put(name, data.as_bytes()),
        None => {
            if let Some(dir) = std::path::Path::new(path).parent() {
                let _ = std::fs::create_dir_all(dir);
            }
            std::fs::write(path, data)
        }
    }
}

pub fn append(name: &str, path: &str, line: &str) -> std::io::Result<()> {
    match store() {
        Some(s) => s.append(name, line),
        None => {
            use std::io::Write;
            // one write call per line: several nodes appending to one folder on Windows interleaved
            // their lines byte by byte when written in pieces (the public-signet run of 2026-10-31)
            std::fs::OpenOptions::new().create(true).append(true).open(path)?.write_all(line.as_bytes())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    #[derive(Default)]
    struct Mem(Mutex<HashMap<String, Vec<u8>>>);
    impl SecretStore for Mem {
        fn get(&self, name: &str) -> std::io::Result<Option<Vec<u8>>> {
            Ok(self.0.lock().unwrap().get(name).cloned())
        }
        fn put(&self, name: &str, data: &[u8]) -> std::io::Result<()> {
            self.0.lock().unwrap().insert(name.into(), data.to_vec());
            Ok(())
        }
        fn append(&self, name: &str, line: &str) -> std::io::Result<()> {
            self.0.lock().unwrap().entry(name.into()).or_default().extend_from_slice(line.as_bytes());
            Ok(())
        }
    }

    /// (the only test that installs a store: it is process-wide)
    #[test]
    fn files_until_a_store_is_installed_then_nothing_on_disk() {
        let dir = std::env::temp_dir().join(format!("bitaid-secrets-{}", std::process::id()));
        let p = |n: &str| dir.join(n).to_string_lossy().to_string();
        write("a.key", &p("a.key"), "one").unwrap();
        append("k.jsonl", &p("k.jsonl"), "x\n").unwrap();
        append("k.jsonl", &p("k.jsonl"), "y\n").unwrap();
        assert_eq!(read("a.key", &p("a.key")).unwrap().as_deref(), Some("one"));
        assert_eq!(read("k.jsonl", &p("k.jsonl")).unwrap().as_deref(), Some("x\ny\n"));
        assert_eq!(read("none", &p("none")).unwrap(), None);
        // a file that exists but cannot be read is an error, never "absent"
        std::fs::create_dir_all(dir.join("adir")).unwrap();
        assert!(read("adir", &p("adir")).is_err());
        let mem = Arc::new(Mem::default());
        set_store(mem.clone());
        assert!(in_store());
        write("b.key", &p("b.key"), "two").unwrap();
        append("k2.jsonl", &p("k2.jsonl"), "z\n").unwrap();
        assert!(!std::path::Path::new(&p("b.key")).exists());
        assert!(!std::path::Path::new(&p("k2.jsonl")).exists());
        assert_eq!(read("b.key", &p("b.key")).unwrap().as_deref(), Some("two"));
        assert_eq!(mem.get("k2.jsonl").unwrap().unwrap(), b"z\n");
        // the files written before are not read through the store
        assert_eq!(read("a.key", &p("a.key")).unwrap(), None);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
