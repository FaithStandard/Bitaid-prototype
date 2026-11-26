//! Runs the app's in-process Tor on its own, for tests on a phone or PC (M4 step 2): Arti bootstrapped
//! with its state in `--dir` (default `$HOME/bitaid-arti`), behind the authenticated SOCKS listener.
//! Prints `BITAID_SOCKS=...` for the node (name `main`) and the time Tor took to bootstrap, then
//! serves until killed.
//! Printing the secret is for this test tool only: the app never logs `BITAID_SOCKS`.
//! `--debug` logs each stream on stderr, and Arti's own progress (RUST_LOG overrides the default
//! filter).
//!   bitaid-tor [--dir DIR] [--debug]
fn main() {
    let args: Vec<String> = std::env::args().collect();
    let dir = args
        .iter()
        .position(|a| a == "--dir")
        .and_then(|i| args.get(i + 1).cloned())
        .unwrap_or_else(|| format!("{}/bitaid-arti", std::env::var("HOME").unwrap_or(".".into())));
    if args.iter().any(|a| a == "--debug") {
        bitaid_tor::set_debug(true);
        let filter = tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
            tracing_subscriber::EnvFilter::new("info,arti_client=debug,tor_hsclient=debug,tor_dirmgr=info,tor_circmgr=info")
        });
        tracing_subscriber::fmt().with_env_filter(filter).with_writer(std::io::stderr).with_ansi(false).init();
    }
    let t0 = std::time::Instant::now();
    match bitaid_tor::Tor::start(&format!("{dir}/state"), &format!("{dir}/cache")) {
        Ok(tor) => {
            println!("TOR_READY {:.2} s", t0.elapsed().as_secs_f64());
            println!("BITAID_SOCKS={}", tor.listener.socks("main"));
            loop {
                std::thread::sleep(std::time::Duration::from_secs(3600));
            }
        }
        Err(e) => {
            println!("TOR_FAILED {e}");
            std::process::exit(1);
        }
    }
}
