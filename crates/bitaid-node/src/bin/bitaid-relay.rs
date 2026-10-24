//! A minimal Nostr relay for Bitaid tests: `bitaid-relay [ADDR]` (default 0.0.0.0:7447).
fn main() {
    let addr = std::env::args().nth(1).unwrap_or("0.0.0.0:7447".into());
    let (h, a) = bitaid_node::relay::spawn(&addr).expect("bind");
    eprintln!("bitaid-relay listening on ws://{a}");
    loop {
        std::thread::sleep(std::time::Duration::from_secs(60));
        let s = h.stats();
        eprintln!(
            "relay: {} events, {} rejected, {} connections",
            s.events, s.rejected, s.connections
        );
    }
}
