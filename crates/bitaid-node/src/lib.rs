//! Bitaid node (prototype, milestone M3): the caller, responder, archivist and oracle roles as one
//! daemon, exchanging the messages of Specification Appendix B.2 over Nostr relays and storing
//! evidence on Blossom-compatible servers.
//!
//! This is a prototype for testing and review, not production software. It must not hold real funds.
/// Long waits (a minute or more) stretched for slow chains: `BITAID_TIME_SCALE` (default 1) multiplies
/// every wait that may span blocks — a node's idle exit, settlement, a panel's seating, the chain's
/// own confirmations — while message-level timeouts under a minute stay as they are. On a chain with
/// 10-minute blocks the waits tuned for 20-second blocks are about 30 times too short.
pub fn slow(secs: u64) -> u64 {
    if secs < 60 {
        return secs;
    }
    let k: f64 = std::env::var("BITAID_TIME_SCALE")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|k: &f64| *k >= 1.0)
        .unwrap_or(1.0);
    (secs as f64 * k) as u64
}

pub mod blossom;
pub mod case;
pub mod chain;
pub mod gossip;
pub mod node;
pub mod nostr;
pub mod pool;
pub mod relay;
pub mod settle;
pub mod wire;

/// HTTP for the chain RPC and Blossom: `.onion` URLs go through Tor's SOCKS port (`BITAID_SOCKS`,
/// e.g. 127.0.0.1:9150), with the name resolved by Tor; anything else is fetched directly.
pub fn http_for(url: &str) -> &'static ureq::Agent {
    use std::sync::OnceLock;
    static DIRECT: OnceLock<ureq::Agent> = OnceLock::new();
    static TOR: OnceLock<ureq::Agent> = OnceLock::new();
    let onion = url
        .split("://")
        .nth(1)
        .unwrap_or(url)
        .split(['/', ':'])
        .next()
        .unwrap_or("")
        .ends_with(".onion");
    match (onion, std::env::var("BITAID_SOCKS")) {
        (true, Ok(p)) => TOR.get_or_init(|| {
            let proxy = ureq::Proxy::new(format!("socks5://{p}")).expect("BITAID_SOCKS host:port");
            ureq::AgentBuilder::new()
                .proxy(proxy)
                .timeout(std::time::Duration::from_secs(120))
                .build()
        }),
        _ => DIRECT.get_or_init(|| {
            ureq::AgentBuilder::new()
                .timeout(std::time::Duration::from_secs(60))
                .build()
        }),
    }
}
pub mod arb;

/// A node on the same machine as a service reaches it locally rather than through its own onion
/// address: `BITAID_SELF_ONION` names this machine's onion, and URLs on it become 127.0.0.1.
pub fn local_url(url: &str) -> String {
    match std::env::var("BITAID_SELF_ONION") {
        Ok(o) if !o.is_empty() && url.contains(&o) => url.replace(&o, "127.0.0.1"),
        _ => url.to_string(),
    }
}
