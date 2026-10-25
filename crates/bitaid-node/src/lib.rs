//! Bitaid node (prototype, milestone M3): the caller, responder, archivist and oracle roles as one
//! daemon, exchanging the messages of Specification Appendix B.2 over Nostr relays and storing
//! evidence on Blossom-compatible servers.
//!
//! This is a prototype for testing and review, not production software. It must not hold real funds.
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
