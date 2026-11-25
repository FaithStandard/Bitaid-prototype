//! Bitaid node (prototype, milestone M3): the caller, responder, archivist and oracle roles as one
//! daemon, exchanging the messages of Specification Appendix B.2 over Nostr relays and storing
//! evidence on Blossom-compatible servers.
//!
//! This is a prototype for testing and review, not production software. It must not hold real funds.
/// Blocks from an escalation to the block whose hash draws its panel (Specification §10.2): the draw
/// block is fixed by the escalation, so no one can try blocks until one suits them, and its hash is
/// unknown when the escalation is published. Offers stated up to two blocks before it are all drawn
/// from. BITAID_DRAW_BLOCKS sets it (default 3).
/// A prefix of a peer-supplied string for logs: never panics on short or non-ASCII input.
pub fn pre(s: &str, n: usize) -> &str {
    let mut i = n.min(s.len());
    while !s.is_char_boundary(i) {
        i -= 1;
    }
    &s[..i]
}

/// Production rules (BITAID_PRODUCTION=1): the spec's windows and no test settings in templates.
pub fn production() -> bool {
    std::env::var("BITAID_PRODUCTION").is_ok_and(|v| v == "1")
}

/// Blocks from a tier's opening to its draw block (`BITAID_DRAW_BLOCKS`). Offers count from the
/// block that anchors them and must be anchored two blocks before the draw, so the default leaves
/// two checkpoint periods and a margin.
pub fn draw_blocks() -> u32 {
    std::env::var("BITAID_DRAW_BLOCKS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(2 * checkpoint_blocks() + 4)
}

/// Blocks above a draw block before anyone draws from it (`BITAID_DRAW_DEPTH`, default 3): a short
/// reorganisation that replaced the block would otherwise leave nodes with different panels.
/// How often, in blocks, the pool's members anchor a checkpoint of the timed messages they hold
/// (§7; env BITAID_CHECKPOINT_BLOCKS, default 6).
pub fn checkpoint_blocks() -> u32 {
    std::env::var("BITAID_CHECKPOINT_BLOCKS").ok().and_then(|v| v.parse().ok()).filter(|v| *v > 0).unwrap_or(6)
}

/// Blocks after a tier's draw block by which its opener must have published the draw before another
/// carrier may (§10.5): the draw's depth and two finality graces.
pub fn carry_after() -> u32 {
    draw_depth() + 2 * (2 * checkpoint_blocks() + 2) + 2
}

/// The last block by which a tier's draw must be anchored, counted from its draw block: room for a
/// carrier to publish it after the opener's turn, then the stake deadline (a draw anchored later
/// seats no one, and the tier lapses by its carrier's doing).
pub fn draw_by(draw_h: u32, commit_blocks: u32) -> u32 {
    draw_h + carry_after() + commit_blocks
}

pub fn draw_depth() -> u32 {
    std::env::var("BITAID_DRAW_DEPTH")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(3)
}

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

/// How long to wait for an answer that crosses links. Two rules, both from the public signet runs
/// over Tor (2026-11-15), where 20 and 30 second waits tuned on a local machine ended cases that
/// every party was answering:
///
/// * a wait on a reply ends when the reply comes, so a long limit costs nothing where links are fast;
/// * the limit is never shorter than the worst the links do. Over Tor a link drops and is rebuilt in
///   minutes, not seconds, and an onion service is at times unreachable for longer.
///
/// `BITAID_REPLY_MIN` is that floor in seconds (0 on a local machine; 900 on runs over Tor): every
/// wait on a reply is at least that long, whatever figure the code names.
pub fn reply(secs: u64) -> u64 {
    let floor: u64 = std::env::var("BITAID_REPLY_MIN").ok().and_then(|v| v.parse().ok()).unwrap_or(0);
    slow(secs).max(floor)
}

/// Links as they are over Tor, for local runs: `BITAID_LAG="lo-hi,pct:spike"` in milliseconds delays
/// every message this node receives by a time drawn between `lo` and `hi`, and `pct` in a hundred by
/// `spike` instead (a circuit being rebuilt). Unset, nothing is delayed. A local run with no lag
/// proves the logic; only one with lag shows whether the waits fit the network.
pub fn lag() -> Option<std::time::Duration> {
    let v = std::env::var("BITAID_LAG").ok()?;
    let (range, spike) = v.split_once(',').unwrap_or((v.as_str(), ""));
    let (lo, hi) = range.split_once('-')?;
    let (lo, hi): (u64, u64) = (lo.parse().ok()?, hi.parse().ok()?);
    let mut ms = lo + rand::random::<u64>() % (hi.saturating_sub(lo) + 1);
    if let Some((pct, sp)) = spike.split_once(':') {
        if rand::random::<u64>() % 100 < pct.parse().unwrap_or(0) {
            ms = sp.parse().unwrap_or(ms);
        }
    }
    Some(std::time::Duration::from_millis(ms))
}

/// Amounts divided for a test chain whose coins come from a faucet: `BITAID_SAT_SCALE` (default 1)
/// divides every amount the prototype chooses — bonds, case pots, fees, retention — so a run fits a
/// few hundredths of a coin. Every mechanism and proportion stays the same.
pub fn sats(x: u64) -> u64 {
    let k: u64 = std::env::var("BITAID_SAT_SCALE")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|k: &u64| *k >= 1)
        .unwrap_or(1);
    x / k
}

pub mod blossom;
pub mod case;
pub mod chain;
/// What a running role reports to an app (M4).
pub mod events;
pub mod gossip;
pub mod ledger;
pub mod market;
pub mod node;
pub mod nostr;
pub mod pool;
pub mod relay;
/// Every role the node runs (caller, responder, pool member, archivist, arbitrator, audit), driven by
/// its arguments: the binary's whole program, callable from an app (M4).
pub mod roles;
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
