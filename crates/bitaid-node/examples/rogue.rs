//! A hostile peer, for testing a Core's defences while a real case runs through it. First the bonded
//! link itself: a stranger with no stake, a proof with a wrong signature, someone else's stake, a
//! proof signed for another Core. Then, with stakes of its own (the Core's price of entry, paid like
//! anyone's): a message longer than the limit, a stream of garbage, messages dated in the past and
//! the future, a replay, an envelope claiming a block height the chain has not reached, a flood of
//! validly signed junk, a banned key coming back, one key opening many links, and a storm of
//! connections that never prove anything. An observer link watches what the Core forwards. Each
//! attack prints PASS or FAIL; the honest nodes' own checks show whether the case still finished.
//!
//! cargo run --release --example rogue -- --peer 127.0.0.1:7700 [--wait SECS] [--flood N] [--storm N]
//! (needs BITAID_RPC and BITAID_WALLET: its stakes are paid from that wallet, kept in BITAID_LINK_DIR)
use bitaid_node::chain::Rpc;
use bitaid_node::gossip::{self, Credential, BURST, MAX_IN, MAX_JUNK, MAX_LINE, PER_KEY, PROOF_SECS};
use bitaid_node::node::link_credentials;
use bitaid_node::nostr::{kind, now, Event};
use bitaid_node::wire::{self, b64, Msg};
use bitcoin::secp256k1::{Keypair, Secp256k1};
use std::collections::HashSet;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

fn arg(name: &str) -> Option<String> {
    let a: Vec<String> = std::env::args().collect();
    a.iter().position(|x| x == name).and_then(|i| a.get(i + 1).cloned())
}

static PASSED: Mutex<(u32, u32)> = Mutex::new((0, 0));

fn report(ok: bool, what: &str) {
    println!("[{}] rogue {what}", if ok { "PASS" } else { "FAIL" });
    let mut p = PASSED.lock().unwrap();
    if ok {
        p.0 += 1
    } else {
        p.1 += 1
    }
}

fn keys() -> Keypair {
    Keypair::new(&Secp256k1::new(), &mut rand::thread_rng())
}

fn rand_hex() -> String {
    hex::encode(rand::random::<[u8; 32]>())
}

/// A well-formed, validly signed event the protocol will not act on (an empty case message).
fn junk(k: &Keypair, at: u64) -> Event {
    Event::new_at(
        k,
        kind::CASE,
        vec![vec!["c".into(), rand_hex()], vec!["t".into(), "Noise".into()]],
        b64(&rand::random::<[u8; 24]>()),
        at,
    )
}

fn line(e: &Event) -> Vec<u8> {
    let mut v = serde_json::to_vec(e).unwrap();
    v.push(b'\n');
    v
}

/// True if the Core closes `s` within `secs` (reads until end of stream or an error).
fn closed_within(s: &mut TcpStream, secs: u64) -> bool {
    let _ = s.set_read_timeout(Some(Duration::from_secs(secs)));
    let mut buf = [0u8; 65536];
    let end = Instant::now() + Duration::from_secs(secs);
    loop {
        match s.read(&mut buf) {
            Ok(0) => return true,
            Ok(_) => {
                if Instant::now() > end {
                    return false;
                }
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                return false
            }
            Err(_) => return true,
        }
    }
}

/// Watches what the Core forwards: the ids of every message it sends on one link.
struct Observer {
    seen: Arc<Mutex<HashSet<String>>>,
    first: Arc<Mutex<Option<String>>>,
}

/// Dials and answers the Core's challenge with `proof` (built from the challenge); None: no proof.
fn open(peer: &str, socks: Option<&str>, proof: Option<&dyn Fn(&[u8; 32]) -> String>) -> std::io::Result<TcpStream> {
    let s = gossip::dial(peer, socks)?;
    let _ = s.set_write_timeout(Some(Duration::from_secs(15)));
    let _ = s.set_read_timeout(Some(Duration::from_secs(60)));
    // the challenge line, read a byte at a time so nothing after it is consumed
    let mut line = Vec::new();
    let mut b = [0u8; 1];
    let mut r = s.try_clone()?;
    while r.read(&mut b)? == 1 && b[0] != b'\n' && line.len() < 4096 {
        line.push(b[0]);
    }
    let _ = s.set_read_timeout(None);
    let ch = serde_json::from_slice::<serde_json::Value>(&line)
        .ok()
        .and_then(|v| v["challenge"].as_str().and_then(|h| hex::decode(h).ok()))
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .ok_or_else(|| std::io::Error::other("no challenge from the Core"))?;
    if let Some(f) = proof {
        let mut w = s.try_clone()?;
        w.write_all((f(&ch) + "\n").as_bytes())?;
    }
    Ok(s)
}

/// Dials with a proper proof for `c`.
fn connect(peer: &str, socks: Option<&str>, c: &Credential) -> std::io::Result<TcpStream> {
    open(peer, socks, Some(&|ch: &[u8; 32]| gossip::proof_line(c, ch, peer)))
}

impl Observer {
    fn start(peer: &str, socks: Option<&str>, c: &Credential) -> Observer {
        let s = connect(peer, socks, c).expect("observer cannot connect");
        let seen = Arc::new(Mutex::new(HashSet::new()));
        let first = Arc::new(Mutex::new(None));
        let (sn, fs) = (seen.clone(), first.clone());
        std::thread::spawn(move || {
            for l in BufReader::new(s).lines() {
                let l = match l {
                    Ok(l) => l,
                    Err(e) => {
                        eprintln!("rogue: observer link ended: {e}");
                        break;
                    }
                };
                if let Ok(e) = serde_json::from_str::<Event>(&l) {
                    fs.lock().unwrap().get_or_insert(l.clone());
                    sn.lock().unwrap().insert(e.id);
                }
            }
            eprintln!("rogue: observer link closed by the Core");
        });
        Observer { seen, first }
    }
    fn got(&self, id: &str) -> bool {
        self.seen.lock().unwrap().contains(id)
    }
    fn wait_for(&self, id: &str, secs: u64) -> bool {
        let end = Instant::now() + Duration::from_secs(secs);
        while Instant::now() < end {
            if self.got(id) {
                return true;
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        false
    }
}

fn main() {
    let peer = arg("--peer").unwrap_or("127.0.0.1:7700".into());
    let socks = arg("--socks");
    let socks = socks.as_deref();
    let wait: u64 = arg("--wait").and_then(|v| v.parse().ok()).unwrap_or(0);
    // the flood goes on until the Core cuts the link (or this many messages)
    let flood: usize = arg("--flood")
        .and_then(|v| v.parse().ok())
        .unwrap_or(200_000);
    let storm: usize = arg("--storm")
        .and_then(|v| v.parse().ok())
        .unwrap_or(MAX_IN + 16);
    // the stakes this stranger pays for its own keys, like anyone (kept and reused while unspent)
    let rpc = Rpc::from_env();
    let mut cs = link_credentials(
        &["rogue-obs", "rogue-a", "rogue-b", "rogue-c", "rogue-d", "rogue-e", "rogue-f"],
        &rpc,
    );
    assert_eq!(cs.len(), 7, "cannot lock the link stakes");
    let (cf, ce, cd, cc, cb, ca, co) = (
        cs.pop().unwrap(), cs.pop().unwrap(), cs.pop().unwrap(), cs.pop().unwrap(),
        cs.pop().unwrap(), cs.pop().unwrap(), cs.pop().unwrap(),
    );
    if wait > 0 {
        println!("rogue: waiting {wait} s, so the attacks land while a case runs");
        std::thread::sleep(Duration::from_secs(wait));
    }
    let obs = Observer::start(&peer, socks, &co);
    std::thread::sleep(Duration::from_secs(5));
    let k = keys();
    let closed_by = PROOF_SECS + 15;

    // A. the bonded link itself
    // A1. a stranger with no stake: it is sent nothing, its message is dropped, the link is closed
    let e0 = junk(&k, now());
    match open(&peer, socks, None) {
        Ok(mut s) => {
            let _ = s.write_all(&line(&e0));
            let cut = closed_within(&mut s, closed_by);
            report(cut && !obs.got(&e0.id), "a stranger with no stake: its message dropped, the link closed after the proof window");
        }
        Err(e) => report(false, &format!("no-stake stranger: {e}")),
    }
    // A2. a proof whose signature is over another challenge
    let bad = |ch: &[u8; 32]| {
        let mut other = *ch;
        other[0] ^= 1;
        gossip::proof_line(&ca, &other, &peer)
    };
    match open(&peer, socks, Some(&bad)) {
        Ok(mut s) => report(closed_within(&mut s, closed_by), "a proof signed over another challenge: refused, link closed"),
        Err(e) => report(false, &format!("wrong signature: {e}")),
    }
    // A3. someone else's stake: a fresh key claiming another key's outpoint
    let thief = Credential { keys: keys(), stake: ca.stake.clone() };
    match open(&peer, socks, Some(&|ch: &[u8; 32]| gossip::proof_line(&thief, ch, &peer))) {
        Ok(mut s) => report(closed_within(&mut s, closed_by), "another key's stake claimed: refused, link closed"),
        Err(e) => report(false, &format!("stolen stake: {e}")),
    }
    // A4. a proof signed for another Core (what a hostile Core could pass on from its own peers)
    match open(&peer, socks, Some(&|ch: &[u8; 32]| gossip::proof_line(&ca, ch, "elsewhere.onion:7700"))) {
        Ok(mut s) => report(closed_within(&mut s, closed_by), "a proof signed for another Core's address: refused, link closed"),
        Err(e) => report(false, &format!("proof for another address: {e}")),
    }

    // B. with a stake of its own
    // B0. control: one fresh, valid message is forwarded
    let mut a = connect(&peer, socks, &ca).expect("cannot connect");
    let ctl = junk(&k, now());
    a.write_all(&line(&ctl)).unwrap();
    report(
        obs.wait_for(&ctl.id, 20),
        "control: a staked peer's fresh, validly signed message is forwarded",
    );

    // B1. stale and future-dated messages are refused, not forwarded
    let old = junk(&k, now() - 2 * 86_400);
    let fut = junk(&k, now() + 86_400);
    a.write_all(&line(&old)).unwrap();
    a.write_all(&line(&fut)).unwrap();
    std::thread::sleep(Duration::from_secs(10));
    report(
        !obs.got(&old.id) && !obs.got(&fut.id),
        "a message dated two days ago and one dated tomorrow: neither forwarded",
    );

    // B2. a replay of a message the Core has already seen goes nowhere
    let replay = obs.first.lock().unwrap().clone();
    if let Some(l) = replay {
        let e: Event = serde_json::from_str(&l).unwrap();
        let before = obs.seen.lock().unwrap().len();
        a.write_all(l.as_bytes()).unwrap();
        a.write_all(b"\n").unwrap();
        std::thread::sleep(Duration::from_secs(5));
        report(
            obs.seen.lock().unwrap().len() == before,
            &format!(
                "replay of a message already seen ({}…): not forwarded again",
                bitaid_node::pre(&e.id, 8)
            ),
        );
    }

    // B3. an envelope claiming a block height the chain has not reached (honest nodes refuse it and
    //     log 'refused … claims height'; the Core only relays, so it reaches them)
    let ek = keys();
    let case = rand_hex();
    let bytes = wire::sign(
        &ek,
        10_000_000,
        Msg::Escalate {
            case_id: case.clone(),
            tier: 1,
            reason: "rogue: a height from the future".into(),
            post: String::new(),
        },
    );
    let e = Event::new(
        &ek,
        kind::CASE,
        vec![vec!["c".into(), case], vec!["t".into(), "Escalate".into()]],
        b64(&bytes),
    );
    a.write_all(&line(&e)).unwrap();
    report(
        obs.wait_for(&e.id, 20),
        "an escalation claiming block 10,000,000 relayed for the nodes to judge (they should log 'refused Escalate')",
    );
    drop(a);

    // B4. a message longer than the limit closes the link, and its key is banned
    let mut b = connect(&peer, socks, &cb).expect("cannot connect");
    let chunk = vec![b'x'; 1 << 16];
    let mut sent = 0;
    while sent <= MAX_LINE + (1 << 16) {
        if b.write_all(&chunk).is_err() {
            break;
        }
        sent += chunk.len();
    }
    report(
        closed_within(&mut b, 30),
        &format!("a {} KiB message with no end: link closed", sent >> 10),
    );
    std::thread::sleep(Duration::from_secs(2));
    match connect(&peer, socks, &cb) {
        Ok(mut s) => {
            let probe = junk(&k, now());
            let _ = s.write_all(&line(&probe));
            let cut = closed_within(&mut s, closed_by);
            report(cut && !obs.got(&probe.id), "the same key back after its abuse: banned, its link refused at the proof");
        }
        Err(_) => report(true, "the same key back after its abuse: banned, refused"),
    }

    // B5. garbage lines close the link
    let mut c = connect(&peer, socks, &cc).expect("cannot connect");
    for i in 0..(MAX_JUNK + 50) {
        if c.write_all(format!("not a message {i}\n").as_bytes()).is_err() {
            break;
        }
    }
    report(
        closed_within(&mut c, 30),
        &format!("{} lines of garbage: link closed, key banned", MAX_JUNK + 50),
    );

    // B6. a flood of validly signed junk is cut at the rate limit
    let mut d = connect(&peer, socks, &cd).expect("cannot connect");
    let t0 = Instant::now();
    let mut n = 0;
    for i in 0..flood {
        let kk = if i % 100 == 0 { keys() } else { k };
        let e = junk(&kk, now());
        if d.write_all(&line(&e)).is_err() {
            break;
        }
        n += 1;
    }
    let cut = closed_within(&mut d, 60);
    report(
        cut,
        &format!(
            "flood of validly signed messages: link closed after {n} sent in {:.1} s (limit: a burst of {}, then {}/s), key banned",
            t0.elapsed().as_secs_f64(),
            BURST,
            gossip::RATE
        ),
    );

    // B7. one key opening many links: at most PER_KEY are kept
    let mut many = vec![];
    for _ in 0..8 {
        if let Ok(s) = connect(&peer, socks, &ce) {
            many.push(s);
        }
    }
    std::thread::sleep(Duration::from_secs(5));
    let mut open_n = 0;
    for s in many.iter_mut() {
        if !closed_within(s, 1) {
            open_n += 1;
        }
    }
    report(
        open_n <= PER_KEY,
        &format!("one staked key opening 8 links: {open_n} kept (at most {PER_KEY} per key)"),
    );
    drop(many);

    // B8. a storm of connections that never prove anything: they hold no slot past the proof
    //     window, and a staked newcomer is accepted and its message forwarded
    let mut held = vec![];
    for _ in 0..storm {
        if let Ok(s) = open(&peer, socks, None) {
            held.push(s);
        }
    }
    std::thread::sleep(Duration::from_secs(15));
    let after = junk(&k, now());
    match connect(&peer, socks, &cf) {
        Ok(mut s) => {
            let _ = s.write_all(&line(&after));
            report(
                obs.wait_for(&after.id, 40),
                &format!("{storm} connections without a proof (the Core keeps at most {MAX_IN} incoming): a staked newcomer still accepted and its message forwarded"),
            );
        }
        Err(e) => report(false, &format!("after the storm: cannot connect ({e})")),
    }
    drop(held);

    let p = PASSED.lock().unwrap();
    println!("[rogue] {} passed, {} failed", p.0, p.1);
}
