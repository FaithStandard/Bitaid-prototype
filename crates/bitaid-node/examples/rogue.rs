//! A hostile peer, for testing a Core's defences while a real case runs through it. It connects to
//! the Core's gossip port like any stranger who learnt the onion address, and tries, one after
//! another: a message longer than the limit, a stream of garbage, messages dated in the past and the
//! future, a replay of a message already seen, an envelope claiming a block height the chain has
//! not reached, a flood of validly signed junk, and more connections than the Core accepts. An
//! observer link watches what the Core forwards. Each attack prints PASS or FAIL; the honest nodes'
//! own checks show whether the case still finished.
//!
//! cargo run --release --example rogue -- --peer 127.0.0.1:7700 [--wait SECS] [--flood N] [--storm N]
use bitaid_node::gossip::{self, BURST, MAX_IN, MAX_JUNK, MAX_LINE};
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

impl Observer {
    fn start(peer: &str, socks: Option<&str>) -> Observer {
        let s = gossip::dial(peer, socks).expect("observer cannot connect");
        let seen = Arc::new(Mutex::new(HashSet::new()));
        let first = Arc::new(Mutex::new(None));
        let (sn, fs) = (seen.clone(), first.clone());
        std::thread::spawn(move || {
            for l in BufReader::new(s).lines() {
                let Ok(l) = l else { break };
                if let Ok(e) = serde_json::from_str::<Event>(&l) {
                    fs.lock().unwrap().get_or_insert(l.clone());
                    sn.lock().unwrap().insert(e.id);
                }
            }
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
    let dial = || gossip::dial(&peer, socks);
    if wait > 0 {
        println!("rogue: waiting {wait} s, so the attacks land while a case runs");
        std::thread::sleep(Duration::from_secs(wait));
    }
    let obs = Observer::start(&peer, socks);
    std::thread::sleep(Duration::from_secs(5));
    let k = keys();

    // 0. control: one fresh, valid message is forwarded
    let mut a = dial().expect("cannot connect");
    let ctl = junk(&k, now());
    a.write_all(&line(&ctl)).unwrap();
    report(
        obs.wait_for(&ctl.id, 20),
        "control: a fresh, validly signed message is forwarded",
    );

    // 1. stale and future-dated messages are refused, not forwarded
    let old = junk(&k, now() - 2 * 86_400);
    let fut = junk(&k, now() + 86_400);
    a.write_all(&line(&old)).unwrap();
    a.write_all(&line(&fut)).unwrap();
    std::thread::sleep(Duration::from_secs(10));
    report(
        !obs.got(&old.id) && !obs.got(&fut.id),
        "a message dated two days ago and one dated tomorrow: neither forwarded",
    );

    // 2. a replay of a message the Core has already seen goes nowhere
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
                &e.id[..8]
            ),
        );
    }

    // 3. an envelope claiming a block height the chain has not reached (honest nodes refuse it and
    //    log 'refused … claims height'; the Core only relays, so it reaches them)
    let ek = keys();
    let case = rand_hex();
    let bytes = wire::sign(
        &ek,
        10_000_000,
        Msg::Escalate {
            case_id: case.clone(),
            tier: 1,
            reason: "rogue: a height from the future".into(),
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

    // 4. a message longer than the limit closes the link
    let mut b = dial().expect("cannot connect");
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

    // 5. garbage lines close the link
    let mut c = dial().expect("cannot connect");
    for i in 0..(MAX_JUNK + 50) {
        if c.write_all(format!("not a message {i}\n").as_bytes()).is_err() {
            break;
        }
    }
    report(
        closed_within(&mut c, 30),
        &format!("{} lines of garbage: link closed", MAX_JUNK + 50),
    );

    // 6. a flood of validly signed junk is cut at the rate limit
    let mut d = dial().expect("cannot connect");
    let t0 = Instant::now();
    let mut n = 0;
    let mut last = String::new();
    for i in 0..flood {
        let kk = if i % 100 == 0 { keys() } else { k };
        let e = junk(&kk, now());
        last = e.id.clone();
        if d.write_all(&line(&e)).is_err() {
            break;
        }
        n += 1;
    }
    let cut = closed_within(&mut d, 60);
    report(
        cut,
        &format!(
            "flood of validly signed messages: link closed after {n} sent in {:.1} s (limit: a burst of {}, then {}/s)",
            t0.elapsed().as_secs_f64(),
            BURST,
            gossip::RATE
        ),
    );
    let _ = last;

    // 7. more connections than the Core accepts: the excess are closed, and once the storm is over
    //    a new peer is accepted and a fresh message forwarded
    let mut held = vec![];
    for _ in 0..storm {
        if let Ok(s) = dial() {
            held.push(s);
        }
    }
    std::thread::sleep(Duration::from_secs(5));
    let mut refused = 0;
    for s in held.iter_mut() {
        if closed_within(s, 1) {
            refused += 1;
        }
    }
    report(
        refused > 0,
        &format!(
            "{storm} connections at once: {refused} closed by the Core (it keeps at most {MAX_IN} incoming)"
        ),
    );
    drop(held);
    std::thread::sleep(Duration::from_secs(5));
    let after = junk(&k, now());
    match dial() {
        Ok(mut s) => {
            let _ = s.write_all(&line(&after));
            let fresh = Observer::start(&peer, socks);
            report(
                obs.wait_for(&after.id, 30) || fresh.wait_for(&after.id, 30),
                "after the storm: a new peer accepted and its message forwarded",
            );
        }
        Err(e) => report(false, &format!("after the storm: cannot connect ({e})")),
    }

    let p = PASSED.lock().unwrap();
    println!("[rogue] {} passed, {} failed", p.0, p.1);
}
