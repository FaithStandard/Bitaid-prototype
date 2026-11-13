//! What every role shares: an identity, a transport (Core-to-Core gossip, or relays for the earlier
//! tests), a chain connection, case keys, and a mailbox that
//! keeps messages until the step that needs them asks for them.
use crate::chain::Rpc;
use crate::gossip::{Credential, Demand, Gossip, Verify};
use crate::nostr::{kind, Client, Event, Filter};
use crate::wire::{self, b64, unb64, Envelope, Msg};
use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey, XOnlyPublicKey};
use musig2::secp::{Point, Scalar};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// How messages travel: the Specification's gossip between Cores (over Tor onion services), or
/// Nostr relays, kept only as the stand-in used by the earlier device tests.
pub enum Net {
    Gossip(Gossip),
    Relays(Client),
}

impl Net {
    pub fn publish(&self, e: &Event) {
        match self {
            Net::Gossip(g) => g.publish(e),
            Net::Relays(c) => c.publish(e),
        }
    }
    pub fn subscribe(&mut self, id: &str, f: Vec<Filter>) {
        match self {
            Net::Gossip(g) => g.subscribe(id, f),
            Net::Relays(c) => c.subscribe(id, f),
        }
    }
    pub fn next_event(&mut self, t: Duration) -> Option<(String, Event)> {
        match self {
            Net::Gossip(g) => g.next_event(t),
            Net::Relays(c) => c.next_event(t),
        }
    }
    pub fn relay_count(&self) -> usize {
        match self {
            Net::Gossip(g) => g.links(),
            Net::Relays(c) => c.relay_count(),
        }
    }
}

/// Bounds on what a hostile peer can make a node hold (see `gossip` for the link-level limits).
///
/// Messages of a *kept* case (one whose funded alert this node has checked, or that it takes part
/// in) are never pushed out by other traffic: author keys cost nothing, so no rule that ranks authors
/// can tell a flood from a busy honest party. A kept case is bounded instead, per sender: a case's
/// insiders (holders of its key) may each record `PER_SENDER_SEALED` messages in it, anyone else
/// `PER_SENDER_OPEN` plain ones, from at most `OPEN_SENDERS` distinct keys. Past a bound the newest
/// is not recorded, so what a case was built on (its alert, roster, incident) is never displaced.
/// Everything else shares the remaining room, oldest out first.
pub const MAX_BACKLOG: usize = 20_000;
pub const MAX_LOCKED: usize = 5_000;
pub const MAX_HISTORY: usize = 100_000;
pub const PER_SENDER_SEALED: usize = 256;
pub const PER_SENDER_OPEN: usize = 64;
pub const OPEN_SENDERS: usize = 1_024;
pub const SEALED_SENDERS: usize = 256;

/// What a kept case has recorded, per sender, to bound it.
#[derive(Default)]
struct Kept {
    sealed: HashMap<String, usize>,
    open: HashMap<String, usize>,
    /// the case's oracle key, when known: what a bond offered for the case must be under
    oracle: Option<bitcoin::secp256k1::XOnlyPublicKey>,
}

/// Drops, in one pass, the oldest tenth of the entries `keep` does not protect (amortised: a flood
/// past the bound costs one sweep per tenth of it, not a shift per message).
fn trim<T>(v: &mut VecDeque<T>, cap: usize, kept: impl Fn(&T) -> bool) {
    if v.len() <= cap {
        return;
    }
    let mut drop = (v.len() - cap).max(cap / 10);
    v.retain(|x| {
        if drop > 0 && !kept(x) {
            drop -= 1;
            false
        } else {
            true
        }
    });
    // everything left is kept and still over the bound: the oldest go all the same (a bound that
    // nothing can enforce is no bound, and every push would sweep the whole list for nothing)
    while v.len() > cap + cap / 10 {
        v.pop_front();
    }
}
/// Blocks a sender's claimed height may run ahead of this node's chain.
pub const MAX_AHEAD: u32 = 6;

pub struct Node {
    /// called on every message as it is read off the network, before anything else handles it: for
    /// what must not wait on the main loop (an archivist admitting a case's uploaders while it is busy
    /// convening a review)
    pub observer: Option<Box<dyn FnMut(&Envelope)>>,
    pub name: String,
    pub keys: Keypair,
    pub client: Net,
    pub rpc: Rpc,
    pub case_keys: HashMap<String, [u8; 32]>,
    /// verified messages not yet asked for
    backlog: VecDeque<(Envelope, Event)>,
    /// every verified message this node has read, in arrival order: replayed by `arb::Replay`
    pub history: Vec<Envelope>,
    /// subscriptions whose messages only go to the history (read by replays), never to the mailbox
    history_only: std::collections::HashSet<String>,
    /// encrypted case messages whose key has not arrived yet
    locked: VecDeque<Event>,
    /// cases whose messages other traffic never pushes out, with their per-sender counts
    kept: HashMap<String, Kept>,
    pub t0: Instant,
    last_sent: Instant,
    pace_ms: u64,
    height_cache: u32,
    height_at: Option<Instant>,
    pub passed: u32,
    pub failed: u32,
}

/// x-only key of a scalar, as a `bitcoin` key.
pub fn xo(s: &Scalar) -> XOnlyPublicKey {
    let p: Point = *s * musig2::secp::G;
    XOnlyPublicKey::from_slice(&p.serialize_xonly()).unwrap()
}

pub fn scalar_hex(s: &Scalar) -> String {
    hex::encode(s.serialize())
}

/// The link stake a node locks to dial a Core, for a link that receives (Specification §7.1: 20,000
/// sats; a relaying Core's is larger): a fidelity bond per identity. Scaled by SAT_SCALE on a test
/// chain, never below LINK_STAKE_FLOOR (an output must stay above dust).
pub const LINK_STAKE: u64 = 20_000;
pub const LINK_STAKE_FLOOR: u64 = 1_000;

/// The link stake in sats on this chain.
pub fn link_stake() -> u64 {
    crate::sats(LINK_STAKE).max(LINK_STAKE_FLOOR)
}

/// The script a link stake pays to: the link key alone (taproot, key path only).
pub fn link_spk(k: &XOnlyPublicKey) -> bitcoin::ScriptBuf {
    bitcoin::ScriptBuf::new_p2tr(&Secp256k1::verification_only(), *k, None)
}

/// A Core's check of a claimed link stake: unspent, in a block, paying at least the link stake to
/// the key alone.
pub fn link_verifier() -> Verify {
    let rpc = Arc::new(Rpc::from_env());
    Arc::new(move |k: &XOnlyPublicKey, stake: &str| {
        let op: bitcoin::OutPoint = stake.parse().map_err(|_| "not an outpoint".to_string())?;
        // a stake whose spend waits in the mempool no longer holds; a backend that cannot be asked
        // says nothing either way (the error starts with `UNAVAILABLE`, and a link is not cut for it)
        let (out, conf) = match rpc.utxo_state(&op) {
            Err(e) => return Err(format!("{}: {e}", crate::gossip::UNAVAILABLE)),
            Ok(None) => return Err("spent, or not an output".into()),
            Ok(Some(x)) => x,
        };
        if conf == 0 {
            return Err("not yet in a block".into());
        }
        if out.script_pubkey != link_spk(k) {
            return Err("does not pay the key".into());
        }
        if out.value.to_sat() < link_stake() {
            return Err(format!("{} sats, below the link stake", out.value.to_sat()));
        }
        Ok(())
    })
}

/// Several link credentials at once (the hostile-peer test needs seven): the usable ones kept, the
/// rest made in one transaction and one confirmation.
pub fn link_credentials(names: &[&str], rpc: &Rpc) -> Vec<Credential> {
    let dir = std::env::var("BITAID_LINK_DIR").unwrap_or_else(|_| {
        format!("{}/.bitaid", std::env::var("HOME").unwrap_or(".".into()))
    });
    let _ = std::fs::create_dir_all(&dir);
    let secp = Secp256k1::new();
    let load = |name: &str| -> Option<Credential> {
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(format!("{dir}/link_{name}.json")).ok()?).ok()?;
        let sk = SecretKey::from_slice(&hex::decode(v["secret"].as_str()?).ok()?).ok()?;
        let kp = Keypair::from_secret_key(&secp, &sk);
        let stake = v["stake"].as_str()?.to_string();
        let (o, _) = rpc.confirmed_utxo(&stake.parse().ok()?)?;
        (o.script_pubkey == link_spk(&kp.x_only_public_key().0) && o.value.to_sat() >= link_stake())
            .then_some(Credential { keys: kp, stake })
    };
    let mut have: Vec<Option<Credential>> = names.iter().map(|n| load(n)).collect();
    let missing: Vec<usize> = (0..names.len()).filter(|i| have[*i].is_none()).collect();
    if !missing.is_empty() {
        let kps: Vec<Keypair> = missing.iter().map(|_| Keypair::new(&secp, &mut rand::thread_rng())).collect();
        let pay: Vec<(bitcoin::ScriptBuf, u64)> =
            kps.iter().map(|k| (link_spk(&k.x_only_public_key().0), link_stake())).collect();
        eprintln!("gossip: locking {} link stakes of {} sats in one transaction (once; reused while unspent)", kps.len(), link_stake());
        match rpc.pay_many(&pay) {
            Err(e) => eprintln!("gossip: cannot lock the link stakes ({e})"),
            Ok(txid) => {
            rpc.confirm(&[txid]);
            for (i, kp) in missing.iter().zip(kps) {
                let spk = link_spk(&kp.x_only_public_key().0);
                if let Some(vout) = (0..(pay.len() as u32 + 2)).find(|v| {
                    rpc.utxo(&bitcoin::OutPoint { txid, vout: *v }).map(|o| o.script_pubkey == spk).unwrap_or(false)
                }) {
                    let stake = format!("{txid}:{vout}");
                    let _ = std::fs::write(
                        format!("{dir}/link_{}.json", names[*i]),
                        serde_json::json!({"secret": hex::encode(kp.secret_bytes()), "stake": stake, "who": names[*i]}).to_string(),
                    );
                    have[*i] = Some(Credential { keys: kp, stake });
                }
            }
            }
        }
    }
    have.into_iter().flatten().collect()
}

/// This node's link credential: kept in BITAID_LINK_DIR (default ~/.bitaid) as link_<name>.json and
/// reused while its stake stays unspent; otherwise a new key and stake are made and confirmed (on a
/// test chain the secret is kept, so the stake can be spent back). BITAID_LINK_STAKE=0: none.
pub fn link_credential(name: &str, rpc: &Rpc) -> Option<Credential> {
    if std::env::var("BITAID_LINK_STAKE").map(|v| v == "0").unwrap_or(false) {
        return None;
    }
    let dir = std::env::var("BITAID_LINK_DIR").unwrap_or_else(|_| {
        format!("{}/.bitaid", std::env::var("HOME").unwrap_or(".".into()))
    });
    let _ = std::fs::create_dir_all(&dir);
    let path = format!("{dir}/link_{name}.json");
    let secp = Secp256k1::new();
    let usable = |kp: &Keypair, stake: &str| {
        stake
            .parse::<bitcoin::OutPoint>()
            .ok()
            .and_then(|op| rpc.confirmed_utxo(&op))
            .map(|(o, _)| {
                o.script_pubkey == link_spk(&kp.x_only_public_key().0)
                    && o.value.to_sat() >= link_stake()
            })
            .unwrap_or(false)
    };
    if let Ok(t) = std::fs::read_to_string(&path) {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&t) {
            let kp = v["secret"]
                .as_str()
                .and_then(|h| hex::decode(h).ok())
                .and_then(|b| SecretKey::from_slice(&b).ok())
                .map(|sk| Keypair::from_secret_key(&secp, &sk));
            let stake = v["stake"].as_str().unwrap_or("").to_string();
            if let Some(kp) = kp {
                if usable(&kp, &stake) {
                    return Some(Credential { keys: kp, stake });
                }
            }
        }
    }
    let kp = Keypair::new(&secp, &mut rand::thread_rng());
    let spk = link_spk(&kp.x_only_public_key().0);
    eprintln!("[{name}] gossip: locking a link stake of {} sats (once; reused while unspent)", link_stake());
    let txid = match rpc.pay_many(&[(spk.clone(), link_stake())]) {
        Ok(t) => t,
        Err(e) => {
            // a Core refuses a link without a stake, so dialling on would only loop link up / link
            // down: stop here and say why
            eprintln!("[{name}] LINK_STAKE_FAILED: cannot lock a link stake of {} sats ({e}); the wallet behind BITAID_RPC needs funds", link_stake());
            std::process::exit(3);
        }
    };
    rpc.confirm(&[txid]);
    let Some(vout) = (0..8u32).find(|v| {
        rpc.utxo(&bitcoin::OutPoint { txid, vout: *v })
            .map(|o| o.script_pubkey == spk)
            .unwrap_or(false)
    }) else {
        eprintln!("[{name}] LINK_STAKE_FAILED: the link stake {txid} was sent but its output cannot be found");
        std::process::exit(3);
    };
    let stake = format!("{txid}:{vout}");
    let _ = std::fs::write(
        &path,
        serde_json::json!({"secret": hex::encode(kp.secret_bytes()), "stake": stake, "who": name}).to_string(),
    );
    Some(Credential { keys: kp, stake })
}

impl Node {
    pub fn new(name: &str, relays: &[String], rpc: Rpc, secret: Option<[u8; 32]>) -> Node {
        let secp = Secp256k1::new();
        let keys = match secret {
            Some(s) => Keypair::from_secret_key(&secp, &SecretKey::from_slice(&s).unwrap()),
            None => Keypair::new(&secp, &mut rand::thread_rng()),
        };
        let mut c = Client::new();
        let client = &mut c;
        for r in relays {
            eprintln!("[{name}] connecting to relay {r} …");
            let mut ok = false;
            for _ in 0..60 {
                if client.add_relay(r).is_ok() {
                    ok = true;
                    break;
                }
                std::thread::sleep(Duration::from_secs(1));
            }
            if !ok {
                eprintln!("[{name}] could not reach relay {r}");
            }
        }
        Self::with_net(name, Net::Relays(c), rpc, keys)
    }

    /// A node on Core-to-Core gossip: `listen` (if this is a Core others dial), `peers` to dial,
    /// `socks` (Tor) for onion peers. Waits up to `wait` for at least one link.
    pub fn gossip(
        name: &str,
        listen: Option<&str>,
        peers: &[String],
        socks: Option<&str>,
        rpc: Rpc,
        secret: Option<[u8; 32]>,
        wait: Duration,
    ) -> Node {
        // bonded links: a Core demands a proof of stake on every incoming link (BITAID_OPEN_LINKS=1
        // opens them, for tests); a node that dials proves with its link stake
        let demand = match listen {
            Some(l) if std::env::var("BITAID_OPEN_LINKS").is_err() => {
                let mut names = vec![l.to_string()];
                if let Ok(v) = std::env::var("BITAID_LINK_NAMES") {
                    names.extend(v.split(',').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()));
                }
                Some(Demand {
                    verify: link_verifier(),
                    names,
                })
            }
            _ => None,
        };
        let cred = if peers.is_empty() {
            None
        } else {
            link_credential(name, &rpc)
        };
        let g = Gossip::start_with(listen, peers, socks, demand, cred).expect("gossip listen");
        if let Some(l) = listen {
            eprintln!("[{name}] gossip: listening on {l}");
        }
        for p in peers {
            eprintln!(
                "[{name}] gossip: dialling {p}{} …",
                if socks.is_some() { " through Tor" } else { "" }
            );
        }
        if !peers.is_empty() {
            let n = g.wait_links(1, wait);
            if n == 0 {
                eprintln!("[{name}] gossip: no peer reachable yet; continuing, links retry in the background");
            }
        }
        Self::with_net(name, Net::Gossip(g), rpc, Self::keypair(secret))
    }

    fn keypair(secret: Option<[u8; 32]>) -> Keypair {
        let secp = Secp256k1::new();
        match secret {
            Some(s) => Keypair::from_secret_key(&secp, &SecretKey::from_slice(&s).unwrap()),
            None => Keypair::new(&secp, &mut rand::thread_rng()),
        }
    }

    fn with_net(name: &str, client: Net, rpc: Rpc, keys: Keypair) -> Node {
        Node {
            name: name.into(),
            keys,
            client,
            rpc,
            case_keys: HashMap::new(),
            backlog: VecDeque::new(),
            history: vec![],
            observer: None,
            history_only: Default::default(),
            locked: VecDeque::new(),
            kept: HashMap::new(),
            t0: Instant::now(),
            last_sent: Instant::now() - Duration::from_secs(10),
            pace_ms: std::env::var("BITAID_PACE_MS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(400),
            height_cache: 0,
            height_at: None,
            passed: 0,
            failed: 0,
        }
    }

    pub fn me(&self) -> String {
        hex::encode(self.keys.x_only_public_key().0.serialize())
    }

    pub fn log(&self, s: &str) {
        eprintln!(
            "[{} {:>7.2}s] {s}",
            self.name,
            self.t0.elapsed().as_secs_f64()
        );
    }

    pub fn check(&mut self, what: &str, ok: bool, detail: &str) {
        if ok {
            self.passed += 1;
        } else {
            self.failed += 1;
        }
        let d = if detail.is_empty() {
            String::new()
        } else {
            format!(" — {detail}")
        };
        println!(
            "[{}] {} {what}{d}",
            if ok { "PASS" } else { "FAIL" },
            self.name
        );
        self.log(&format!("{} {what}{d}", if ok { "PASS" } else { "FAIL" }));
    }

    /// Signs and publishes; `enc` encrypts with the case key (the relay then sees only tags).
    pub fn send(
        &mut self,
        k: u16,
        mut tags: Vec<Vec<String>>,
        msg: Msg,
        enc: Option<&str>,
    ) -> String {
        let name = msg.name();
        let h = self.height();
        let bytes = wire::sign(&self.keys, h, msg);
        let content = match enc {
            Some(case) => {
                let key = self.case_keys[case];
                tags.push(vec!["enc".into(), "1".into()]);
                b64(&wire::encrypt(&key, case.as_bytes(), &bytes))
            }
            None => b64(&bytes),
        };
        tags.push(vec!["t".into(), name.into()]);
        let e = Event::new(&self.keys, k, tags, content);
        // pace publishing: public relays rate-limit bursts from one key
        let gap = Duration::from_millis(self.pace_ms);
        let since = self.last_sent.elapsed();
        if since < gap {
            std::thread::sleep(gap - since);
        }
        self.client.publish(&e);
        self.last_sent = Instant::now();
        e.id
    }

    /// The chain height, refreshed at most every 10 s, so a slow chain connection never delays
    /// sending a message (the height in an envelope is informational).
    pub fn height(&mut self) -> u32 {
        if self
            .height_at
            .map(|t| t.elapsed() > Duration::from_secs(10))
            .unwrap_or(true)
        {
            let h = self.rpc.height();
            if h > 0 || self.height_at.is_none() {
                self.height_cache = h;
            }
            self.height_at = Some(Instant::now());
        }
        self.height_cache
    }

    /// Marks a case as kept: its messages are no longer pushed out by other traffic (see MAX_HISTORY).
    pub fn keep(&mut self, case: &str) {
        self.kept.entry(case.into()).or_default();
    }
    /// Keeps a case and records its oracle key (from its checked alert).
    pub fn keep_under(&mut self, case: &str, oracle_key: &str) {
        self.kept.entry(case.into()).or_default().oracle = wire::xonly(oracle_key);
    }
    /// A case that is over (settled, refunded, its seizure distributed) is kept no longer: its
    /// messages age out of the history like any others.
    pub fn unkeep(&mut self, case: &str) {
        self.kept.remove(case);
    }

    pub fn send_case(&mut self, case: &str, to: &[String], msg: Msg, encrypted: bool) -> String {
        self.keep(case);
        let mut tags = vec![vec!["c".into(), case.into()]];
        for p in to {
            tags.push(vec!["p".into(), p.clone()]);
        }
        self.send(
            kind::CASE,
            tags,
            msg,
            if encrypted { Some(case) } else { None },
        )
    }

    pub fn subscribe(&mut self, id: &str, filters: Vec<Filter>) {
        self.client.subscribe(id, filters);
    }

    /// Reads every message matching `filters` into the history only (for replays across cases, such as
    /// arbitrators' momentum), not into the mailbox. Add it after the subscriptions whose messages the
    /// node acts on: a message goes to the first subscription it matches.
    pub fn subscribe_history(&mut self, id: &str, filters: Vec<Filter>) {
        self.history_only.insert(id.to_string());
        self.client.subscribe(id, filters);
    }

    fn decode(&mut self, e: &Event) -> Option<Envelope> {
        let raw = unb64(&e.content)?;
        let bytes = if e.tag("enc") == Some("1") {
            let case = e.tag("c")?.to_string();
            match self.case_keys.get(&case) {
                Some(k) => wire::decrypt(k, case.as_bytes(), &raw)?,
                None => {
                    // a case this node holds no key for (yet): kept, within a bound, in case the key arrives
                    self.locked.push_back(e.clone());
                    let kept = &self.kept;
                    trim(&mut self.locked, MAX_LOCKED, |x| x.tag("c").is_some_and(|c| kept.contains_key(c)));
                    return None;
                }
            }
        } else {
            raw
        };
        let env = wire::verify(&bytes).ok()?;
        // the Bitaid signature and the event must be by the same key, written one way only (lower-case
        // hex): keys are compared as text, so another spelling of one key would count as another party
        if env.sender != e.pubkey
            || env.sender.len() != 64
            || !env.sender.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        {
            return None;
        }
        // a sender claiming to see blocks this node's chain does not have is lying or on another
        // chain; acting on it could set draws and deadlines by a future that never comes
        if env.height > self.height() + MAX_AHEAD {
            self.height_at = None;
            let h = self.height();
            if h > 0 && env.height > h + MAX_AHEAD {
                self.log(&format!(
                    "refused {} from {}: claims height {} (chain at {h})",
                    env.msg.name(),
                    &env.sender[..8.min(env.sender.len())],
                    env.height
                ));
                return None;
            }
        }
        if let Some(f) = self.observer.as_mut() {
            f(&env);
        }
        if let Some(case) = env.msg.case_id() {
            let record = match self.kept.get_mut(case) {
                // a kept case records each sender up to its bound; past it, the newest is not recorded
                Some(k) => {
                    let oracle = k.oracle;
                    let sealed = e.tag("enc") == Some("1");
                    let (m, cap) = if sealed {
                        (&mut k.sealed, PER_SENDER_SEALED)
                    } else {
                        (&mut k.open, PER_SENDER_OPEN)
                    };
                    // a new sender has room while the case's senders are under their bound; past
                    // it, only one whose message is backed on chain (an arbitrator's offer naming a
                    // live bond of its own) still gets in, so throwaway keys cannot fill a case and
                    // shut its arbitrators out. A sender refused is not remembered.
                    let bound = if sealed { SEALED_SENDERS } else { OPEN_SENDERS };
                    let room = m.contains_key(&env.sender)
                        || m.len() < bound
                        || (m.len() < 4 * bound
                            && oracle.is_some_and(|o| crate::arb::offer_backed(&self.rpc, &o, &env.msg)));
                    if room && m.get(&env.sender).copied().unwrap_or(0) < cap {
                        *m.entry(env.sender.clone()).or_default() += 1;
                        true
                    } else {
                        false
                    }
                }
                None => true,
            };
            if record {
                self.history.push(env.clone());
                if self.history.len() > MAX_HISTORY {
                    self.trim_history();
                }
            }
        }
        Some(env)
    }

    /// Drops the oldest tenth of the history that belongs to no kept case. If kept cases alone
    /// overfill it, the case kept longest is kept no more (it ages out like the rest) and the sweep
    /// runs again.
    fn trim_history(&mut self) {
        loop {
            let mut drop = (self.history.len() - MAX_HISTORY).max(MAX_HISTORY / 10);
            let kept = &self.kept;
            self.history.retain(|x| {
                if drop > 0 && !x.msg.case_id().is_some_and(|c| kept.contains_key(c)) {
                    drop -= 1;
                    false
                } else {
                    true
                }
            });
            if self.history.len() <= MAX_HISTORY {
                return;
            }
            let oldest = self
                .history
                .iter()
                .find_map(|x| x.msg.case_id().filter(|c| self.kept.contains_key(*c)).map(String::from));
            match oldest {
                Some(c) => {
                    self.kept.remove(&c);
                }
                None => return,
            }
        }
    }

    pub fn add_case_key(&mut self, case: &str, key: impl AsRef<[u8]>) {
        let Ok(key) = <[u8; 32]>::try_from(key.as_ref()) else {
            self.log(&format!("case {}: unsealed key has the wrong length; ignored", crate::pre(case, 8)));
            return;
        };
        self.case_keys.insert(case.into(), key);
        let locked = std::mem::take(&mut self.locked);
        for e in locked {
            if let Some(env) = self.decode(&e) {
                self.push_backlog(env, e);
            }
        }
    }

    fn pull(&mut self, timeout: Duration) -> bool {
        match self.client.next_event(timeout) {
            Some((sub, e)) => {
                if let Some(env) = self.decode(&e) {
                    if !self.history_only.contains(&sub) {
                        self.push_backlog(env, e);
                    }
                }
                true
            }
            None => false,
        }
    }

    /// Puts a message back in the mailbox, to be handled again by a later `wait` (a message that
    /// arrived before what it depends on, such as an escalation before the tier below is on chain).
    pub fn defer(&mut self, env: Envelope, e: Event) {
        self.push_backlog(env, e);
    }

    /// The mailbox is bounded: past MAX_BACKLOG the oldest unhandled messages that belong to no kept
    /// case are dropped, so a flood of well-formed messages nobody acts on cannot grow it without end,
    /// nor push out the messages of the cases this node is working on.
    fn push_backlog(&mut self, env: Envelope, e: Event) {
        self.backlog.push_back((env, e));
        let kept = &self.kept;
        trim(&mut self.backlog, MAX_BACKLOG, |x| x.0.msg.case_id().is_some_and(|c| kept.contains_key(c)));
    }

    /// The first message, old or new, for which `f` returns Some; others stay in the mailbox.
    pub fn wait<T>(
        &mut self,
        timeout: Duration,
        mut f: impl FnMut(&Envelope, &Event) -> Option<T>,
    ) -> Option<T> {
        let end = Instant::now() + timeout;
        loop {
            for i in 0..self.backlog.len() {
                let r = {
                    let (env, e) = &self.backlog[i];
                    f(env, e)
                };
                if let Some(t) = r {
                    self.backlog.remove(i);
                    return Some(t);
                }
            }
            let left = end.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return None;
            }
            self.pull(left.min(Duration::from_millis(200)));
        }
    }

    /// Everything `f` accepts until `timeout` or until `enough` returns true.
    pub fn collect<T>(
        &mut self,
        timeout: Duration,
        mut f: impl FnMut(&Envelope, &Event) -> Option<T>,
        mut enough: impl FnMut(&[T]) -> bool,
    ) -> Vec<T> {
        let mut out = Vec::new();
        let end = Instant::now() + timeout;
        while !enough(&out) {
            let left = end.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            match self.wait(left, &mut f) {
                Some(t) => out.push(t),
                None => break,
            }
        }
        out
    }

    /// Everything `f` accepts until the chain reaches `height` (a protocol deadline, judged by this
    /// node's own chain tip) or until `enough` returns true. `cap` bounds the wait on a chain that
    /// stops producing blocks.
    pub fn collect_until<T>(
        &mut self,
        height: u32,
        cap: Duration,
        mut f: impl FnMut(&Envelope, &Event) -> Option<T>,
        mut enough: impl FnMut(&[T]) -> bool,
    ) -> Vec<T> {
        let mut out = Vec::new();
        let end = Instant::now() + cap;
        while !enough(&out) && self.tip() < height && Instant::now() < end {
            if let Some(t) = self.wait(Duration::from_secs(2), &mut f) {
                out.push(t);
            }
        }
        out
    }

    /// Forgets the cached height, so the next message is signed with the chain's height now (an
    /// escalation's height fixes its draw block, which must not be mined yet when it arrives).
    pub fn refresh_height(&mut self) {
        self.height_at = None;
    }

    /// The chain height for judging deadlines: as `height`, but refreshed every 2 s.
    pub fn tip(&mut self) -> u32 {
        if self
            .height_at
            .map(|t| t.elapsed() > Duration::from_secs(2))
            .unwrap_or(true)
        {
            self.height_at = None;
        }
        self.height()
    }

    /// Waits for the first announcement of `role`; returns (identity, key, url).
    pub fn find_service(
        &mut self,
        role: &str,
        timeout: Duration,
    ) -> Option<(String, String, String)> {
        let r = role.to_string();
        self.wait(timeout, |env, _| match &env.msg {
            Msg::Announce { role, key, url } if *role == r => {
                Some((env.sender.clone(), key.clone(), url.clone()))
            }
            _ => None,
        })
    }

    pub fn all_services(
        &mut self,
        role: &str,
        want: usize,
        timeout: Duration,
    ) -> Vec<(String, String, String)> {
        let r = role.to_string();
        let mut seen = std::collections::HashSet::new();
        self.collect(
            timeout,
            |env, _| match &env.msg {
                Msg::Announce { role, key, url }
                    if *role == r && seen.insert(env.sender.clone()) =>
                {
                    Some((env.sender.clone(), key.clone(), url.clone()))
                }
                _ => None,
            },
            |v| v.len() >= want,
        )
    }

    pub fn summary(&self) -> i32 {
        println!(
            "[{}] {} passed, {} failed",
            self.name, self.passed, self.failed
        );
        if self.failed == 0 {
            0
        } else {
            1
        }
    }
}

pub fn point_hex(p: &Point) -> String {
    hex::encode(p.serialize())
}
pub fn point_from(s: &str) -> Option<Point> {
    Point::from_slice(&hex::decode(s).ok()?).ok()
}
pub fn scalar_from(s: &str) -> Option<Scalar> {
    Scalar::from_slice(&hex::decode(s).ok()?).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_flood_never_pushes_out_kept_entries() {
        let mut v: VecDeque<(bool, usize)> = (0..100).map(|i| (true, i)).collect();
        for i in 0..50_000 {
            v.push_back((false, i));
            trim(&mut v, 1_000, |x| x.0);
            assert!(v.len() <= 1_000 + 1_000 / 10);
        }
        assert_eq!(v.iter().filter(|x| x.0).count(), 100, "every kept entry stays");
        assert_eq!(v.iter().take(100).map(|x| x.1).collect::<Vec<_>>(), (0..100).collect::<Vec<_>>());
    }
}
