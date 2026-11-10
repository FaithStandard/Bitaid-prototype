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
pub const MAX_BACKLOG: usize = 20_000;
pub const MAX_LOCKED: usize = 5_000;
pub const MAX_HISTORY: usize = 100_000;
/// Blocks a sender's claimed height may run ahead of this node's chain.
pub const MAX_AHEAD: u32 = 6;

pub struct Node {
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
    locked: Vec<Event>,
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
        let (out, _) = rpc
            .confirmed_utxo(&op)
            .ok_or("not an unspent output in a block")?;
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
            eprintln!("[{name}] gossip: cannot lock a link stake ({e}); dialling without one");
            return None;
        }
    };
    rpc.confirm(&[txid]);
    let vout = (0..8u32).find(|v| {
        rpc.utxo(&bitcoin::OutPoint { txid, vout: *v })
            .map(|o| o.script_pubkey == spk)
            .unwrap_or(false)
    })?;
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
            history_only: Default::default(),
            locked: vec![],
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

    pub fn send_case(&mut self, case: &str, to: &[String], msg: Msg, encrypted: bool) -> String {
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
                    self.locked.push(e.clone());
                    if self.locked.len() > MAX_LOCKED {
                        self.locked.remove(0);
                    }
                    return None;
                }
            }
        } else {
            raw
        };
        let env = wire::verify(&bytes).ok()?;
        // the Bitaid signature and the event must be by the same key
        if env.sender != e.pubkey {
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
        if env.msg.case_id().is_some() {
            self.history.push(env.clone());
            if self.history.len() > MAX_HISTORY {
                let over = self.history.len() - MAX_HISTORY;
                self.history.drain(..over);
            }
        }
        Some(env)
    }

    pub fn add_case_key(&mut self, case: &str, key: [u8; 32]) {
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

    /// The mailbox is bounded: past MAX_BACKLOG the oldest unhandled message is dropped, so a flood
    /// of well-formed messages nobody acts on cannot grow it without end.
    fn push_backlog(&mut self, env: Envelope, e: Event) {
        self.backlog.push_back((env, e));
        while self.backlog.len() > MAX_BACKLOG {
            self.backlog.pop_front();
        }
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
