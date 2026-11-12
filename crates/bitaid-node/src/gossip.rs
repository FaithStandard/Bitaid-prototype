//! Core-to-Core gossip (Specification §7.1, B.2), the transport the protocol specifies: every Core
//! keeps direct links to peers, forwards each message it has not seen before to every other link,
//! and replays its recent log to a peer that connects, which is how a lagging node converges. Links
//! run over Tor onion services: a Core listens on a local port published as an onion service and
//! dials other Cores' onion addresses through its own Tor's SOCKS port, so no side ever needs an
//! inbound connection from the open internet, and no peer learns another's IP address. A phone app
//! is a thin client: one outbound link to its own Core, no listener.
//!
//! The unit carried is the signed event container of `nostr` (id, key, kind, tags, content, signature),
//! used here only as a self-verifying envelope; no relay is involved. Every message is verified
//! before it is stored, forwarded or delivered, so a peer can drop messages but never forge or alter
//! one. Not yet built: the DHT for peer discovery (peers come from a bootstrap list) and geofenced
//! forwarding (every message is flooded; subscribers filter by cell).
//!
//! Bonded links: there is no free tier. A Core opens every incoming link with a fresh challenge, and
//! the peer has 30 s to prove control of a link key with a stake on chain: an unspent, confirmed
//! output paying at least the link stake to that key alone. Until then the peer is sent nothing and
//! what it sends is dropped. A key cut for abuse (flooding, junk, oversized messages) is banned for an
//! hour, and one key holds at most two links at once, so a connection storm needs a stake per
//! connection. The stake is a fidelity bond: it costs the locked coins' time and a fresh output per
//! identity, and is not yet forfeitable (that needs the pool-co-signed path the role bonds have).
use crate::nostr::{now, Event, Filter};
use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::{schnorr, Keypair, Message, Secp256k1, XOnlyPublicKey};
use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::sync::mpsc::{channel, sync_channel, Receiver, RecvTimeoutError, Sender, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// How long a Core keeps messages to replay to peers that connect later.
pub const KEEP_SECS: u64 = 86_400;

// Limits against a hostile peer. Anyone who knows a Core's onion address can connect and send
// whatever it likes; none of this lets it run code (messages are parsed into fixed structures and
// signatures checked), but without limits it could exhaust memory, threads or bandwidth.
/// Longest line (one message) a peer may send; a longer one closes the link.
pub const MAX_LINE: usize = 2 << 20;
/// Message ids remembered for de-duplication (oldest forgotten first).
pub const MAX_SEEN: usize = 200_000;
/// Messages kept to replay to peers that connect later.
pub const MAX_STORE: usize = 50_000;
/// Bytes those messages may take in all.
pub const MAX_STORE_BYTES: usize = 256 << 20;
/// Bytes of the log one source (the link that first brought a message, or this node) may hold.
/// When the log is full, the source holding the most loses its oldest first: a peer flooding its
/// own messages pushes out its own, never the cases and history other links brought.
pub const MAX_SOURCE_BYTES: usize = 32 << 20;
/// Incoming links at once; when full, the least useful established one makes room.
pub const MAX_IN: usize = 64;
/// A message dated further than this in the future is refused.
pub const FUTURE_SECS: u64 = 600;
/// New messages an incoming link may bring: a burst of this many, refilled at RATE per second.
pub const BURST: f64 = 20_000.0;
pub const RATE: f64 = 100.0;
/// Lines that are not valid signed messages an incoming link may send before it is closed.
pub const MAX_JUNK: u32 = 1_000;
/// Seconds a peer has to prove its link stake.
pub const PROOF_SECS: u64 = 30;
/// Links one link key may hold at once.
pub const PER_KEY: usize = 2;
/// How long a key cut for abuse is refused.
pub const BAN_SECS: u64 = 3_600;
/// How often the proven links' stakes are checked again (one thread for all links): a stake spent
/// after the proof ends its links. A chain backend that cannot be asked cuts no link.
pub const RECHECK_SECS: u64 = 600;
/// How a stake check that could not reach the chain backend begins its error.
pub const UNAVAILABLE: &str = "UNAVAILABLE";

/// What a dialling node proves with: its link key and the outpoint (`txid:vout`) of its stake.
#[derive(Clone)]
pub struct Credential {
    pub keys: Keypair,
    pub stake: String,
}

/// Checks a claimed stake: (link key, outpoint) → Ok if it is an unspent, confirmed output paying at
/// least the link stake to that key alone.
pub type Verify = Arc<dyn Fn(&XOnlyPublicKey, &str) -> Result<(), String> + Send + Sync>;

/// What a Core needs to demand proofs: the checker, and the addresses it is dialled at (a proof
/// signed for another address is refused, so a hostile Core cannot pass on a peer's proof).
#[derive(Clone)]
pub struct Demand {
    pub verify: Verify,
    pub names: Vec<String>,
}

/// The digest a link key signs: the domain tag, the Core's challenge and the address dialled.
pub fn link_digest(challenge: &[u8; 32], to: &str) -> [u8; 32] {
    let mut v = b"bitaid/link/v1".to_vec();
    v.extend_from_slice(challenge);
    v.extend_from_slice(to.as_bytes());
    sha256::Hash::hash(&v).to_byte_array()
}

/// The proof line a dialler sends in answer to `challenge`.
pub fn proof_line(c: &Credential, challenge: &[u8; 32], to: &str) -> String {
    proof_line_since(c, challenge, to, 0)
}

/// The proof line, with the time of the newest message the dialler has had over a link: the Core
/// replays only what came after (less SINCE_MARGIN). Not signed: a lie only costs the liar messages.
pub fn proof_line_since(c: &Credential, challenge: &[u8; 32], to: &str, since: u64) -> String {
    let secp = Secp256k1::new();
    let msg = Message::from_digest(link_digest(challenge, to));
    let sig = secp.sign_schnorr(&msg, &c.keys);
    serde_json::json!({"proof": {
        "key": c.keys.x_only_public_key().0.to_string(),
        "stake": c.stake,
        "to": to,
        "sig": hex::encode(sig.as_ref()),
    }, "since": since})
    .to_string()
}

/// A set that forgets its oldest members past `cap`.
pub struct Bounded {
    set: HashSet<String>,
    order: VecDeque<String>,
    cap: usize,
}

impl Bounded {
    pub fn new(cap: usize) -> Bounded {
        Bounded { set: HashSet::new(), order: VecDeque::new(), cap }
    }
    pub fn contains(&self, k: &str) -> bool {
        self.set.contains(k)
    }
    pub fn insert(&mut self, k: String) {
        if self.set.insert(k.clone()) {
            self.order.push_back(k);
            while self.order.len() > self.cap {
                if let Some(old) = self.order.pop_front() {
                    self.set.remove(&old);
                }
            }
        }
    }
}

impl Default for Bounded {
    fn default() -> Bounded {
        Bounded::new(MAX_SEEN)
    }
}

struct Link {
    /// lines queued for this peer, shared with every other link (one copy of each message in memory);
    /// bounded, so a peer that stops reading is closed rather than queued for without end
    out: SyncSender<Arc<str>>,
    incoming: bool,
    since: Instant,
    /// new, valid messages this link brought
    useful: u64,
    /// to close it from outside (eviction)
    stream: Option<TcpStream>,
    /// proved its stake (or one we dialled): only these are sent messages
    authed: bool,
}

/// The log of recent messages, accounted per source. A message is held by every link that brought
/// it, not only the first: a peer that races honest messages to this node and then floods cannot
/// take them down with its own, since dropping its share leaves them held by the honest links that
/// also delivered them. A message leaves the log when its last holder lets go (or it ages out).
#[derive(Default)]
pub struct Store {
    items: HashMap<String, (Event, Arc<str>, Vec<String>)>,
    /// ids in arrival order (entries already dropped are skipped and compacted away)
    order: VecDeque<String>,
    by_src: HashMap<String, VecDeque<String>>,
    /// bytes and messages each source holds (each holder is charged a message in full)
    src_bytes: HashMap<String, usize>,
    src_count: HashMap<String, usize>,
    bytes: usize,
    last_sweep: u64,
}

impl Store {
    pub fn len(&self) -> usize {
        self.items.len()
    }
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
    /// The kept messages, oldest first.
    pub fn iter(&self) -> impl Iterator<Item = (&Event, &Arc<str>)> {
        self.order.iter().filter_map(|id| self.items.get(id).map(|x| (&x.0, &x.1)))
    }
    /// Whether `src` holds message `id`.
    pub fn holds(&self, id: &str, src: &str) -> bool {
        self.items.get(id).is_some_and(|x| x.2.iter().any(|o| o == src))
    }
    fn uncharge(&mut self, src: &str, n: usize) {
        if let Some(b) = self.src_bytes.get_mut(src) {
            *b = b.saturating_sub(n);
        }
        let empty = match self.src_count.get_mut(src) {
            Some(c) => {
                *c = c.saturating_sub(1);
                *c == 0
            }
            None => true,
        };
        if empty {
            self.src_bytes.remove(src);
            self.src_count.remove(src);
            self.by_src.remove(src);
        }
    }
    fn charge(&mut self, id: &str, src: &str, n: usize) {
        self.by_src.entry(src.into()).or_default().push_back(id.into());
        *self.src_bytes.entry(src.into()).or_default() += n;
        *self.src_count.entry(src.into()).or_default() += 1;
    }
    /// Removes a message outright (aged out), releasing every holder's share.
    fn remove(&mut self, id: &str) {
        if let Some((_, l, owners)) = self.items.remove(id) {
            self.bytes -= l.len();
            for o in owners {
                self.uncharge(&o, l.len());
            }
        }
    }
    /// `src` lets go of its oldest message; the message itself goes only if no one else holds it.
    fn drop_oldest(&mut self, src: &str) {
        while let Some(id) = self.by_src.get_mut(src).and_then(|q| q.pop_front()) {
            let Some(x) = self.items.get_mut(&id) else { continue };
            let Some(i) = x.2.iter().position(|o| o == src) else { continue };
            x.2.swap_remove(i);
            let (n, last) = (x.1.len(), x.2.is_empty());
            if last {
                self.items.remove(&id);
                self.bytes -= n;
            }
            self.uncharge(src, n);
            return;
        }
        self.src_bytes.remove(src);
        self.src_count.remove(src);
        self.by_src.remove(src);
    }
    /// Records that `src` also brought message `id`, already kept: it now shares holding it.
    pub fn also_from(&mut self, id: &str, src: &str) {
        let Some(x) = self.items.get_mut(id) else { return };
        if x.2.iter().any(|o| o == src) {
            return;
        }
        x.2.push(src.into());
        let n = x.1.len();
        self.charge(id, src, n);
        while self.src_bytes.get(src).copied().unwrap_or(0) > MAX_SOURCE_BYTES {
            self.drop_oldest(src);
        }
    }
    pub fn insert(&mut self, e: Event, line: Arc<str>, src: &str, t: u64) {
        // an id already kept is not counted twice (its bytes would never be released)
        if self.items.contains_key(&e.id) {
            self.also_from(&e.id, src);
            return;
        }
        let n = line.len();
        let id = e.id.clone();
        self.order.push_back(id.clone());
        self.bytes += n;
        self.items.insert(id.clone(), (e, line, vec![src.into()]));
        self.charge(&id, src, n);
        while self.src_bytes.get(src).copied().unwrap_or(0) > MAX_SOURCE_BYTES {
            self.drop_oldest(src);
        }
        // over the byte budget: the source holding the most bytes lets go of its oldest; over the
        // count: the source holding the most messages (small messages cannot push out others by count)
        while self.bytes > MAX_STORE_BYTES {
            let Some(big) = self.src_bytes.iter().max_by_key(|x| *x.1).map(|x| x.0.clone()) else {
                break;
            };
            self.drop_oldest(&big);
        }
        while self.items.len() > MAX_STORE {
            let Some(big) = self.src_count.iter().max_by_key(|x| *x.1).map(|x| x.0.clone()) else {
                break;
            };
            self.drop_oldest(&big);
        }
        // messages past the replay window go, swept at most once a minute
        if t >= self.last_sweep + 60 {
            self.last_sweep = t;
            let cutoff = t.saturating_sub(KEEP_SECS);
            let old: Vec<String> = self
                .items
                .iter()
                .filter(|x| x.1 .0.created_at < cutoff)
                .map(|x| x.0.clone())
                .collect();
            for id in old {
                self.remove(&id);
            }
        }
        let held: usize = self.src_count.values().sum();
        if self.order.len() > 2 * self.items.len() + 1_000
            || self.by_src.values().map(|q| q.len()).sum::<usize>() > 2 * held + 1_000
        {
            let items = &self.items;
            self.order.retain(|id| items.contains_key(id));
            for (src, q) in self.by_src.iter_mut() {
                q.retain(|id| items.get(id).is_some_and(|x| x.2.iter().any(|o| o == src)));
            }
        }
    }
}

#[derive(Default)]
struct Shared {
    seen: Bounded,
    store: Store,
    links: HashMap<u64, Link>,
    next: u64,
    /// incoming links accepted, counted from the moment of accepting (before the link's thread has
    /// registered it), so a burst of connections cannot slip past MAX_IN
    incoming: usize,
    /// link keys refused until the given time, and links held per key
    banned: HashMap<String, Instant>,
    per_key: HashMap<String, usize>,
    /// the stake each proven link proved with, checked again by one thread
    stakes: HashMap<u64, (XOnlyPublicKey, String)>,
    /// the newest message (by its time) that reached this node over a link: what a peer it
    /// reconnects to need not send again (a slow Tor link otherwise re-reads the whole log on every
    /// reconnect and stalls again)
    newest_in: u64,
}

/// How far before a peer's newest message a replay to it starts (clocks and gossip order differ).
pub const SINCE_MARGIN: u64 = 600;

/// Why a message was not admitted.
enum Admit {
    New(Arc<str>),
    Seen,
    Invalid,
}

pub struct Gossip {
    shared: Arc<Mutex<Shared>>,
    rx: Receiver<Event>,
    tx: Sender<Event>,
    subs: Vec<(String, Vec<Filter>)>,
    delivered: Bounded,
    pending: VecDeque<(String, Event)>,
    socks: Option<String>,
}

/// Connects through a SOCKS5 proxy (Tor) to `host:port`, the host resolved by the proxy, so
/// `.onion` addresses work and no DNS query leaves this machine.
pub fn socks5_connect(proxy: &str, host: &str, port: u16) -> std::io::Result<TcpStream> {
    let mut s = TcpStream::connect(proxy)?;
    s.set_read_timeout(Some(Duration::from_secs(120)))?;
    s.write_all(&[5, 1, 0])?;
    let mut r = [0u8; 2];
    s.read_exact(&mut r)?;
    if r != [5, 0] {
        return Err(std::io::Error::other(
            "SOCKS5: no acceptable authentication",
        ));
    }
    let h = host.as_bytes();
    let mut req = vec![5, 1, 0, 3, h.len() as u8];
    req.extend_from_slice(h);
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req)?;
    let mut head = [0u8; 4];
    s.read_exact(&mut head)?;
    if head[1] != 0 {
        return Err(std::io::Error::other(format!(
            "SOCKS5: connect refused (code {})",
            head[1]
        )));
    }
    let skip = match head[3] {
        1 => 4 + 2,
        4 => 16 + 2,
        3 => {
            let mut l = [0u8; 1];
            s.read_exact(&mut l)?;
            l[0] as usize + 2
        }
        _ => return Err(std::io::Error::other("SOCKS5: bad reply")),
    };
    let mut rest = vec![0u8; skip];
    s.read_exact(&mut rest)?;
    s.set_read_timeout(None)?;
    Ok(s)
}

fn split_addr(a: &str) -> Option<(String, u16)> {
    let (h, p) = a.rsplit_once(':')?;
    Some((h.to_string(), p.parse().ok()?))
}

/// Dials a peer: through SOCKS5 if a proxy is given or the host is an onion address, else directly.
pub fn dial(addr: &str, socks: Option<&str>) -> std::io::Result<TcpStream> {
    let (host, port) =
        split_addr(addr).ok_or_else(|| std::io::Error::other("address must be host:port"))?;
    // onion addresses go through Tor; anything else (a Core on the same machine, a LAN test) directly,
    // since Tor refuses to connect to local addresses
    match socks {
        Some(p) if host.ends_with(".onion") => socks5_connect(p, &host, port),
        None if host.ends_with(".onion") => {
            Err(std::io::Error::other("an onion address needs --socks"))
        }
        _ => {
            let sa = (host.as_str(), port)
                .to_socket_addrs()?
                .next()
                .ok_or_else(|| std::io::Error::other("no address"))?;
            TcpStream::connect_timeout(&sa, Duration::from_secs(20))
        }
    }
}

fn admit(shared: &Arc<Mutex<Shared>>, e: &Event, src: &str) -> Admit {
    let mut g = shared.lock().unwrap();
    if g.seen.contains(&e.id) {
        // a later deliverer shares holding it, so the first one cannot take it down alone
        g.store.also_from(&e.id, src);
        return Admit::Seen;
    }
    let t = now();
    // a message older than the replay window, or dated in the future, is a replay or a forgery
    // of time: refused before the signature is even checked
    // just past the window is not junk: an honest peer's replay can cross the edge in transit
    if e.created_at.saturating_add(KEEP_SECS) < t && e.created_at.saturating_add(KEEP_SECS + 600) >= t {
        return Admit::Seen;
    }
    if e.created_at.saturating_add(KEEP_SECS) < t || e.created_at > t + FUTURE_SECS || !e.verify() {
        return Admit::Invalid;
    }
    g.seen.insert(e.id.clone());
    let line: Arc<str> = serde_json::to_string(e).unwrap().into();
    g.store.insert(e.clone(), line.clone(), src, t);
    if src != "self" && e.created_at <= t + 60 {
        g.newest_in = g.newest_in.max(e.created_at);
    }
    Admit::New(line)
}

/// Reads one line of at most MAX_LINE bytes: Ok(None) at the end of the stream, Err if too long.
fn read_line(r: &mut BufReader<TcpStream>, buf: &mut Vec<u8>) -> std::io::Result<Option<()>> {
    buf.clear();
    let n = r.by_ref().take(MAX_LINE as u64 + 1).read_until(b'\n', buf)?;
    if n == 0 {
        return Ok(None);
    }
    if buf.last() != Some(&b'\n') && buf.len() > MAX_LINE {
        return Err(std::io::Error::other("message longer than the limit"));
    }
    while buf.last() == Some(&b'\n') || buf.last() == Some(&b'\r') {
        buf.pop();
    }
    Ok(Some(()))
}

/// Makes room for a new incoming link if all slots are taken: a link still without its proof of stake
/// after 10 s is closed. A staked link is never closed to make room for a stranger, so a connection
/// storm cannot cut honest peers off; it can only hold free slots for the proof window, and filling
/// them with staked links takes a stake per two links. False if no slot can be freed.
fn make_room(shared: &Arc<Mutex<Shared>>) -> bool {
    let mut g = shared.lock().unwrap();
    if g.incoming < MAX_IN {
        g.incoming += 1;
        return true;
    }
    // only a link still without its proof after 10 s gives up its slot: a stranger never pushes out
    // a peer that has proved its stake, even one that only listens
    let victim = g
        .links
        .values()
        .filter(|l| l.incoming && !l.authed && l.since.elapsed() > Duration::from_secs(10))
        .min_by_key(|l| l.since);
    match victim.and_then(|l| l.stream.as_ref()) {
        Some(s) => {
            // the victim's slot passes to the newcomer (its own count is given back when it ends)
            eprintln!("gossip: making room: closing {:?}, still without a proof", s.peer_addr().ok());
            let _ = s.shutdown(std::net::Shutdown::Both);
            g.incoming += 1;
            true
        }
        None => false,
    }
}

/// Checks every proven link's stake once, outside the lock; closes the links whose stake no longer
/// holds, and forgets the stakes of links that have ended.
fn recheck(shared: &Arc<Mutex<Shared>>, verify: &Verify) {
    let todo: Vec<(u64, XOnlyPublicKey, String)> = {
        let mut g = shared.lock().unwrap();
        let live: std::collections::HashSet<u64> = g.links.keys().copied().collect();
        g.stakes.retain(|id, _| live.contains(id));
        g.stakes.iter().map(|(id, (k, s))| (*id, *k, s.clone())).collect()
    };
    let mut verdict: HashMap<String, Result<(), String>> = HashMap::new();
    for (id, xk, stake) in todo {
        let r = verdict
            .entry(format!("{xk}{stake}"))
            .or_insert_with(|| verify(&xk, &stake))
            .clone();
        match r {
            Err(e) if !e.starts_with(UNAVAILABLE) => {
                eprintln!("gossip: link {id}: stake {stake} no longer holds ({e}); closing");
                let g = shared.lock().unwrap();
                if let Some(s) = g.links.get(&id).and_then(|l| l.stream.as_ref()) {
                    let _ = s.shutdown(std::net::Shutdown::Both);
                }
            }
            _ => {}
        }
    }
}

/// Queues `line` for every link but `except`; a link whose queue is full (a peer that stopped
/// reading) is closed.
fn forward(g: &Shared, line: &Arc<str>, except: Option<u64>) {
    for (lid, l) in g.links.iter() {
        if Some(*lid) != except && l.authed {
            if let Err(TrySendError::Full(_)) = l.out.try_send(line.clone()) {
                eprintln!("gossip: link {lid} not reading (its queue is full); closing it");
                if let Some(s) = &l.stream {
                    let _ = s.shutdown(std::net::Shutdown::Both);
                }
            }
        }
    }
}

/// Checks a proof line against `challenge`; Ok(link key) or why it was refused.
fn check_proof(
    shared: &Arc<Mutex<Shared>>,
    d: &Demand,
    challenge: &[u8; 32],
    line: &[u8],
) -> Result<(String, XOnlyPublicKey, String), String> {
    let v: serde_json::Value = serde_json::from_slice(line).map_err(|_| "not a proof".to_string())?;
    let p = v.get("proof").ok_or("not a proof")?;
    let field = |k: &str| p.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string();
    let (key, stake, to, sig) = (field("key"), field("stake"), field("to"), field("sig"));
    if !d.names.is_empty() && !d.names.iter().any(|n| *n == to) {
        return Err(format!("proof signed for another address ({to})"));
    }
    let xk: XOnlyPublicKey = key.parse().map_err(|_| "bad key".to_string())?;
    // the key as one spelling: bans and the per-key limit must not be dodged by changing the case of a
    // hex letter (review finding, reproduced)
    let key = xk.to_string();
    let sig = hex::decode(&sig)
        .ok()
        .and_then(|b| schnorr::Signature::from_slice(&b).ok())
        .ok_or("bad signature")?;
    let msg = Message::from_digest(link_digest(challenge, &to));
    Secp256k1::verification_only()
        .verify_schnorr(&sig, &msg, &xk)
        .map_err(|_| "signature does not match the challenge".to_string())?;
    {
        let g = shared.lock().unwrap();
        if let Some(t) = g.banned.get(&key) {
            if Instant::now() < *t {
                return Err(format!("key {} banned", crate::pre(&key, 8)));
            }
        }
        if g.per_key.get(&key).copied().unwrap_or(0) >= PER_KEY {
            return Err(format!("key {} already holds {PER_KEY} links", crate::pre(&key, 8)));
        }
    }
    (d.verify)(&xk, &stake).map_err(|e| format!("stake {stake}: {e}"))?;
    let mut g = shared.lock().unwrap();
    // checked again under the lock: two links of one key proving at once
    let n = g.per_key.entry(key.clone()).or_insert(0);
    if *n >= PER_KEY {
        return Err(format!("key {} already holds {PER_KEY} links", crate::pre(&key, 8)));
    }
    *n += 1;
    Ok((key, xk, stake))
}

#[allow(clippy::too_many_arguments)]
fn run_link(
    shared: Arc<Mutex<Shared>>,
    local: Sender<Event>,
    s: TcpStream,
    label: String,
    incoming: bool,
    demand: Option<Demand>,
    cred: Option<Credential>,
    to: String,
    resume: u64,
) {
    let _ = s.set_nodelay(true);
    let mut w = match s.try_clone() {
        Ok(w) => w,
        Err(_) => return,
    };
    // a Tor circuit to a phone can stall for a minute and recover: only a longer stall ends the link
    let _ = w.set_write_timeout(Some(Duration::from_secs(180)));
    let mut r = BufReader::new(match s.try_clone() {
        Ok(x) => x,
        Err(_) => return,
    });
    let mut buf = Vec::new();
    // every incoming link opens with a fresh challenge; a dialler answers it with its proof
    let challenge: [u8; 32] = rand::random();
    let mut first: Option<Vec<u8>> = None;
    // what the peer says it already has: replays to it start there (0: everything)
    let mut since = 0u64;
    if incoming {
        let l = format!("{{\"challenge\":\"{}\"}}\n", hex::encode(challenge));
        if w.write_all(l.as_bytes()).is_err() {
            return;
        }
    } else {
        let _ = s.set_read_timeout(Some(Duration::from_secs(PROOF_SECS)));
        let got = read_line(&mut r, &mut buf);
        match &got {
            Ok(Some(())) => {}
            Ok(None) => eprintln!("gossip: {label}: closed before sending a challenge"),
            Err(e) => eprintln!("gossip: {label}: no challenge within {PROOF_SECS} s ({e})"),
        }
        if let Ok(Some(())) = got {
            let v = serde_json::from_slice::<serde_json::Value>(&buf).ok();
            let ch = v
                .as_ref()
                .and_then(|v| v.get("challenge").and_then(|c| c.as_str()).map(String::from))
                .and_then(|h| hex::decode(h).ok())
                .and_then(|b| <[u8; 32]>::try_from(b).ok());
            let _ = &v;
            since = resume;
            match (ch, &cred) {
                (Some(ch), Some(c)) => {
                    let mine = shared.lock().unwrap().newest_in;
                    let l = proof_line_since(c, &ch, &to, mine) + "\n";
                    if w.write_all(l.as_bytes()).is_err() {
                        return;
                    }
                }
                (Some(_), None) => eprintln!("gossip: {label}: the Core asks for a link stake and this node has none"),
                // a Core that opens with a message, not a challenge: keep it
                (None, _) => first = Some(buf.clone()),
            }
        }
        let _ = s.set_read_timeout(None);
    }
    let must_prove = incoming && demand.is_some();
    let (otx, orx) = sync_channel::<Arc<str>>(MAX_STORE + 10_000);
    let replay = |g: &Shared, tx: &SyncSender<Arc<str>>, since: u64| {
        // the recent log first, so a peer that connects late catches up; nothing within a minute
        // of leaving the window is sent, so the peer never counts this node's replay as stale junk,
        // and nothing the peer says it already had (its newest, less a margin)
        let fresh = (now().saturating_sub(KEEP_SECS) + 60).max(since.saturating_sub(SINCE_MARGIN));
        for (e, l) in g.store.iter() {
            if e.created_at >= fresh {
                let _ = tx.try_send(l.clone());
            }
        }
    };
    let id = {
        let mut g = shared.lock().unwrap();
        g.next += 1;
        let id = g.next;
        if !must_prove {
            replay(&g, &otx, since);
        }
        g.links.insert(
            id,
            Link {
                out: otx.clone(),
                incoming,
                since: Instant::now(),
                useful: 0,
                stream: s.try_clone().ok(),
                authed: !must_prove,
            },
        );
        id
    };
    let wl = label.clone();
    std::thread::spawn(move || {
        for line in orx {
            if let Err(e) = w.write_all(line.as_bytes()).and_then(|_| w.write_all(b"\n")) {
                eprintln!("gossip: write to {wl} failed ({e}); closing the link");
                // the reader side ends with it, so the peer redials and catches up from the replay
                let _ = w.shutdown(std::net::Shutdown::Both);
                break;
            }
        }
    });
    let mut key: Option<String> = None;
    let mut junk = 0u32;
    let mut why: Option<String> = None;
    if must_prove {
        let d = demand.as_ref().unwrap();
        let end = Instant::now() + Duration::from_secs(PROOF_SECS);
        let _ = s.set_read_timeout(Some(Duration::from_secs(PROOF_SECS)));
        why = Some(loop {
            if Instant::now() > end {
                break ": no proof of stake in time".into();
            }
            match read_line(&mut r, &mut buf) {
                Ok(Some(())) => {}
                Ok(None) => break String::new(),
                Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {
                    break ": no proof of stake in time".into()
                }
                Err(e) => break format!(": {e}"),
            }
            if !buf.starts_with(b"{\"proof\"") {
                // anything else before the proof is dropped unread
                junk += 1;
                if junk > MAX_JUNK {
                    break ": too many lines before a proof".into();
                }
                continue;
            }
            match check_proof(&shared, d, &challenge, &buf) {
                Ok((k, xk, stake)) => {
                    since = serde_json::from_slice::<serde_json::Value>(&buf)
                        .ok()
                        .and_then(|v| v.get("since").and_then(|x| x.as_u64()))
                        .unwrap_or(0);
                    key = Some(k);
                    // the stake is checked again while the link lasts (see RECHECK_SECS)
                    shared.lock().unwrap().stakes.insert(id, (xk, stake));
                    break String::new();
                }
                Err(e) => break format!(": no valid proof of stake ({e})"),
            }
        });
        if key.is_some() {
            why = None;
            let _ = s.set_read_timeout(None);
            let mut g = shared.lock().unwrap();
            replay(&g, &otx, since);
            if let Some(l) = g.links.get_mut(&id) {
                l.authed = true;
            }
            drop(g);
            eprintln!("gossip: link up ({label}), key {}", crate::pre(key.as_deref().unwrap_or(""), 16));
        }
    } else {
        eprintln!("gossip: link up ({label})");
    }
    drop(otx);
    // an incoming link (a peer we did not choose) is rate-limited: a burst, then RATE new messages a
    // second; links we dialled ourselves are trusted with their replay of a full log
    let (mut tokens, mut t0) = (BURST, Instant::now());
    let why = match why {
        Some(w) => w,
        None => loop {
            if let Some(f) = first.take() {
                buf = f;
            } else {
                match read_line(&mut r, &mut buf) {
                    Ok(Some(())) => {}
                    Ok(None) => break String::new(),
                    Err(e) => break format!(": {e}"),
                }
            }
            let e = match std::str::from_utf8(&buf)
                .ok()
                .and_then(|l| serde_json::from_str::<Event>(l).ok())
            {
                Some(e) => e,
                None => {
                    junk += 1;
                    if incoming && junk > MAX_JUNK {
                        break ": too many malformed lines".into();
                    }
                    continue;
                }
            };
            let line = match admit(&shared, &e, key.as_deref().unwrap_or(&label)) {
                // a copy of what this node already has is cheap but not free: resending the log
                // over and over drains the link's allowance too, at a fiftieth of a new message
                Admit::Seen => {
                    if incoming {
                        tokens = (tokens + t0.elapsed().as_secs_f64() * RATE).min(BURST);
                        t0 = Instant::now();
                        tokens -= 0.02;
                        if tokens < 0.0 {
                            break ": flooding (copies above the rate limit)".into();
                        }
                    }
                    continue;
                }
                Admit::Invalid => {
                    junk += 1;
                    if incoming && junk > MAX_JUNK {
                        break ": too many invalid messages".into();
                    }
                    continue;
                }
                Admit::New(l) => l,
            };
            if incoming {
                tokens = (tokens + t0.elapsed().as_secs_f64() * RATE).min(BURST);
                t0 = Instant::now();
                tokens -= 1.0;
                if tokens < 0.0 {
                    break ": flooding (new messages above the rate limit)".into();
                }
            }
            // forward to every other link, deliver locally
            let mut g = shared.lock().unwrap();
            if let Some(l) = g.links.get_mut(&id) {
                l.useful += 1;
            }
            forward(&g, &line, Some(id));
            drop(g);
            let _ = local.send(e);
        },
    };
    let abuse = why.contains("flooding")
        || why.contains("malformed")
        || why.contains("invalid messages")
        || why.contains("longer than the limit");
    {
        let mut g = shared.lock().unwrap();
        g.links.remove(&id);
        if incoming {
            g.incoming = g.incoming.saturating_sub(1);
        }
        if let Some(k) = &key {
            if let Some(n) = g.per_key.get_mut(k) {
                *n = n.saturating_sub(1);
            }
            if abuse {
                g.banned
                    .insert(k.clone(), Instant::now() + Duration::from_secs(BAN_SECS));
            }
        }
    }
    // close the socket outright: the writer thread may be blocked sending to a peer that stopped
    // reading, and would otherwise hold the socket (and itself) open for ever
    let _ = s.shutdown(std::net::Shutdown::Both);
    let banned = match (&key, abuse) {
        (Some(k), true) => format!("; key {} banned for {} min", crate::pre(&k, 16), BAN_SECS / 60),
        _ => String::new(),
    };
    eprintln!("gossip: link down ({label}){why}{banned}");
}

impl Gossip {
    /// `listen`: local address to accept peers on (published as an onion service), if any;
    /// `peers`: Cores to dial and keep dialled; `socks`: Tor's SOCKS port, for onion peers.
    pub fn start(
        listen: Option<&str>,
        peers: &[String],
        socks: Option<&str>,
    ) -> std::io::Result<Gossip> {
        Self::start_with(listen, peers, socks, None, None)
    }

    /// As `start`, with bonded links: `demand` makes this Core require a proof of stake on every
    /// incoming link; `cred` is what this node proves with when it dials.
    pub fn start_with(
        listen: Option<&str>,
        peers: &[String],
        socks: Option<&str>,
        demand: Option<Demand>,
        cred: Option<Credential>,
    ) -> std::io::Result<Gossip> {
        let shared = Arc::new(Mutex::new(Shared::default()));
        let (tx, rx) = channel();
        if let Some(d) = demand.clone() {
            let sh = shared.clone();
            std::thread::spawn(move || loop {
                std::thread::sleep(Duration::from_secs(RECHECK_SECS));
                recheck(&sh, &d.verify);
            });
        }
        if let Some(addr) = listen {
            let l = TcpListener::bind(addr)?;
            let (sh, t, demand) = (shared.clone(), tx.clone(), demand.clone());
            std::thread::spawn(move || {
                for s in l.incoming().flatten() {
                    if !make_room(&sh) {
                        // every slot is held by a link too new to judge: refuse this one
                        let _ = s.shutdown(std::net::Shutdown::Both);
                        continue;
                    }
                    let (sh, t, d) = (sh.clone(), t.clone(), demand.clone());
                    let label = s
                        .peer_addr()
                        .map(|a| format!("incoming {a}"))
                        .unwrap_or("incoming".into());
                    std::thread::spawn(move || run_link(sh, t, s, label, true, d, None, String::new(), 0));
                }
            });
        }
        for p in peers {
            let (sh, t, p, sx, c) = (
                shared.clone(),
                tx.clone(),
                p.clone(),
                socks.map(String::from),
                cred.clone(),
            );
            // keep the link up: redial with backoff whenever it drops
            std::thread::spawn(move || {
                let mut wait = 1u64;
                // when the last link to this peer that lasted came up: a redial replays only what
                // this node has had since then (less a margin); what came before that link the peer
                // had already, and what the link failed to carry is all newer
                let mut down = 0u64;
                loop {
                    let t0 = Instant::now();
                    let up = now();
                    match dial(&p, sx.as_deref()) {
                        Ok(s) => {
                            run_link(sh.clone(), t.clone(), s, format!("to {p}"), false, None, c.clone(), p.clone(), down);
                            if t0.elapsed() > Duration::from_secs(PROOF_SECS) {
                                down = up;
                            }
                        }
                        Err(e) => eprintln!("gossip: cannot reach {p}: {e}"),
                    }
                    if t0.elapsed() > Duration::from_secs(30) {
                        wait = 1;
                    }
                    std::thread::sleep(Duration::from_secs(wait));
                    wait = (wait * 2).min(30);
                }
            });
        }
        Ok(Gossip {
            shared,
            rx,
            tx,
            subs: vec![],
            delivered: Bounded::new(MAX_SEEN),
            pending: VecDeque::new(),
            socks: socks.map(String::from),
        })
    }

    pub fn links(&self) -> usize {
        self.shared.lock().unwrap().links.len()
    }

    /// Waits until at least `n` links are up, or `timeout`.
    pub fn wait_links(&self, n: usize, timeout: Duration) -> usize {
        let end = Instant::now() + timeout;
        while self.links() < n && Instant::now() < end {
            std::thread::sleep(Duration::from_millis(200));
        }
        self.links()
    }

    pub fn socks(&self) -> Option<&str> {
        self.socks.as_deref()
    }

    /// Sends to every link, and to this node's own subscriptions (as a relay echoes).
    pub fn publish(&self, e: &Event) {
        if let Admit::New(line) = admit(&self.shared, e, "self") {
            forward(&self.shared.lock().unwrap(), &line, None);
            let _ = self.tx.send(e.clone());
        }
    }

    /// Adds a local subscription and delivers matching messages already in the log.
    pub fn subscribe(&mut self, id: &str, filters: Vec<Filter>) {
        let stored: Vec<Event> = self.shared.lock().unwrap().store.iter().map(|x| x.0.clone()).collect();
        for e in stored {
            if !self.delivered.contains(&e.id) && filters.iter().any(|f| f.matches(&e)) {
                self.delivered.insert(e.id.clone());
                self.pending.push_back((id.to_string(), e));
            }
        }
        self.subs.retain(|(i, _)| i != id);
        self.subs.push((id.into(), filters));
    }

    pub fn unsubscribe(&mut self, id: &str) {
        self.subs.retain(|(i, _)| i != id);
    }

    pub fn next_event(&mut self, timeout: Duration) -> Option<(String, Event)> {
        if let Some(x) = self.pending.pop_front() {
            return Some(x);
        }
        let end = Instant::now() + timeout;
        loop {
            let left = end.saturating_duration_since(Instant::now());
            match self.rx.recv_timeout(left) {
                Ok(e) => {
                    if self.delivered.contains(&e.id) {
                        continue;
                    }
                    if let Some((sid, _)) = self
                        .subs
                        .iter()
                        .find(|(_, fs)| fs.iter().any(|f| f.matches(&e)))
                    {
                        self.delivered.insert(e.id.clone());
                        return Some((sid.clone(), e));
                    }
                }
                Err(RecvTimeoutError::Timeout) | Err(RecvTimeoutError::Disconnected) => {
                    return None
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(id: usize, t: u64, size: usize) -> (Event, Arc<str>) {
        let e = Event {
            id: format!("{id:064x}"),
            pubkey: String::new(),
            created_at: t,
            kind: 1,
            tags: vec![],
            content: "x".repeat(size),
            sig: String::new(),
        };
        let l: Arc<str> = serde_json::to_string(&e).unwrap().into();
        (e, l)
    }

    #[test]
    fn a_flooding_source_pushes_out_only_its_own() {
        let t = now();
        let mut s = Store::default();
        for i in 0..100 {
            let (e, l) = ev(i, t, 1_000);
            s.insert(e, l, "honest", t);
        }
        // one source sends far past the log's whole byte budget, in big messages
        for i in 100..(100 + (MAX_STORE_BYTES / (1 << 20)) * 3) {
            let (e, l) = ev(i, t, 1 << 20);
            s.insert(e, l, "flooder", t);
        }
        assert!(s.bytes <= MAX_STORE_BYTES);
        assert!(s.src_bytes["flooder"] <= MAX_SOURCE_BYTES);
        assert_eq!(s.src_bytes["honest"], s.by_src["honest"].len() * s.iter().next().unwrap().1.len());
        assert_eq!(s.by_src["honest"].len(), 100, "the honest history stays");
        // many sources at once: the log stays within budget and the honest one still keeps its own
        for k in 0..20 {
            for i in 0..40 {
                let (e, l) = ev(10_000 + k * 100 + i, t, 1 << 20);
                s.insert(e, l, &format!("flood{k}"), t);
            }
        }
        assert!(s.bytes <= MAX_STORE_BYTES);
        assert_eq!(s.by_src["honest"].len(), 100);
    }

    #[test]
    fn racing_honest_messages_first_does_not_let_a_flooder_drop_them() {
        let t = now();
        let mut s = Store::default();
        // the attacker delivers 100 honest cases first; the honest link brings the same ones after
        for i in 0..100 {
            let (e, l) = ev(i, t, 1_000);
            s.insert(e.clone(), l.clone(), "racer", t);
            s.insert(e, l, "honest", t);
        }
        assert_eq!(s.len(), 100);
        // then floods far past every budget
        for i in 100..(100 + (MAX_STORE_BYTES / (1 << 20)) * 3) {
            let (e, l) = ev(i, t, 1 << 20);
            s.insert(e, l, "racer", t);
        }
        assert!(s.bytes <= MAX_STORE_BYTES);
        assert!(s.src_bytes["racer"] <= MAX_SOURCE_BYTES);
        for i in 0..100 {
            assert!(s.holds(&format!("{i:064x}"), "honest"), "honest case {i} kept");
        }
        // and the count limit: tiny messages from many fresh sources still leave the honest ones
        for k in 0..60 {
            for i in 0..1_000 {
                let (e, l) = ev(1_000_000 + k * 1_000 + i, t, 1);
                s.insert(e, l, &format!("tiny{k}"), t);
            }
        }
        assert!(s.len() <= MAX_STORE);
        for i in 0..100 {
            assert!(s.holds(&format!("{i:064x}"), "honest"));
        }
        // a message held by one source alone does go when that source lets go
        let held: usize = s.src_count.values().sum();
        assert_eq!(held, s.by_src.values().map(|q| q.iter().filter(|id| s.items.contains_key(*id)).count()).sum::<usize>());
    }

    #[test]
    fn a_spent_stake_ends_its_link_and_an_unreachable_backend_ends_none() {
        use std::io::Read;
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let sh = Arc::new(Mutex::new(Shared::default()));
        let mut far = vec![];
        let k = bitcoin::secp256k1::Keypair::from_seckey_slice(&bitcoin::secp256k1::Secp256k1::new(), &[7u8; 32])
            .unwrap()
            .x_only_public_key()
            .0;
        for (id, stake) in [(1u64, "ok"), (2, "spent"), (3, "down")] {
            let near = TcpStream::connect(addr).unwrap();
            let (f, _) = l.accept().unwrap();
            f.set_read_timeout(Some(Duration::from_millis(300))).unwrap();
            far.push(f);
            let (out, _rx) = std::sync::mpsc::sync_channel(1);
            let mut g = sh.lock().unwrap();
            g.links.insert(id, Link { out, incoming: true, since: Instant::now(), useful: 0, stream: Some(near), authed: true });
            g.stakes.insert(id, (k, stake.into()));
            std::mem::forget(_rx);
        }
        let v: Verify = Arc::new(|_, s: &str| match s {
            "ok" => Ok(()),
            "down" => Err(format!("{UNAVAILABLE}: connection refused")),
            _ => Err("spent, or not an output".into()),
        });
        recheck(&sh, &v);
        let mut b = [0u8; 1];
        let closed: Vec<bool> = far.iter_mut().map(|f| matches!(f.read(&mut b), Ok(0))).collect();
        assert_eq!(closed, vec![false, true, false]);
    }

    #[test]
    fn old_messages_leave_the_log() {
        let t = now();
        let mut s = Store::default();
        let (e, l) = ev(1, t - KEEP_SECS - 10, 10);
        s.insert(e, l, "a", t - 120);
        let (e, l) = ev(2, t, 10);
        s.insert(e, l, "a", t);
        assert_eq!(s.len(), 1);
        assert_eq!(s.iter().next().unwrap().0.id, format!("{:064x}", 2));
    }
}
