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
use crate::nostr::{now, Event, Filter};
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
/// Messages kept to replay to peers that connect later (oldest dropped first).
pub const MAX_STORE: usize = 50_000;
/// Incoming links at once; when full, the least useful established one makes room.
pub const MAX_IN: usize = 64;
/// A message dated further than this in the future is refused.
pub const FUTURE_SECS: u64 = 600;
/// New messages an incoming link may bring: a burst of this many, refilled at RATE per second.
pub const BURST: f64 = 20_000.0;
pub const RATE: f64 = 100.0;
/// Lines that are not valid signed messages an incoming link may send before it is closed.
pub const MAX_JUNK: u32 = 1_000;

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
}

#[derive(Default)]
struct Shared {
    seen: Bounded,
    store: VecDeque<(Event, Arc<str>)>,
    links: HashMap<u64, Link>,
    next: u64,
    /// incoming links accepted, counted from the moment of accepting (before the link's thread has
    /// registered it), so a burst of connections cannot slip past MAX_IN
    incoming: usize,
}

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

fn admit(shared: &Arc<Mutex<Shared>>, e: &Event) -> Admit {
    let mut g = shared.lock().unwrap();
    if g.seen.contains(&e.id) {
        return Admit::Seen;
    }
    let t = now();
    // a message older than the replay window, or dated in the future, is a replay or a forgery
    // of time: refused before the signature is even checked
    if e.created_at + KEEP_SECS < t || e.created_at > t + FUTURE_SECS || !e.verify() {
        return Admit::Invalid;
    }
    g.seen.insert(e.id.clone());
    let line: Arc<str> = serde_json::to_string(e).unwrap().into();
    g.store.push_back((e.clone(), line.clone()));
    let cutoff = t.saturating_sub(KEEP_SECS);
    while g
        .store
        .front()
        .map(|x| x.0.created_at < cutoff)
        .unwrap_or(false)
        || g.store.len() > MAX_STORE
    {
        g.store.pop_front();
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

/// Makes room for a new incoming link if all slots are taken: a link up a minute or more that has
/// never brought a new message is closed. A link that has brought messages is never closed to make
/// room for a stranger, so a connection storm cannot cut honest peers off; it can only fill the
/// free slots, which costs it the slots and nothing else. False if no slot can be freed.
fn make_room(shared: &Arc<Mutex<Shared>>) -> bool {
    let mut g = shared.lock().unwrap();
    if g.incoming < MAX_IN {
        g.incoming += 1;
        return true;
    }
    let victim = g
        .links
        .values()
        .filter(|l| l.incoming && l.useful == 0 && l.since.elapsed() > Duration::from_secs(60))
        .min_by_key(|l| l.since);
    match victim.and_then(|l| l.stream.as_ref()) {
        Some(s) => {
            // the victim's slot passes to the newcomer (its own count is given back when it ends)
            let _ = s.shutdown(std::net::Shutdown::Both);
            g.incoming += 1;
            true
        }
        None => false,
    }
}

/// Queues `line` for every link but `except`; a link whose queue is full (a peer that stopped
/// reading) is closed.
fn forward(g: &Shared, line: &Arc<str>, except: Option<u64>) {
    for (lid, l) in g.links.iter() {
        if Some(*lid) != except {
            if let Err(TrySendError::Full(_)) = l.out.try_send(line.clone()) {
                if let Some(s) = &l.stream {
                    let _ = s.shutdown(std::net::Shutdown::Both);
                }
            }
        }
    }
}

fn run_link(
    shared: Arc<Mutex<Shared>>,
    local: Sender<Event>,
    s: TcpStream,
    label: String,
    incoming: bool,
) {
    let _ = s.set_nodelay(true);
    let (otx, orx) = sync_channel::<Arc<str>>(MAX_STORE + 10_000);
    let id = {
        let mut g = shared.lock().unwrap();
        g.next += 1;
        let id = g.next;
        // replay the recent log first, so a peer that connects late catches up
        for (_, l) in &g.store {
            let _ = otx.try_send(l.clone());
        }
        g.links.insert(
            id,
            Link {
                out: otx,
                incoming,
                since: Instant::now(),
                useful: 0,
                stream: s.try_clone().ok(),
            },
        );
        id
    };
    let mut w = match s.try_clone() {
        Ok(w) => w,
        Err(_) => return,
    };
    // a peer that does not read what it is sent for a minute is cut off rather than waited for
    let _ = w.set_write_timeout(Some(Duration::from_secs(60)));
    std::thread::spawn(move || {
        for line in orx {
            if w.write_all(line.as_bytes()).is_err() || w.write_all(b"\n").is_err() {
                // the reader side ends with it, so the peer redials and catches up from the replay
                let _ = w.shutdown(std::net::Shutdown::Both);
                break;
            }
        }
    });
    eprintln!("gossip: link up ({label})");
    let mut r = BufReader::new(s);
    let mut buf = Vec::new();
    // an incoming link (a peer we did not choose) is rate-limited: a burst, then RATE new messages a
    // second; links we dialled ourselves are trusted with their replay of a full log
    let (mut tokens, mut t0, mut junk) = (BURST, Instant::now(), 0u32);
    let why = loop {
        match read_line(&mut r, &mut buf) {
            Ok(Some(())) => {}
            Ok(None) => break String::new(),
            Err(e) => break format!(": {e}"),
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
        let line = match admit(&shared, &e) {
            Admit::Seen => continue,
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
    };
    {
        let mut g = shared.lock().unwrap();
        g.links.remove(&id);
        if incoming {
            g.incoming = g.incoming.saturating_sub(1);
        }
    }
    // close the socket outright: the writer thread may be blocked sending to a peer that stopped
    // reading, and would otherwise hold the socket (and itself) open for ever
    let _ = r.get_ref().shutdown(std::net::Shutdown::Both);
    eprintln!("gossip: link down ({label}){why}");
}

impl Gossip {
    /// `listen`: local address to accept peers on (published as an onion service), if any;
    /// `peers`: Cores to dial and keep dialled; `socks`: Tor's SOCKS port, for onion peers.
    pub fn start(
        listen: Option<&str>,
        peers: &[String],
        socks: Option<&str>,
    ) -> std::io::Result<Gossip> {
        let shared = Arc::new(Mutex::new(Shared::default()));
        let (tx, rx) = channel();
        if let Some(addr) = listen {
            let l = TcpListener::bind(addr)?;
            let (sh, t) = (shared.clone(), tx.clone());
            std::thread::spawn(move || {
                for s in l.incoming().flatten() {
                    if !make_room(&sh) {
                        // every slot is held by a link too new to judge: refuse this one
                        let _ = s.shutdown(std::net::Shutdown::Both);
                        continue;
                    }
                    let (sh, t) = (sh.clone(), t.clone());
                    let label = s
                        .peer_addr()
                        .map(|a| format!("incoming {a}"))
                        .unwrap_or("incoming".into());
                    std::thread::spawn(move || run_link(sh, t, s, label, true));
                }
            });
        }
        for p in peers {
            let (sh, t, p, sx) = (
                shared.clone(),
                tx.clone(),
                p.clone(),
                socks.map(String::from),
            );
            // keep the link up: redial with backoff whenever it drops
            std::thread::spawn(move || {
                let mut wait = 1u64;
                loop {
                    let t0 = Instant::now();
                    match dial(&p, sx.as_deref()) {
                        Ok(s) => run_link(sh.clone(), t.clone(), s, format!("to {p}"), false),
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
        if let Admit::New(line) = admit(&self.shared, e) {
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
