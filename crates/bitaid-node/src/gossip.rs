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
use std::sync::mpsc::{channel, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// How long a Core keeps messages to replay to peers that connect later.
pub const KEEP_SECS: u64 = 86_400;

#[derive(Default)]
struct Shared {
    seen: HashSet<String>,
    store: VecDeque<Event>,
    links: HashMap<u64, Sender<String>>,
    next: u64,
}

pub struct Gossip {
    shared: Arc<Mutex<Shared>>,
    rx: Receiver<Event>,
    tx: Sender<Event>,
    subs: Vec<(String, Vec<Filter>)>,
    delivered: HashSet<String>,
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

fn admit(shared: &Arc<Mutex<Shared>>, e: &Event) -> bool {
    let mut g = shared.lock().unwrap();
    if g.seen.contains(&e.id) || !e.verify() {
        return false;
    }
    g.seen.insert(e.id.clone());
    g.store.push_back(e.clone());
    let cutoff = now().saturating_sub(KEEP_SECS);
    while g
        .store
        .front()
        .map(|x| x.created_at < cutoff)
        .unwrap_or(false)
    {
        g.store.pop_front();
    }
    true
}

fn run_link(shared: Arc<Mutex<Shared>>, local: Sender<Event>, s: TcpStream, label: String) {
    let _ = s.set_nodelay(true);
    let (otx, orx) = channel::<String>();
    let id = {
        let mut g = shared.lock().unwrap();
        g.next += 1;
        let id = g.next;
        // replay the recent log first, so a peer that connects late catches up
        for e in &g.store {
            let _ = otx.send(serde_json::to_string(e).unwrap());
        }
        g.links.insert(id, otx);
        id
    };
    let mut w = match s.try_clone() {
        Ok(w) => w,
        Err(_) => return,
    };
    std::thread::spawn(move || {
        for line in orx {
            if w.write_all(line.as_bytes()).is_err() || w.write_all(b"\n").is_err() {
                break;
            }
        }
    });
    eprintln!("gossip: link up ({label})");
    let r = BufReader::new(s);
    for line in r.lines() {
        let Ok(line) = line else { break };
        let Ok(e) = serde_json::from_str::<Event>(&line) else {
            continue;
        };
        if admit(&shared, &e) {
            // forward to every other link, deliver locally
            let g = shared.lock().unwrap();
            for (lid, out) in g.links.iter() {
                if *lid != id {
                    let _ = out.send(line.clone());
                }
            }
            drop(g);
            let _ = local.send(e);
        }
    }
    shared.lock().unwrap().links.remove(&id);
    eprintln!("gossip: link down ({label})");
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
                    let (sh, t) = (sh.clone(), t.clone());
                    let label = s
                        .peer_addr()
                        .map(|a| format!("incoming {a}"))
                        .unwrap_or("incoming".into());
                    std::thread::spawn(move || run_link(sh, t, s, label));
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
                        Ok(s) => run_link(sh.clone(), t.clone(), s, format!("to {p}")),
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
            delivered: HashSet::new(),
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
        if admit(&self.shared, e) {
            let line = serde_json::to_string(e).unwrap();
            for out in self.shared.lock().unwrap().links.values() {
                let _ = out.send(line.clone());
            }
            let _ = self.tx.send(e.clone());
        }
    }

    /// Adds a local subscription and delivers matching messages already in the log.
    pub fn subscribe(&mut self, id: &str, filters: Vec<Filter>) {
        let stored: Vec<Event> = self.shared.lock().unwrap().store.iter().cloned().collect();
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
