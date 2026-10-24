//! A minimal Nostr relay (NIP-01) for tests and private deployments: in memory, one thread per
//! connection. Ephemeral events are forwarded and never stored; others are kept and replayed to
//! matching subscriptions until EOSE. Every event's id and signature are checked before anything
//! else, so the relay forwards nothing it could have forged or altered.
use crate::nostr::{Event, Filter};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc::{channel, Sender};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tungstenite::{accept, Message};

type Subs = Vec<(String, Vec<Filter>)>;

#[derive(Default)]
struct State {
    stored: Vec<Event>,
    /// connection id -> (outgoing channel, subscriptions)
    conns: HashMap<u64, (Sender<String>, Subs)>,
    next: u64,
    /// counters for the log
    events: u64,
    rejected: u64,
}

pub struct Stats {
    pub events: u64,
    pub rejected: u64,
    pub connections: usize,
}

#[derive(Clone)]
pub struct RelayHandle(Arc<Mutex<State>>);

impl RelayHandle {
    pub fn stats(&self) -> Stats {
        let s = self.0.lock().unwrap();
        Stats {
            events: s.events,
            rejected: s.rejected,
            connections: s.conns.len(),
        }
    }
}

/// Serves on `addr` in background threads; returns at once.
pub fn spawn(addr: &str) -> std::io::Result<(RelayHandle, std::net::SocketAddr)> {
    let l = TcpListener::bind(addr)?;
    let local = l.local_addr()?;
    let st = RelayHandle(Arc::new(Mutex::new(State::default())));
    let h = st.clone();
    std::thread::spawn(move || {
        for s in l.incoming().flatten() {
            let st = st.clone();
            std::thread::spawn(move || {
                let _ = serve(st, s);
            });
        }
    });
    Ok((h, local))
}

fn serve(st: RelayHandle, s: TcpStream) -> Result<(), Box<dyn std::error::Error>> {
    s.set_read_timeout(Some(Duration::from_millis(30)))?;
    s.set_nodelay(true)?;
    let mut ws = accept(s)?;
    let (tx, rx) = channel::<String>();
    let me = {
        let mut g = st.0.lock().unwrap();
        g.next += 1;
        let id = g.next;
        g.conns.insert(id, (tx.clone(), vec![]));
        id
    };
    let res = (|| -> Result<(), Box<dyn std::error::Error>> {
        loop {
            while let Ok(m) = rx.try_recv() {
                ws.send(Message::Text(m))?;
            }
            match ws.read() {
                Ok(Message::Text(t)) => handle(&st, me, &tx, &t),
                Ok(Message::Ping(p)) => ws.send(Message::Pong(p))?,
                Ok(Message::Close(_)) => return Ok(()),
                Ok(_) => {}
                Err(tungstenite::Error::Io(e))
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut => {}
                Err(e) => return Err(e.into()),
            }
        }
    })();
    st.0.lock().unwrap().conns.remove(&me);
    res
}

fn handle(st: &RelayHandle, me: u64, tx: &Sender<String>, text: &str) {
    let Ok(Value::Array(a)) = serde_json::from_str::<Value>(text) else {
        let _ = tx.send(json!(["NOTICE", "invalid message"]).to_string());
        return;
    };
    match a.first().and_then(|v| v.as_str()) {
        Some("EVENT") => {
            let Some(e) = a
                .get(1)
                .and_then(|v| serde_json::from_value::<Event>(v.clone()).ok())
            else {
                let _ = tx.send(json!(["NOTICE", "invalid event"]).to_string());
                return;
            };
            let mut g = st.0.lock().unwrap();
            if !e.verify() {
                g.rejected += 1;
                let _ =
                    tx.send(json!(["OK", e.id, false, "invalid: bad id or signature"]).to_string());
                return;
            }
            g.events += 1;
            let _ = tx.send(json!(["OK", e.id, true, ""]).to_string());
            for (out, subs) in g.conns.values() {
                for (sid, fs) in subs {
                    if fs.iter().any(|f| f.matches(&e)) {
                        let _ = out.send(json!(["EVENT", sid, e]).to_string());
                    }
                }
            }
            if !e.is_ephemeral() {
                g.stored.push(e);
            }
        }
        Some("REQ") => {
            let sid = a.get(1).and_then(|v| v.as_str()).unwrap_or("").to_string();
            let fs: Vec<Filter> = a[2..]
                .iter()
                .filter_map(|v| serde_json::from_value(v.clone()).ok())
                .collect();
            let mut g = st.0.lock().unwrap();
            for f in &fs {
                let mut hits: Vec<&Event> = g.stored.iter().filter(|e| f.matches(e)).collect();
                if let Some(n) = f.limit {
                    let k = hits.len().saturating_sub(n);
                    hits.drain(..k);
                }
                for e in hits {
                    let _ = tx.send(json!(["EVENT", sid, e]).to_string());
                }
            }
            let _ = tx.send(json!(["EOSE", sid]).to_string());
            if let Some((_, subs)) = g.conns.get_mut(&me) {
                subs.retain(|(i, _)| *i != sid);
                subs.push((sid, fs));
            }
        }
        Some("CLOSE") => {
            let sid = a.get(1).and_then(|v| v.as_str()).unwrap_or("");
            let mut g = st.0.lock().unwrap();
            if let Some((_, subs)) = g.conns.get_mut(&me) {
                subs.retain(|(i, _)| i != sid);
            }
        }
        _ => {
            let _ = tx.send(json!(["NOTICE", "unknown message"]).to_string());
        }
    }
}
