//! Nostr (NIP-01) as the transport for Bitaid messages.
//!
//! An event is signed with the sender's identity key (BIP340), the same key that signs the Bitaid
//! message it carries, so a relay can check it and route it by its tags but learns nothing it could
//! forge. Relays are interchangeable: a node publishes to several and deduplicates by event id.
//! Bitaid traffic uses ephemeral kinds (20000–29999), which relays forward without storing; the
//! anchored event log, not any relay, is the record.
use bitcoin::secp256k1::{schnorr, Keypair, Message, Secp256k1, XOnlyPublicKey};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::net::TcpStream;
use std::sync::mpsc::{channel, Receiver, RecvTimeoutError, Sender};
use std::time::{Duration, Instant};
use tungstenite::stream::MaybeTlsStream;
use tungstenite::{Message as WsMsg, WebSocket};

/// Ephemeral event kinds used by Bitaid.
pub mod kind {
    /// Alerts, routed by an H3 cell tag (`g`).
    pub const ALERT: u16 = 21_000;
    /// Every other message of a case, tagged with the case id (`c`) and, if addressed, recipients (`p`).
    pub const CASE: u16 = 21_001;
    /// Service announcements (oracle key, archivist URL): a regular kind, so relays keep them for
    /// nodes that start later.
    pub const ANNOUNCE: u16 = 7_002;
    /// Blossom upload authorisation (BUD-02); never published, sent in an HTTP header.
    pub const BLOSSOM_AUTH: u16 = 24_242;
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Event {
    pub id: String,
    pub pubkey: String,
    pub created_at: u64,
    pub kind: u16,
    pub tags: Vec<Vec<String>>,
    pub content: String,
    pub sig: String,
}

pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn id_of(
    pubkey: &str,
    created_at: u64,
    kind: u16,
    tags: &[Vec<String>],
    content: &str,
) -> [u8; 32] {
    let ser = json!([0, pubkey, created_at, kind, tags, content]).to_string();
    Sha256::digest(ser.as_bytes()).into()
}

impl Event {
    pub fn new(keys: &Keypair, kind: u16, tags: Vec<Vec<String>>, content: String) -> Event {
        Self::new_at(keys, kind, tags, content, now())
    }

    pub fn new_at(
        keys: &Keypair,
        kind: u16,
        tags: Vec<Vec<String>>,
        content: String,
        t: u64,
    ) -> Event {
        let secp = Secp256k1::new();
        let pubkey = hex::encode(keys.x_only_public_key().0.serialize());
        let id = id_of(&pubkey, t, kind, &tags, &content);
        let sig = secp.sign_schnorr(&Message::from_digest(id), keys);
        Event {
            id: hex::encode(id),
            pubkey,
            created_at: t,
            kind,
            tags,
            content,
            sig: hex::encode(sig.as_ref()),
        }
    }

    /// The id commits to every field and the signature to the id.
    pub fn verify(&self) -> bool {
        let id = id_of(
            &self.pubkey,
            self.created_at,
            self.kind,
            &self.tags,
            &self.content,
        );
        if hex::encode(id) != self.id {
            return false;
        }
        let (Ok(pk), Ok(sig)) = (hex::decode(&self.pubkey), hex::decode(&self.sig)) else {
            return false;
        };
        let (Ok(pk), Ok(sig)) = (
            XOnlyPublicKey::from_slice(&pk),
            schnorr::Signature::from_slice(&sig),
        ) else {
            return false;
        };
        Secp256k1::verification_only()
            .verify_schnorr(&sig, &Message::from_digest(id), &pk)
            .is_ok()
    }

    pub fn tag(&self, name: &str) -> Option<&str> {
        self.tags
            .iter()
            .find(|t| t.len() >= 2 && t[0] == name)
            .map(|t| t[1].as_str())
    }

    pub fn tag_values<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        self.tags
            .iter()
            .filter(move |t| t.len() >= 2 && t[0] == name)
            .map(|t| t[1].as_str())
    }

    pub fn is_ephemeral(&self) -> bool {
        (20_000..30_000).contains(&self.kind)
    }
}

/// A NIP-01 subscription filter.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Filter {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ids: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authors: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kinds: Option<Vec<u16>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub since: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub until: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
    /// Tag filters, `#g`, `#c`, `#p` … flattened into the JSON object.
    #[serde(flatten)]
    pub tags: std::collections::BTreeMap<String, Vec<String>>,
}

impl Filter {
    pub fn kinds(k: &[u16]) -> Filter {
        Filter {
            kinds: Some(k.to_vec()),
            ..Default::default()
        }
    }
    pub fn tag(mut self, name: char, values: &[String]) -> Filter {
        self.tags.insert(format!("#{name}"), values.to_vec());
        self
    }
    pub fn matches(&self, e: &Event) -> bool {
        let pre = |list: &Option<Vec<String>>, v: &str| {
            list.as_ref()
                .map(|l| l.iter().any(|x| v.starts_with(x.as_str())))
                .unwrap_or(true)
        };
        pre(&self.ids, &e.id)
            && pre(&self.authors, &e.pubkey)
            && self
                .kinds
                .as_ref()
                .map(|k| k.contains(&e.kind))
                .unwrap_or(true)
            && self.since.map(|s| e.created_at >= s).unwrap_or(true)
            && self.until.map(|u| e.created_at <= u).unwrap_or(true)
            && self.tags.iter().all(|(k, vals)| {
                let name = k.trim_start_matches('#');
                e.tag_values(name).any(|v| vals.iter().any(|x| x == v))
            })
    }
}

/// What a relay sends a client.
#[derive(Clone, Debug)]
pub enum RelayMsg {
    Event(String, Event),
    Ok(String, bool, String),
    Eose(String),
    Notice(String),
    Closed(String, String),
}

pub fn parse_relay_msg(s: &str) -> Option<RelayMsg> {
    let v: Value = serde_json::from_str(s).ok()?;
    let a = v.as_array()?;
    let st = |i: usize| a.get(i).and_then(|x| x.as_str()).unwrap_or("").to_string();
    match a.first()?.as_str()? {
        "EVENT" => Some(RelayMsg::Event(
            st(1),
            serde_json::from_value(a.get(2)?.clone()).ok()?,
        )),
        "OK" => Some(RelayMsg::Ok(st(1), a.get(2)?.as_bool()?, st(3))),
        "EOSE" => Some(RelayMsg::Eose(st(1))),
        "NOTICE" => Some(RelayMsg::Notice(st(1))),
        "CLOSED" => Some(RelayMsg::Closed(st(1), st(2))),
        _ => None,
    }
}

fn set_timeout(ws: &mut WebSocket<MaybeTlsStream<TcpStream>>, d: Duration) {
    match ws.get_mut() {
        MaybeTlsStream::Plain(s) => {
            let _ = s.set_read_timeout(Some(d));
        }
        MaybeTlsStream::Rustls(s) => {
            let _ = s.get_mut().set_read_timeout(Some(d));
        }
        _ => {}
    }
}

fn would_block(e: &tungstenite::Error) -> bool {
    matches!(e, tungstenite::Error::Io(io) if io.kind() == std::io::ErrorKind::WouldBlock || io.kind() == std::io::ErrorKind::TimedOut)
}

/// A connection to one relay, driven by its own thread.
pub struct Relay {
    pub url: String,
    out: Sender<String>,
}

/// A client over several relays: publishes to all, receives from all, deduplicates by event id.
pub struct Client {
    relays: Vec<Relay>,
    rx: Receiver<(usize, RelayMsg)>,
    tx: Sender<(usize, RelayMsg)>,
    seen: std::collections::HashSet<String>,
    subs: Vec<(String, Vec<Filter>)>,
    pending: std::collections::VecDeque<(usize, RelayMsg)>,
}

impl Client {
    pub fn new() -> Client {
        let (tx, rx) = channel();
        Client {
            relays: vec![],
            rx,
            tx,
            seen: Default::default(),
            subs: vec![],
            pending: Default::default(),
        }
    }

    /// Connects to a relay (`ws://` or `wss://`). Existing subscriptions are sent to it.
    pub fn add_relay(&mut self, url: &str) -> Result<(), String> {
        let (mut ws, _) = tungstenite::connect(url).map_err(|e| format!("{url}: {e}"))?;
        set_timeout(&mut ws, Duration::from_millis(30));
        let (otx, orx) = channel::<String>();
        let idx = self.relays.len();
        let tx = self.tx.clone();
        let u = url.to_string();
        std::thread::spawn(move || loop {
            while let Ok(s) = orx.try_recv() {
                if ws.send(WsMsg::Text(s)).is_err() {
                    let _ = tx.send((idx, RelayMsg::Notice(format!("{u}: send failed"))));
                    return;
                }
            }
            match ws.read() {
                Ok(WsMsg::Text(t)) => {
                    if let Some(m) = parse_relay_msg(&t) {
                        if tx.send((idx, m)).is_err() {
                            return;
                        }
                    }
                }
                Ok(WsMsg::Ping(p)) => {
                    let _ = ws.send(WsMsg::Pong(p));
                }
                Ok(WsMsg::Close(_)) => return,
                Ok(_) => {}
                Err(e) if would_block(&e) => {}
                Err(_) => {
                    let _ = tx.send((idx, RelayMsg::Notice(format!("{u}: disconnected"))));
                    return;
                }
            }
        });
        for (id, f) in &self.subs {
            let _ = otx.send(req_json(id, f));
        }
        self.relays.push(Relay {
            url: url.into(),
            out: otx,
        });
        Ok(())
    }

    pub fn relay_count(&self) -> usize {
        self.relays.len()
    }

    pub fn publish(&self, e: &Event) {
        let s = json!(["EVENT", e]).to_string();
        for r in &self.relays {
            let _ = r.out.send(s.clone());
        }
    }

    pub fn subscribe(&mut self, id: &str, filters: Vec<Filter>) {
        let s = req_json(id, &filters);
        for r in &self.relays {
            let _ = r.out.send(s.clone());
        }
        self.subs.retain(|(i, _)| i != id);
        self.subs.push((id.into(), filters));
    }

    pub fn unsubscribe(&mut self, id: &str) {
        let s = json!(["CLOSE", id]).to_string();
        for r in &self.relays {
            let _ = r.out.send(s.clone());
        }
        self.subs.retain(|(i, _)| i != id);
    }

    /// The next new, valid event on any subscription, or None after `timeout`.
    pub fn next_event(&mut self, timeout: Duration) -> Option<(String, Event)> {
        let end = Instant::now() + timeout;
        loop {
            let left = end.saturating_duration_since(Instant::now());
            let m = match self.pending.pop_front() {
                Some(m) => Ok(m),
                None => self.rx.recv_timeout(left),
            };
            match m {
                Ok((_, RelayMsg::Event(sub, e))) => {
                    if self.seen.insert(e.id.clone()) && e.verify() {
                        return Some((sub, e));
                    }
                }
                Ok(_) => {}
                Err(RecvTimeoutError::Timeout) => return None,
                Err(RecvTimeoutError::Disconnected) => return None,
            }
        }
    }

    /// Waits for every relay's OK for event `id`; returns how many accepted it.
    pub fn wait_ok(&mut self, id: &str, timeout: Duration) -> usize {
        let end = Instant::now() + timeout;
        let mut got = std::collections::HashSet::new();
        let mut ok = 0;
        while got.len() < self.relays.len() {
            let left = end.saturating_duration_since(Instant::now());
            match self.rx.recv_timeout(left) {
                Ok((i, RelayMsg::Ok(eid, acc, _))) if eid == id => {
                    if got.insert(i) && acc {
                        ok += 1;
                    }
                }
                Ok(m @ (_, RelayMsg::Event(..))) => self.pending.push_back(m),
                Ok(_) => {}
                Err(_) => break,
            }
        }
        ok
    }
}

impl Default for Client {
    fn default() -> Self {
        Self::new()
    }
}

fn req_json(id: &str, filters: &[Filter]) -> String {
    let mut a = vec![json!("REQ"), json!(id)];
    for f in filters {
        a.push(serde_json::to_value(f).unwrap());
    }
    Value::Array(a).to_string()
}
