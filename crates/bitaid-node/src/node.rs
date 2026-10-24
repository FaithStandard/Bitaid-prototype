//! What every role shares: an identity, relays, a chain connection, case keys, and a mailbox that
//! keeps messages until the step that needs them asks for them.
use crate::chain::Rpc;
use crate::nostr::{kind, Client, Event, Filter};
use crate::wire::{self, b64, unb64, Envelope, Msg};
use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey, XOnlyPublicKey};
use musig2::secp::{Point, Scalar};
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

pub struct Node {
    pub name: String,
    pub keys: Keypair,
    pub client: Client,
    pub rpc: Rpc,
    pub case_keys: HashMap<String, [u8; 32]>,
    /// verified messages not yet asked for
    backlog: VecDeque<(Envelope, Event)>,
    /// encrypted case messages whose key has not arrived yet
    locked: Vec<Event>,
    pub t0: Instant,
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

impl Node {
    pub fn new(name: &str, relays: &[String], rpc: Rpc, secret: Option<[u8; 32]>) -> Node {
        let secp = Secp256k1::new();
        let keys = match secret {
            Some(s) => Keypair::from_secret_key(&secp, &SecretKey::from_slice(&s).unwrap()),
            None => Keypair::new(&secp, &mut rand::thread_rng()),
        };
        let mut client = Client::new();
        for r in relays {
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
        Node {
            name: name.into(),
            keys,
            client,
            rpc,
            case_keys: HashMap::new(),
            backlog: VecDeque::new(),
            locked: vec![],
            t0: Instant::now(),
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
        let bytes = wire::sign(&self.keys, self.rpc.height(), msg);
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
        self.client.publish(&e);
        e.id
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

    fn decode(&mut self, e: &Event) -> Option<Envelope> {
        let raw = unb64(&e.content)?;
        let bytes = if e.tag("enc") == Some("1") {
            let case = e.tag("c")?.to_string();
            match self.case_keys.get(&case) {
                Some(k) => wire::decrypt(k, case.as_bytes(), &raw)?,
                None => {
                    self.locked.push(e.clone());
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
        Some(env)
    }

    pub fn add_case_key(&mut self, case: &str, key: [u8; 32]) {
        self.case_keys.insert(case.into(), key);
        let locked = std::mem::take(&mut self.locked);
        for e in locked {
            if let Some(env) = self.decode(&e) {
                self.backlog.push_back((env, e));
            }
        }
    }

    fn pull(&mut self, timeout: Duration) -> bool {
        match self.client.next_event(timeout) {
            Some((_, e)) => {
                if let Some(env) = self.decode(&e) {
                    self.backlog.push_back((env, e));
                }
                true
            }
            None => false,
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
