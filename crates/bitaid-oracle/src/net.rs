//! A minimal network for running pool members as separate processes on separate machines.
//!
//! Members connect to a relay (`bitaid-hub`) that rebroadcasts every line to everyone else and replays
//! its history to late joiners — a stand-in for the Nostr relays of milestone M3. Messages are JSON, one
//! per line. Shares meant for one member are encrypted to it (ECDH on secp256k1 + ChaCha20-Poly1305), so
//! the relay and the other members see only ciphertext.
use crate::attest::Share;
use crate::nonces::Commitments;
use bitcoin::secp256k1::{ecdh::SharedSecret, PublicKey, SecretKey};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::sync::mpsc::{channel, Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Msg {
    Hello {
        id: u16,
        enc: String,
    },
    Dkg1 {
        id: u16,
        pkg: String,
    },
    Dkg2 {
        from: u16,
        to: u16,
        ct: String,
    },
    NonceCommit {
        c: Commitments,
    },
    NonceShare {
        from: u16,
        to: u16,
        ct: String,
    },
    NonceStatus {
        id: u16,
        bad: Vec<u16>,
    },
    Ready {
        id: u16,
        q: String,
        public: String,
        qualified: Vec<u16>,
        members: Vec<u16>,
    },
    AttestReq {
        req: u64,
        index: usize,
        message: String,
    },
    AttestShare {
        req: u64,
        share: Share,
    },
    CosignReq {
        session: u64,
        digest: String,
    },
    Commit {
        session: u64,
        id: u16,
        c: String,
    },
    Package {
        session: u64,
        pkg: String,
    },
    SigShare {
        session: u64,
        id: u16,
        s: String,
    },
}

pub struct Conn {
    writer: TcpStream,
    rx: Receiver<Msg>,
    pending: VecDeque<Msg>,
}

impl Conn {
    pub fn connect(addr: &str) -> std::io::Result<Conn> {
        let s = TcpStream::connect(addr)?;
        s.set_nodelay(true)?;
        let r = s.try_clone()?;
        let (tx, rx) = channel();
        std::thread::spawn(move || {
            for line in BufReader::new(r).lines().map_while(Result::ok) {
                if let Ok(m) = serde_json::from_str::<Msg>(&line) {
                    if tx.send(m).is_err() {
                        break;
                    }
                }
            }
        });
        Ok(Conn {
            writer: s,
            rx,
            pending: VecDeque::new(),
        })
    }
    pub fn send(&mut self, m: &Msg) {
        let mut line = serde_json::to_string(m).unwrap();
        line.push('\n');
        let _ = self.writer.write_all(line.as_bytes());
    }
    /// Returns the next message satisfying `want`, keeping the others for later calls.
    pub fn wait<F: Fn(&Msg) -> bool>(&mut self, want: F, timeout: Duration) -> Option<Msg> {
        if let Some(pos) = self.pending.iter().position(&want) {
            return self.pending.remove(pos);
        }
        let end = Instant::now() + timeout;
        loop {
            let left = end.saturating_duration_since(Instant::now());
            match self.rx.recv_timeout(left) {
                Ok(m) if want(&m) => return Some(m),
                Ok(m) => self.pending.push_back(m),
                Err(RecvTimeoutError::Timeout) | Err(RecvTimeoutError::Disconnected) => {
                    return None
                }
            }
        }
    }
    /// Collects up to `count` messages satisfying `want` within `timeout`.
    pub fn collect<F: Fn(&Msg) -> bool>(
        &mut self,
        want: F,
        count: usize,
        timeout: Duration,
    ) -> Vec<Msg> {
        let end = Instant::now() + timeout;
        let mut out = Vec::new();
        while out.len() < count {
            let left = end.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            match self.wait(&want, left) {
                Some(m) => out.push(m),
                None => break,
            }
        }
        out
    }
}

fn key(my: &SecretKey, their: &PublicKey) -> ChaCha20Poly1305 {
    let ss = SharedSecret::new(their, my);
    let k = bitaid_core::hashes::tagged("Bitaid/oracle-share", &ss.secret_bytes());
    ChaCha20Poly1305::new((&k).into())
}

/// Encrypts `pt` for `their`, bound to `aad` (sender, recipient, kind).
pub fn seal(my: &SecretKey, their: &PublicKey, aad: &[u8], pt: &[u8]) -> String {
    let n: [u8; 12] = rand::random();
    let ct = key(my, their)
        .encrypt(Nonce::from_slice(&n), Payload { msg: pt, aad })
        .expect("encrypt");
    hex::encode([n.to_vec(), ct].concat())
}

pub fn open(my: &SecretKey, their: &PublicKey, aad: &[u8], hexct: &str) -> Option<Vec<u8>> {
    let b = hex::decode(hexct).ok()?;
    if b.len() < 12 {
        return None;
    }
    key(my, their)
        .decrypt(Nonce::from_slice(&b[..12]), Payload { msg: &b[12..], aad })
        .ok()
}
