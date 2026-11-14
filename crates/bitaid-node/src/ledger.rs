//! The chain as Bitaid's record: what decides money is read from blocks, never from gossip.
//!
//! Gossip carries pointers and signed objects; it is neither ordered, nor complete, nor the same on
//! two nodes, and a sender states its own height. So every fact that several nodes must agree on
//! before money moves is a transaction: a record in an OP_RETURN output, an output it creates, and
//! the block that confirmed it. Any node with the chain reads the same records in the same order,
//! whenever it started and whatever its links delivered.
//!
//! A record is `MAGIC ‖ kind ‖ fields` in an OP_RETURN output of at most 80 bytes:
//!
//! * `POST` (§10.6): a case's posting on the fee market for a tier. It names the case, the tier, the
//!   seat fee bid, the poster's key and a lock height; output 0 of the same transaction is the
//!   posting's escrow, under the bond script of the poster's key (spendable with the oracle pool's
//!   co-signature, which the pool gives only to pay the seats drawn for that case, or by the poster
//!   alone after the lock height). A posting therefore costs what it bids, locked, for as long as it
//!   counts; when its escrow is spent before the lock height the case was seated and paid.
//! * `REGISTER` (§10.2): an arbitrator's entry bond. It names the bond's keys and fallback height;
//!   the output it points at in the same transaction is the bond.
//!
//! * `ANCHOR` (§7): a timestamp. It carries 32 bytes: the id of one signed message, or the root of a
//!   checkpoint (a list of message ids, published beside it). A message whose timing decides
//!   anything (a seat offer, a vote commitment, a reviewer's answer, an appeal, a flag) counts from
//!   the first block that anchors it, never from the height its sender states. Anyone may anchor
//!   anything: an anchor proves only that the message existed by that block, which nobody has to
//!   take on trust, and a message left out of the checkpoints is anchored by its own sender.
//!
//! This module only reads: it parses blocks (as `getblock` verbosity 2 gives them), tracks which
//! recorded outputs were spent and when, and can be cut back to a height when the chain reorganises.
use bitcoin::secp256k1::XOnlyPublicKey;
use bitcoin::{OutPoint, ScriptBuf, Txid};
use serde_json::Value;
use std::collections::HashMap;
use std::str::FromStr;

pub const MAGIC: &[u8; 4] = b"BTAD";
pub const KIND_POST: u8 = 1;
pub const KIND_REGISTER: u8 = 2;
pub const KIND_ANCHOR: u8 = 3;
pub const KIND_RELEASE: u8 = 4;

/// A release's record (5 bytes), carried by the transaction that hands a posting's escrow back
/// before its lock height. Such a spend takes the oracle pool's co-signature, so the pool's word is
/// what the record carries: this escrow was let go, not paid out to a panel.
pub fn release_record() -> Vec<u8> {
    let mut v = MAGIC.to_vec();
    v.push(KIND_RELEASE);
    v
}

/// An anchor's record: 4 + 1 + 32 = 37 bytes.
pub fn anchor_record(root: &[u8; 32]) -> Vec<u8> {
    let mut v = MAGIC.to_vec();
    v.push(KIND_ANCHOR);
    v.extend_from_slice(root);
    v
}

/// The root a checkpoint of several message ids is anchored under. One id alone is its own root.
pub fn checkpoint_root(leaves: &[String]) -> Option<String> {
    match leaves {
        [] => None,
        [one] => (one.len() == 64).then(|| one.clone()),
        many => {
            let mut b = Vec::with_capacity(32 * many.len());
            for l in many {
                b.extend_from_slice(&<[u8; 32]>::try_from(hex::decode(l).ok()?).ok()?);
            }
            Some(hex::encode(bitaid_core::hashes::tagged("Bitaid/checkpoint", &b)))
        }
    }
}

/// A posting's record: 4 + 1 + 32 + 1 + 4 + 32 + 4 = 78 bytes.
pub fn post_record(case: &[u8; 32], tier: u8, fee: u32, poster: &XOnlyPublicKey, lock: u32) -> Vec<u8> {
    let mut v = MAGIC.to_vec();
    v.push(KIND_POST);
    v.extend_from_slice(case);
    v.push(tier);
    v.extend_from_slice(&fee.to_le_bytes());
    v.extend_from_slice(&poster.serialize());
    v.extend_from_slice(&lock.to_le_bytes());
    v
}

/// A registration's record: 4 + 1 + 32 + 32 + 4 + 1 = 74 bytes.
pub fn register_record(scoped: &XOnlyPublicKey, cold: &XOnlyPublicKey, fallback: u32, vout: u8) -> Vec<u8> {
    let mut v = MAGIC.to_vec();
    v.push(KIND_REGISTER);
    v.extend_from_slice(&scoped.serialize());
    v.extend_from_slice(&cold.serialize());
    v.extend_from_slice(&fallback.to_le_bytes());
    v.push(vout);
    v
}

/// Where a recorded output stands on the chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Anchor {
    pub op: OutPoint,
    pub value: u64,
    pub spk: ScriptBuf,
    /// the block that confirmed the record, and the transaction's place in it
    pub height: u32,
    pub pos: usize,
    /// the block in which the output was spent, if it has been
    pub spent: Option<u32>,
    /// spent by a release (see `release_record`), not by a payout
    pub released: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Posting {
    pub case: String,
    pub tier: u8,
    pub fee: u64,
    pub poster: XOnlyPublicKey,
    pub lock: u32,
    pub at: Anchor,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Registration {
    pub scoped: XOnlyPublicKey,
    pub cold: XOnlyPublicKey,
    pub fallback: u32,
    pub at: Anchor,
}

#[derive(Default, Clone, Debug)]
pub struct Ledger {
    pub postings: Vec<Posting>,
    pub registrations: Vec<Registration>,
    /// anchored roots (hex) and the block that confirmed each, in chain order
    pub anchors: Vec<(String, u32)>,
    /// recorded outputs still unspent: (is a posting, index)
    watch: HashMap<OutPoint, (bool, usize)>,
    /// every block read: (height, hash), oldest first
    blocks: Vec<(u32, String)>,
}

fn le32(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

/// The payload of an OP_RETURN script given as hex (a single push of at most 80 bytes).
fn op_return_payload(hex_spk: &str) -> Option<Vec<u8>> {
    let b = hex::decode(hex_spk).ok()?;
    match b.as_slice() {
        [0x6a, n, rest @ ..] if (*n as usize) <= 75 && rest.len() == *n as usize => Some(rest.to_vec()),
        [0x6a, 0x4c, n, rest @ ..] if rest.len() == *n as usize => Some(rest.to_vec()),
        _ => None,
    }
}

fn out_at(tx: &Value, txid: &Txid, vout: usize) -> Option<(OutPoint, u64, ScriptBuf)> {
    let o = tx["vout"].as_array()?.get(vout)?;
    // amounts arrive as BTC with eight decimals; round, never truncate
    let value = (o["value"].as_f64()? * 1e8).round() as u64;
    let spk = ScriptBuf::from_hex(o["scriptPubKey"]["hex"].as_str()?).ok()?;
    Some((OutPoint { txid: *txid, vout: vout as u32 }, value, spk))
}

impl Ledger {
    /// The height of the last block read, if any.
    pub fn tip(&self) -> Option<u32> {
        self.blocks.last().map(|b| b.0)
    }
    /// The hash recorded for a block read, to compare with the chain's (a reorganisation).
    pub fn hash_at(&self, height: u32) -> Option<&str> {
        self.blocks.iter().rev().find(|b| b.0 == height).map(|b| b.1.as_str())
    }
    /// The blocks read, newest first (to find where a reorganisation forked).
    pub fn blocks_back(&self) -> impl Iterator<Item = &(u32, String)> {
        self.blocks.iter().rev()
    }

    /// Reads one block's transactions, in the block's order. Blocks are read in ascending height;
    /// one at or below the tip already read is ignored.
    pub fn absorb(&mut self, height: u32, hash: &str, txs: &[Value]) {
        if self.tip().is_some_and(|t| height <= t) {
            return;
        }
        self.blocks.push((height, hash.to_string()));
        if self.blocks.len() > 4_096 {
            self.blocks.drain(..1_024);
        }
        for (pos, tx) in txs.iter().enumerate() {
            // at most one record per transaction: the first OP_RETURN that parses
            let rec = tx["vout"].as_array().into_iter().flatten().find_map(|o| {
                op_return_payload(o["scriptPubKey"]["hex"].as_str()?).filter(|p| p.starts_with(MAGIC))
            });
            let release = rec.as_ref().is_some_and(|p| p.len() == 5 && p[4] == KIND_RELEASE);
            // spends first: a recorded output spent in this block
            for i in tx["vin"].as_array().into_iter().flatten() {
                let (Some(t), Some(v)) = (i["txid"].as_str(), i["vout"].as_u64()) else { continue };
                let Ok(txid) = Txid::from_str(t) else { continue };
                if let Some((posting, ix)) = self.watch.remove(&OutPoint { txid, vout: v as u32 }) {
                    match posting {
                        true => {
                            self.postings[ix].at.spent = Some(height);
                            self.postings[ix].at.released = release;
                        }
                        false => self.registrations[ix].at.spent = Some(height),
                    }
                }
            }
            let Some(txid) = tx["txid"].as_str().and_then(|t| Txid::from_str(t).ok()) else { continue };
            let Some(p) = rec else { continue };
            match (p.get(4), p.len()) {
                (Some(&KIND_POST), 78) => {
                    let (Ok(poster), Some((op, value, spk))) =
                        (XOnlyPublicKey::from_slice(&p[42..74]), out_at(tx, &txid, 0))
                    else {
                        continue;
                    };
                    self.watch.insert(op, (true, self.postings.len()));
                    self.postings.push(Posting {
                        case: hex::encode(&p[5..37]),
                        tier: p[37],
                        fee: le32(&p[38..42]) as u64,
                        poster,
                        lock: le32(&p[74..78]),
                        at: Anchor { op, value, spk, height, pos, spent: None, released: false },
                    });
                }
                (Some(&KIND_ANCHOR), 37) => self.anchors.push((hex::encode(&p[5..37]), height)),
                (Some(&KIND_REGISTER), 74) => {
                    let (Ok(scoped), Ok(cold), Some((op, value, spk))) = (
                        XOnlyPublicKey::from_slice(&p[5..37]),
                        XOnlyPublicKey::from_slice(&p[37..69]),
                        out_at(tx, &txid, p[73] as usize),
                    ) else {
                        continue;
                    };
                    self.watch.insert(op, (false, self.registrations.len()));
                    self.registrations.push(Registration {
                        scoped,
                        cold,
                        fallback: le32(&p[69..73]),
                        at: Anchor { op, value, spk, height, pos, spent: None, released: false },
                    });
                }
                _ => {}
            }
        }
    }

    /// Forgets everything read at `height` and above (the chain reorganised there): records confirmed
    /// there are gone, and outputs spent there are unspent again.
    pub fn truncate(&mut self, height: u32) {
        self.blocks.retain(|b| b.0 < height);
        self.postings.retain(|p| p.at.height < height);
        self.registrations.retain(|r| r.at.height < height);
        self.anchors.retain(|a| a.1 < height);
        self.watch.clear();
        for (i, p) in self.postings.iter_mut().enumerate() {
            if p.at.spent.is_some_and(|s| s >= height) {
                p.at.spent = None;
                p.at.released = false;
            }
            if p.at.spent.is_none() {
                self.watch.insert(p.at.op, (true, i));
            }
        }
        for (i, r) in self.registrations.iter_mut().enumerate() {
            if r.at.spent.is_some_and(|s| s >= height) {
                r.at.spent = None;
            }
            if r.at.spent.is_none() {
                self.watch.insert(r.at.op, (false, i));
            }
        }
    }

    /// The first block that anchored `root`, if any has.
    pub fn anchored(&self, root: &str) -> Option<u32> {
        self.anchors.iter().find(|a| a.0 == root).map(|a| a.1)
    }

    /// The posting recorded in transaction `txid`, if any.
    pub fn posting(&self, txid: &str) -> Option<&Posting> {
        self.postings.iter().find(|p| p.at.op.txid.to_string() == txid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn key(b: u8) -> XOnlyPublicKey {
        bitcoin::secp256k1::Keypair::from_seckey_slice(&bitcoin::secp256k1::Secp256k1::new(), &[b; 32])
            .unwrap()
            .x_only_public_key()
            .0
    }
    fn txid(n: u8) -> String {
        hex::encode([n; 32])
    }
    fn opret(d: &[u8]) -> String {
        if d.len() <= 75 {
            format!("6a{:02x}{}", d.len(), hex::encode(d))
        } else {
            format!("6a4c{:02x}{}", d.len(), hex::encode(d))
        }
    }
    fn tx(id: u8, spends: &[(u8, u32)], outs: &[(f64, &str)], rec: Option<&[u8]>) -> Value {
        let mut vout: Vec<Value> = outs
            .iter()
            .map(|(v, spk)| json!({"value": v, "scriptPubKey": {"hex": spk}}))
            .collect();
        if let Some(r) = rec {
            vout.push(json!({"value": 0.0, "scriptPubKey": {"hex": opret(r)}}));
        }
        let vin: Vec<Value> = spends.iter().map(|(t, v)| json!({"txid": txid(*t), "vout": v})).collect();
        json!({"txid": txid(id), "vin": vin, "vout": vout})
    }

    #[test]
    fn postings_and_registrations_are_read_spent_and_cut_back() {
        let mut l = Ledger::default();
        let post = post_record(&[7; 32], 1, 20_000, &key(1), 900);
        assert_eq!(post.len(), 78);
        let reg = register_record(&key(2), &key(3), 5_000, 1);
        assert_eq!(reg.len(), 74);
        l.absorb(
            100,
            "h100",
            &[
                tx(1, &[], &[(0.0006, "5120aa")], Some(&post)),
                tx(2, &[], &[(0.5, "5120bb"), (0.1, "5120cc")], Some(&reg)),
                // not ours: another magic, and a record of the wrong length
                tx(3, &[], &[(1.0, "5120dd")], Some(b"XXXX\x01")),
                tx(4, &[], &[(1.0, "5120dd")], Some(&post[..50])),
            ],
        );
        assert_eq!(l.postings.len(), 1);
        let p = &l.postings[0];
        assert_eq!((p.case.as_str(), p.tier, p.fee, p.lock), (hex::encode([7; 32]).as_str(), 1, 20_000, 900));
        assert_eq!((p.at.value, p.at.height, p.at.pos, p.at.spent), (60_000, 100, 0, None));
        assert_eq!(l.registrations.len(), 1);
        assert_eq!((l.registrations[0].at.op.vout, l.registrations[0].at.value), (1, 10_000_000));
        // the escrow is spent in block 103; the bond in 104
        l.absorb(103, "h103", &[tx(5, &[(1, 0)], &[(0.0006, "5120ee")], None)]);
        l.absorb(104, "h104", &[tx(6, &[(2, 1)], &[(0.1, "5120ee")], None)]);
        assert_eq!(l.postings[0].at.spent, Some(103));
        assert_eq!(l.registrations[0].at.spent, Some(104));
        assert!(!l.postings[0].at.released);
        // a block already read changes nothing
        l.absorb(103, "other", &[tx(9, &[], &[(0.0006, "5120aa")], Some(&post))]);
        assert_eq!(l.postings.len(), 1);
        // the chain reorganises from 103: both are unspent again, and can be spent again
        l.truncate(103);
        assert_eq!((l.tip(), l.postings[0].at.spent, l.registrations[0].at.spent), (Some(100), None, None));
        // this time by a release: the spend carries the release record
        l.absorb(103, "h103b", &[tx(7, &[(1, 0)], &[(0.0006, "5120ee")], Some(&release_record()))]);
        assert_eq!((l.postings[0].at.spent, l.postings[0].at.released), (Some(103), true));
        assert_eq!(l.hash_at(103), Some("h103b"));
        // cut back below the records: nothing is left
        l.truncate(100);
        assert!(l.postings.is_empty() && l.registrations.is_empty() && l.tip().is_none());
    }

    #[test]
    fn anchors_count_from_the_first_block_that_holds_them() {
        let (a, b, c) = (hex::encode([1u8; 32]), hex::encode([2u8; 32]), hex::encode([3u8; 32]));
        // one id is its own root; several are anchored under one root, in the order listed
        assert_eq!(checkpoint_root(&[a.clone()]), Some(a.clone()));
        let root = checkpoint_root(&[a.clone(), b.clone()]).unwrap();
        assert_ne!(Some(root.clone()), checkpoint_root(&[b.clone(), a.clone()]));
        assert!(checkpoint_root(&[]).is_none() && checkpoint_root(&["zz".into(), a.clone()]).is_none());
        let rec = |r: &str| anchor_record(&<[u8; 32]>::try_from(hex::decode(r).unwrap()).unwrap());
        let mut l = Ledger::default();
        l.absorb(200, "h200", &[tx(1, &[], &[(1.0, "5120aa")], Some(&rec(&root)))]);
        // the same root anchored again later, and a single id anchored alone
        l.absorb(203, "h203", &[tx(2, &[], &[], Some(&rec(&root))), tx(3, &[], &[], Some(&rec(&c)))]);
        assert_eq!((l.anchored(&root), l.anchored(&c), l.anchored(&a)), (Some(200), Some(203), None));
        // a record of another length is not an anchor
        l.absorb(204, "h204", &[tx(4, &[], &[], Some(&rec(&b)[..36]))]);
        assert_eq!(l.anchored(&b), None);
        // a reorganisation takes back what it confirmed
        l.truncate(203);
        assert_eq!((l.anchored(&root), l.anchored(&c)), (Some(200), None));
    }
}
