//! Phone-side light client of its own Core (Specification §7.2, `design/phone_light.md`).
//!
//! Implements Albert's split:
//! - **Credible first, verified after:** alerts, accepting, opening location, moving can read
//!   signed `LightAnswer` data as `Trust::Credible` as soon as it arrives while proofs check.
//! - **Verified before signing:** `sign_set` and `Msg::Forfeits` call `sign_gate`, which requires
//!   every needed transaction and output to be `Trust::Verified` (PoW header chain + Merkle path,
//!   still on the active chain after any reorg), the verified tip to match at least 2 independent
//!   `TipSource`s (anti-omission check, with a single Core refresh on fresh block / brief fork),
//!   and at least 2 independent `TipSource`s to agree that every required output is unspent.
//!   Any proof failure permanently distrusts the Core and blocks signing.

use crate::chain::Rpc;
use crate::gossip::LocalLink;
use crate::wire::{
    self, light_ask_hash, LightRecord, LightTxProof, Msg, LIGHT_MAX_LOCATOR,
};
use bitaid_core::light::HeaderChain;
use bitcoin::block::Header;
use bitcoin::consensus::Decodable;
use bitcoin::merkle_tree::PartialMerkleTree;
use bitcoin::secp256k1::Keypair;
use bitcoin::{BlockHash, Network, OutPoint, ScriptBuf, Transaction, TxOut, Txid};
use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Minimum number of independent tip/unspent sources required to pass the sign gate.
pub const MIN_TIP_SOURCES: usize = 2;
/// How long a tip-only reading stays fresh before being re-queried (if still at >= verified tip).
pub const TIP_FRESH_SECS: u64 = 60;
/// Timeout for a single refresh `LightAsk` to the Core when a tip source is ahead or forked.
pub const REFRESH_TIMEOUT_SECS: u64 = 30;

/// Trust level of a chain fact held by a `ChainSource`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Trust {
    /// Signed by the Core, not yet proven against the verified `HeaderChain`.
    /// Acceptable for fast UX (alerts, accepting, location, moving); NEVER for signing.
    Credible,
    /// Proven against the verified `HeaderChain` (PoW + MTP + retarget + Merkle path).
    /// Required before signing money-deciding transactions (`sign_set`, `Msg::Forfeits`).
    Verified,
}

/// A value tagged with whether it is `Credible` or `Verified`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Trusted<T> {
    pub value: T,
    pub trust: Trust,
}

impl<T> Trusted<T> {
    pub fn credible(value: T) -> Self {
        Self {
            value,
            trust: Trust::Credible,
        }
    }
    pub fn verified(value: T) -> Self {
        Self {
            value,
            trust: Trust::Verified,
        }
    }
    pub fn is_verified(&self) -> bool {
        self.trust == Trust::Verified
    }
}

/// One on-chain Bitaid record (OP_RETURN payload + its confirming transaction and height).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProvenRecord {
    pub txid: Txid,
    pub height: u32,
    pub block_hash: BlockHash,
    pub payload: Vec<u8>,
}

/// Read-only chain interface shared by `Rpc` (full node) and `CoreLight` (phone light client).
/// Wallet operations (funding bonds, payout addresses, fee-bumping packages) stay on `Rpc`.
pub trait ChainSource: Send + Sync {
    fn height(&self) -> u32;
    fn block_hash(&self, height: u32) -> Option<String>;
    /// Unspent output at `op` (credible or verified; for fast UX reads).
    fn utxo(&self, op: &OutPoint) -> Option<Trusted<TxOut>>;
    /// Unspent output at `op`, verified against PoW + Merkle proof (value & script from proven tx).
    fn verified_utxo(&self, op: &OutPoint) -> Result<TxOut, String>;
    fn tx_height(&self, txid: &Txid) -> Option<Trusted<u32>>;
    fn confirmations(&self, txid: &Txid) -> u32;
    fn verified_confirmations(&self, txid: &Txid) -> Result<u32, String>;
    fn paid_to(&self, txid: &Txid, spk: &ScriptBuf) -> Option<Trusted<u64>>;
    fn has_op_return(&self, txid: &Txid, payload: &[u8]) -> bool;
    fn verified_has_op_return(&self, txid: &Txid, payload: &[u8]) -> Result<bool, String>;
    fn case_records(&self, case_id: &str, from_height: u32) -> Vec<Trusted<ProvenRecord>>;
    /// Verifies that the current tip is cross-checked against independent sources (no omission).
    fn tip_cross_checked(&self) -> Result<(u32, BlockHash), String>;
    /// Gate in front of `sign_set` and `Msg::Forfeits`: requires the Core not to be distrusted,
    /// tip cross-checked against >= 2 independent sources (with one Core refresh on fresh block),
    /// every required tx Merkle-proven on the active chain, and every required output proven AND
    /// confirmed unspent by >= 2 independent sources.
    fn sign_gate(&self, required_txids: &[Txid], required_ops: &[OutPoint]) -> Result<(), String>;
}

impl ChainSource for Rpc {
    fn height(&self) -> u32 {
        Rpc::height(self)
    }

    fn block_hash(&self, height: u32) -> Option<String> {
        Rpc::block_hash_at(self, height)
    }

    fn utxo(&self, op: &OutPoint) -> Option<Trusted<TxOut>> {
        Rpc::utxo(self, op).map(Trusted::verified)
    }

    fn verified_utxo(&self, op: &OutPoint) -> Result<TxOut, String> {
        self.confirmed_utxo(op)
            .map(|(o, _)| o)
            .ok_or_else(|| format!("utxo {op} spent or unconfirmed"))
    }

    fn tx_height(&self, txid: &Txid) -> Option<Trusted<u32>> {
        Rpc::tx_height(self, &txid.to_string()).map(Trusted::verified)
    }

    fn confirmations(&self, txid: &Txid) -> u32 {
        Rpc::confirmations(self, txid)
    }

    fn verified_confirmations(&self, txid: &Txid) -> Result<u32, String> {
        let c = Rpc::confirmations(self, txid);
        if c == 0 {
            Err(format!("tx {txid} unconfirmed"))
        } else {
            Ok(c)
        }
    }

    fn paid_to(&self, txid: &Txid, spk: &ScriptBuf) -> Option<Trusted<u64>> {
        let amt = Rpc::paid_to(self, &txid.to_string(), spk);
        (amt > 0).then(|| Trusted::verified(amt))
    }

    fn has_op_return(&self, txid: &Txid, payload: &[u8]) -> bool {
        Rpc::has_op_return(self, &txid.to_string(), payload)
    }

    fn verified_has_op_return(&self, txid: &Txid, payload: &[u8]) -> Result<bool, String> {
        Ok(Rpc::has_op_return(self, &txid.to_string(), payload))
    }

    fn case_records(&self, case_id: &str, from_height: u32) -> Vec<Trusted<ProvenRecord>> {
        let mut out = Vec::new();
        let txs = crate::light_server::LightBackend::case_record_txs(self, case_id, from_height);
        for (txid_s, h, _pos) in txs {
            let Some((raw, bh_s, _)) = self.raw_tx_and_block(&txid_s) else {
                continue;
            };
            let Ok(tx) = Transaction::consensus_decode(&mut raw.as_slice()) else {
                continue;
            };
            let (Ok(txid), Ok(block_hash), Some(payload)) = (
                Txid::from_str(&txid_s),
                BlockHash::from_str(&bh_s),
                crate::ledger::record_of(&tx),
            ) else {
                continue;
            };
            out.push(Trusted::verified(ProvenRecord {
                txid,
                height: h,
                block_hash,
                payload,
            }));
        }
        out
    }

    fn tip_cross_checked(&self) -> Result<(u32, BlockHash), String> {
        let h = self.height();
        let bh = self
            .block_hash_at(h)
            .ok_or_else(|| format!("cannot read tip hash at {h}"))?;
        let hash = BlockHash::from_str(&bh).map_err(|e| e.to_string())?;
        Ok((h, hash))
    }

    fn sign_gate(&self, required_txids: &[Txid], required_ops: &[OutPoint]) -> Result<(), String> {
        for txid in required_txids {
            if self.confirmations(txid) == 0 {
                return Err(format!("tx {txid} not confirmed"));
            }
        }
        for op in required_ops {
            if self.confirmed_utxo(op).is_none() {
                return Err(format!("output {op} spent or unconfirmed"));
            }
        }
        Ok(())
    }
}

/// Result of querying an independent worker (`TipSource`) for tip + output unspent status.
#[derive(Clone, Debug)]
pub struct TipCheck {
    pub height: u32,
    pub hash: BlockHash,
    /// For each requested outpoint, whether this independent source reports it unspent.
    pub unspent: HashMap<OutPoint, bool>,
}

/// Independent source of the current chain tip and output unspent status (§7.2 anti-omission
/// and anti-spent-output-lie cross-checking).
pub trait TipSource: Send + Sync {
    /// Verified x-only public key (hex) of this independent source; checked to differ from the
    /// Core's pinned key and from every other `TipSource`.
    fn pubkey(&self) -> &str;
    fn check(&self, outpoints: &[OutPoint]) -> Result<TipCheck, String>;
}

/// Queries a specific bonded worker link (`LocalLink` + `link_id`) with `LightAsk { outpoints }`
/// and verifies that the signed answer comes from the pinned `signer_pubkey`.
pub struct LinkTipSource {
    signer_pubkey: String,
    link: LocalLink,
    link_id: u64,
    keys: Keypair,
    timeout: Duration,
}

impl LinkTipSource {
    pub fn new(
        signer_pubkey: String,
        link: LocalLink,
        link_id: u64,
        keys: Keypair,
        timeout: Duration,
    ) -> Self {
        Self {
            signer_pubkey: signer_pubkey.to_ascii_lowercase(),
            link,
            link_id,
            keys,
            timeout,
        }
    }
}

impl TipSource for LinkTipSource {
    fn pubkey(&self) -> &str {
        &self.signer_pubkey
    }

    fn check(&self, outpoints: &[OutPoint]) -> Result<TipCheck, String> {
        let req_id = hex::encode(rand::random::<[u8; 16]>());
        let ask = Msg::LightAsk {
            id: req_id.clone(),
            locator: vec![],
            txids: vec![],
            outpoints: outpoints.iter().map(|o| o.to_string()).collect(),
            case_id: None,
            from_height: 0,
            from_index: 0,
        };
        let ask_hash = light_ask_hash(&ask);
        let raw = wire::sign(&self.keys, 0, ask);
        self.link.send_to(self.link_id, &raw)?;
        let deadline = Instant::now() + self.timeout;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(format!("tip source {} timed out", crate::pre(&self.signer_pubkey, 12)));
            }
            let Some((lid, env)) = self.link.recv_answer(left) else {
                return Err(format!("tip source {} timed out", crate::pre(&self.signer_pubkey, 12)));
            };
            if lid != self.link_id {
                continue;
            }
            if env.sender.to_ascii_lowercase() != self.signer_pubkey {
                return Err(format!(
                    "tip source wrong signer: got {}, expected {}",
                    crate::pre(&env.sender, 12),
                    crate::pre(&self.signer_pubkey, 12)
                ));
            }
            if let Msg::LightAnswer {
                id,
                ask_hash: ah,
                tip_height,
                tip_hash,
                outputs,
                ..
            } = env.msg
            {
                if id != req_id || ah != ask_hash {
                    continue;
                }
                let hash = BlockHash::from_str(&tip_hash).map_err(|e| e.to_string())?;
                let mut unspent = HashMap::new();
                for o in outputs {
                    if let Ok(op) = OutPoint::from_str(&o.outpoint) {
                        unspent.insert(op, o.unspent);
                    }
                }
                return Ok(TipCheck {
                    height: tip_height,
                    hash,
                    unspent,
                });
            }
        }
    }
}

#[derive(Clone, Debug)]
struct CachedTx {
    tx: Transaction,
    height: u32,
    block_hash: BlockHash,
    trust: Trust,
}

#[derive(Clone, Debug)]
struct CachedOutput {
    txout: Option<TxOut>,
    unspent: bool,
    spent_by: Option<Txid>,
    height: u32,
    block_hash: Option<BlockHash>,
    trust: Trust,
}

struct LightState {
    headers: HeaderChain,
    credible_tip: (u32, String),
    txs: HashMap<Txid, CachedTx>,
    outputs: HashMap<OutPoint, CachedOutput>,
    records: HashMap<String, Vec<Trusted<ProvenRecord>>>,
    /// `KIND_ANCHOR` roots -> `(earliest_height, block_hash, trust)`, fed from `LightRecord`s.
    anchors: HashMap<String, (u32, BlockHash, Trust)>,
    /// Inclusive `(height, tx_pos)` cursor up to which anchor records have been synced.
    anchors_cursor: (u32, u32),
    last_records_through: (u32, u32),
    logged_legacy_core: bool,
    last_anchor_sync: Option<Instant>,
    /// Set to true if any proof from the Core fails: stops trusting the Core and blocks signing.
    distrusted: bool,
    distrust_reason: Option<String>,
    tip_checks: HashMap<String, (u32, BlockHash, Instant)>,
}

/// Phone-side light client backed by a `LocalLink` to its Core (with pinned `core_pubkey`),
/// a verified `HeaderChain`, a credible/verified cache, and independent `TipSource`s for the
/// anti-omission & unspent-quorum sign gate.
pub struct CoreLight {
    core_pubkey: String,
    core_link_id: Mutex<Option<u64>>,
    link: LocalLink,
    keys: Keypair,
    state: Mutex<LightState>,
    tip_sources: Mutex<Vec<Box<dyn TipSource>>>,
    /// Serializes outbound `LightAsk` round-trips so two threads never race overlapping locators.
    syncing: Mutex<()>,
    asks: AtomicU64,
}

impl CoreLight {
    /// Creates a `CoreLight` anchored at `(anchor_height, anchor_header)` with a pinned
    /// `core_pubkey` (required: answers from any other key are rejected).
    /// On retargeting networks, `anchor_height` must sit on a 2,016-block boundary.
    pub fn new(
        network: Network,
        anchor_height: u32,
        anchor_header: Header,
        core_pubkey: String,
        link: LocalLink,
        keys: Keypair,
    ) -> Result<Self, String> {
        Self::new_with_ancestors(network, anchor_height, anchor_header, &[], core_pubkey, link, keys)
    }

    /// Creates a `CoreLight` anchored at `(anchor_height, anchor_header)` along with up to 10
    /// hash-linked ancestor headers immediately preceding `anchor_height` (for exact BIP113 MTP).
    pub fn new_with_ancestors(
        network: Network,
        anchor_height: u32,
        anchor_header: Header,
        ancestors: &[Header],
        core_pubkey: String,
        link: LocalLink,
        keys: Keypair,
    ) -> Result<Self, String> {
        let core_pubkey = core_pubkey.trim().to_ascii_lowercase();
        if core_pubkey.len() != 64 || hex::decode(&core_pubkey).is_err() {
            return Err("CoreLight requires a valid 32-byte hex core_pubkey".into());
        }
        let headers = HeaderChain::new_with_ancestors(network, anchor_height, anchor_header, ancestors)
            .map_err(|e| e.to_string())?;
        let (h, bh) = headers.tip();
        Ok(Self {
            core_pubkey,
            core_link_id: Mutex::new(None),
            link,
            keys,
            state: Mutex::new(LightState {
                headers,
                credible_tip: (h, bh.to_string()),
                txs: HashMap::new(),
                outputs: HashMap::new(),
                records: HashMap::new(),
                anchors: HashMap::new(),
                anchors_cursor: (anchor_height, u32::MAX),
                last_records_through: (anchor_height, u32::MAX),
                logged_legacy_core: false,
                last_anchor_sync: None,
                distrusted: false,
                distrust_reason: None,
                tip_checks: HashMap::new(),
            }),
            tip_sources: Mutex::new(Vec::new()),
            syncing: Mutex::new(()),
            asks: AtomicU64::new(0),
        })
    }

    pub fn ask_count(&self) -> u64 {
        self.asks.load(Ordering::Relaxed)
    }

    pub fn set_core_link(&self, link_id: u64) {
        *self.core_link_id.lock().unwrap() = Some(link_id);
    }

    /// Earliest block height anchoring `root_hex` (`KIND_ANCHOR` OP_RETURN), credible or verified.
    pub fn anchored(&self, root_hex: &str) -> Option<u32> {
        let st = self.state.lock().unwrap();
        st.anchors.get(root_hex).map(|(h, _, _)| *h)
    }

    /// Advances an inclusive `(height, tx_pos)` cursor to the next record position to request.
    fn next_cursor(cur: (u32, u32)) -> (u32, u32) {
        if cur.1 == u32::MAX {
            (cur.0.saturating_add(1), 0)
        } else {
            (cur.0, cur.1.saturating_add(1))
        }
    }

    /// Pulls new headers and any new `KIND_ANCHOR` records since the last synced cursor,
    /// paginating by the Core's signed `(height, tx_index)` `records_through` cursor so a block
    /// stuffed with > `LIGHT_MAX_RECORDS` records never stalls pagination and an unprovable record
    /// is retried rather than silently skipped. Throttled to at most once per `min_interval`.
    pub fn sync_anchors(&self, min_interval: Duration) -> Result<(), String> {
        self.sync_anchors_at(min_interval, Self::now_secs())
    }

    pub fn sync_anchors_at(&self, min_interval: Duration, now_secs: u32) -> Result<(), String> {
        // When throttled (message thread), skip immediately if a LightAsk is already in flight
        // so the message thread never blocks waiting on the network.
        if !min_interval.is_zero() && self.syncing.try_lock().is_err() {
            return Ok(());
        }
        let mut cursor = {
            let mut st = self.state.lock().unwrap();
            if st.distrusted {
                return Err("Core is distrusted".into());
            }
            if !min_interval.is_zero()
                && st
                    .last_anchor_sync
                    .is_some_and(|t| t.elapsed() < min_interval)
            {
                return Ok(());
            }
            st.last_anchor_sync = Some(Instant::now());
            let next = Self::next_cursor(st.anchors_cursor);
            (next.0.max(1), if next.0 == 0 { 0 } else { next.1 })
        };
        const MAX_PAGES: usize = 16;
        for _ in 0..MAX_PAGES {
            self.sync_once_cursor_at(
                vec![],
                vec![],
                None,
                cursor.0,
                cursor.1,
                Duration::from_secs(REFRESH_TIMEOUT_SECS),
                now_secs,
            )?;
            let (through, tip) = {
                let mut st = self.state.lock().unwrap();
                let through = st.last_records_through;
                let tip = st.headers.tip().0;
                if through > st.anchors_cursor {
                    st.anchors_cursor = through;
                }
                (through, tip)
            };
            if through >= (tip, u32::MAX) {
                break;
            }
            let next = Self::next_cursor(through);
            if next <= cursor {
                // Unprovable record at `cursor` or legacy Core returning `(0, 0)`: stop this round
                // and retry on the next round instead of spinning.
                break;
            }
            cursor = next;
        }
        Ok(())
    }

    /// Spawns a lightweight background thread that sends one `LightAsk` (headers + `KIND_ANCHOR`
    /// records) every `interval` instead of reading whole blocks over RPC, and logs periodic
    /// `chain stats` every 60 s so even a stalled run reports its counts.
    pub fn follow(
        light: &std::sync::Arc<CoreLight>,
        rpc: std::sync::Arc<Rpc>,
        interval: Duration,
    ) {
        let w = std::sync::Arc::downgrade(light);
        let _ = std::thread::Builder::new()
            .name("bitaid-light-follow".into())
            .spawn(move || {
                let mut last_stats = Instant::now();
                loop {
                    std::thread::sleep(interval);
                    let Some(cl) = w.upgrade() else {
                        break;
                    };
                    if !cl.is_distrusted() {
                        let _ = cl.sync_anchors(Duration::ZERO);
                    }
                    if last_stats.elapsed() >= Duration::from_secs(60) {
                        last_stats = Instant::now();
                        crate::say!(
                            "chain stats: rpc_calls={}, light_asks={}",
                            rpc.call_count(),
                            cl.ask_count()
                        );
                    }
                }
            });
    }

    pub fn core_pubkey(&self) -> &str {
        &self.core_pubkey
    }

    pub fn add_tip_source(&self, src: Box<dyn TipSource>) {
        self.tip_sources.lock().unwrap().push(src);
    }

    pub fn is_distrusted(&self) -> bool {
        self.state.lock().unwrap().distrusted
    }

    pub fn distrust_reason(&self) -> Option<String> {
        self.state.lock().unwrap().distrust_reason.clone()
    }

    pub fn verified_tip(&self) -> (u32, BlockHash) {
        self.state.lock().unwrap().headers.tip()
    }

    /// Returns cached `(unspent, spent_by, height, trust)` for an outpoint, if known.
    pub fn output_status(&self, op: &OutPoint) -> Option<(bool, Option<Txid>, u32, Trust)> {
        let st = self.state.lock().unwrap();
        let c = st.outputs.get(op)?;
        Some((c.unspent, c.spent_by, c.height, c.trust))
    }

    /// Builds a Bitcoin block locator (tip, last 10 hashes, then exponentially sparser down to the
    /// anchor), newest-first, capped at `LIGHT_MAX_LOCATOR`.
    pub fn build_locator(&self) -> Vec<String> {
        let st = self.state.lock().unwrap();
        let (tip_h, _) = st.headers.tip();
        let anchor_h = st.headers.start_height();
        let mut loc = Vec::new();
        let mut h = tip_h;
        let mut step = 1u32;
        while loc.len() < LIGHT_MAX_LOCATOR {
            if let Some(hash) = st.headers.hash_at(h) {
                let s = hash.to_string();
                if loc.last() != Some(&s) {
                    loc.push(s);
                }
            }
            if h <= anchor_h {
                break;
            }
            if loc.len() >= 10 {
                step = step.saturating_mul(2);
            }
            h = h.saturating_sub(step).max(anchor_h);
        }
        loc
    }

    fn mark_distrusted(st: &mut LightState, why: String) -> String {
        crate::say!("FAIL: your Core gave a bad proof ({why}); signing is off");
        st.distrusted = true;
        st.distrust_reason = Some(why.clone());
        why
    }

    /// Stage 1 (Credible): ingests a signed `LightAnswer` immediately into the cache as
    /// `Trust::Credible` (never downgrading already-`Verified` entries) so time-critical UI/role
    /// code can act at once before proof verification completes.
    pub fn ingest_credible(
        &self,
        expected_ask_hash: &str,
        env: &wire::Envelope,
        raw_len: usize,
    ) -> Result<(), String> {
        if env.sender.to_ascii_lowercase() != self.core_pubkey {
            return Err(format!(
                "LightAnswer signed by unexpected key {} (expected {})",
                env.sender, self.core_pubkey
            ));
        }
        env.msg.check_light_bounds(raw_len)?;
        let Msg::LightAnswer {
            ask_hash,
            tip_height,
            tip_hash,
            txs,
            outputs,
            records,
            ..
        } = &env.msg
        else {
            return Err("expected LightAnswer".into());
        };
        if ask_hash != expected_ask_hash {
            return Err(format!(
                "LightAnswer ask_hash mismatch: got {ask_hash}, expected {expected_ask_hash}"
            ));
        }

        let mut st = self.state.lock().unwrap();
        if st.distrusted {
            return Err(format!(
                "Core is distrusted ({})",
                st.distrust_reason.as_deref().unwrap_or("prior proof failure")
            ));
        }
        st.credible_tip = (*tip_height, tip_hash.clone());

        for p in txs {
            if let (Ok(tx), Ok(bh)) = (
                Transaction::consensus_decode(&mut p.raw.as_slice()),
                BlockHash::from_str(&p.block_hash),
            ) {
                let txid = tx.compute_txid();
                let keep_verified = st
                    .txs
                    .get(&txid)
                    .is_some_and(|c| c.trust == Trust::Verified && c.block_hash == bh);
                if !keep_verified {
                    st.txs.insert(
                        txid,
                        CachedTx {
                            tx,
                            height: p.height,
                            block_hash: bh,
                            trust: Trust::Credible,
                        },
                    );
                }
            }
        }

        for o in outputs {
            let Ok(op) = OutPoint::from_str(&o.outpoint) else {
                continue;
            };
            let txout = st
                .txs
                .get(&op.txid)
                .and_then(|c| c.tx.output.get(op.vout as usize).cloned());
            let spent_by = o.spent_by.as_deref().and_then(|s| Txid::from_str(s).ok());
            let bh = st.txs.get(&op.txid).map(|c| c.block_hash);
            let keep_verified = st
                .outputs
                .get(&op)
                .is_some_and(|c| c.trust == Trust::Verified && c.unspent == o.unspent);
            if !keep_verified {
                st.outputs.insert(
                    op,
                    CachedOutput {
                        txout,
                        unspent: o.unspent,
                        spent_by,
                        height: o.height,
                        block_hash: bh,
                        trust: Trust::Credible,
                    },
                );
            }
        }

        for r in records {
            let (Ok(tx), Ok(txid), Ok(bh)) = (
                Transaction::consensus_decode(&mut r.record.as_slice()),
                Txid::from_str(&r.txid),
                BlockHash::from_str(&r.block_hash),
            ) else {
                continue;
            };
            let Some(payload) = crate::ledger::record_of(&tx) else {
                continue;
            };
            if let Some(root_hex) = anchor_record_root(&payload) {
                let keep = st
                    .anchors
                    .get(&root_hex)
                    .is_some_and(|(h, _, t)| *t == Trust::Verified && *h <= r.height);
                if !keep {
                    st.anchors
                        .entry(root_hex)
                        .and_modify(|(h, cur_bh, t)| {
                            if r.height < *h {
                                *h = r.height;
                                *cur_bh = bh;
                                *t = Trust::Credible;
                            }
                        })
                        .or_insert((r.height, bh, Trust::Credible));
                }
            }
            if let Some(cid) = record_case_id(&payload) {
                let list = st.records.entry(cid).or_default();
                if !list.iter().any(|x| x.value.txid == txid) {
                    list.push(Trusted::credible(ProvenRecord {
                        txid,
                        height: r.height,
                        block_hash: bh,
                        payload,
                    }));
                }
            }
        }
        Ok(())
    }

    /// Stage 2 (Verified): cryptographically verifies headers (PoW, MTP, 2h bound, retargets,
    /// reorg work), evicts any orphaned cache entries on reorg, and verifies every tx, output, and
    /// record Merkle proof against `HeaderChain`. Any failure permanently distrusts the Core.
    pub fn verify_answer_at(
        &self,
        expected_ask_hash: &str,
        env: &wire::Envelope,
        raw_len: usize,
        now_secs: u32,
    ) -> Result<(), String> {
        if env.sender.to_ascii_lowercase() != self.core_pubkey {
            return Err(format!("LightAnswer signed by unexpected key {}", env.sender));
        }
        env.msg.check_light_bounds(raw_len)?;
        let Msg::LightAnswer {
            ask_hash,
            tip_height,
            tip_hash,
            headers_from,
            headers,
            txs,
            outputs,
            records,
            records_through,
            ..
        } = &env.msg
        else {
            return Err("expected LightAnswer".into());
        };
        if ask_hash != expected_ask_hash {
            return Err("LightAnswer ask_hash mismatch".into());
        }

        let mut st = self.state.lock().unwrap();
        if st.distrusted {
            return Err(format!(
                "Core is distrusted ({})",
                st.distrust_reason.as_deref().unwrap_or("prior proof failure")
            ));
        }

        // 1. Verify and apply headers (handles extensions, already-held overlaps, and reorgs).
        // A valid fork with <= our cumulative work is a stale answer or reorg race, NOT a lie:
        // ignore its headers and skip items on blocks we do not hold, without distrusting.
        let mut ignored_lighter_fork = false;
        if !headers.is_empty() {
            let mut decoded = Vec::with_capacity(headers.len());
            for (i, raw) in headers.iter().enumerate() {
                let h = Header::consensus_decode(&mut raw.as_slice()).map_err(|e| {
                    Self::mark_distrusted(&mut st, format!("bad header {i}: {e}"))
                })?;
                decoded.push(h);
            }
            let prev_tip_hash = st.headers.tip().1;
            match st.headers.apply_fork_at(&decoded, Some(now_secs)) {
                Ok(_) => {
                    let first_h = decoded[0].block_hash();
                    let actual_from = st.headers.height_of(&first_h);
                    if actual_from != Some(*headers_from) {
                        return Err(Self::mark_distrusted(
                            &mut st,
                            format!(
                                "headers_from mismatch: declared {headers_from}, actual {actual_from:?}"
                            ),
                        ));
                    }
                    let reorged = st.headers.height_of(&prev_tip_hash).is_none();
                    // Evict any previously cached txs/outputs/records whose block was orphaned by a reorg.
                    let LightState {
                        headers: active,
                        txs: cached_txs,
                        outputs: cached_outputs,
                        records: cached_records,
                        anchors: cached_anchors,
                        ..
                    } = &mut *st;
                    cached_txs.retain(|_, c| active.height_of(&c.block_hash).is_some());
                    cached_outputs
                        .retain(|_, c| c.block_hash.is_none_or(|bh| active.height_of(&bh).is_some()));
                    for recs in cached_records.values_mut() {
                        recs.retain(|r| active.height_of(&r.value.block_hash).is_some());
                    }
                    cached_anchors.retain(|_, (_, bh, _)| active.height_of(bh).is_some());
                    if reorged && *headers_from <= st.anchors_cursor.0 {
                        st.anchors_cursor = (headers_from.saturating_sub(1), u32::MAX);
                    }
                }
                Err(bitaid_core::light::LightError::ForkNotHeavier) => {
                    crate::say!(
                        "light-client: ignoring stale/lighter fork from Core (tip_height={tip_height}, ours={})",
                        st.headers.tip().0
                    );
                    ignored_lighter_fork = true;
                }
                Err(e) => {
                    return Err(Self::mark_distrusted(
                        &mut st,
                        format!("header chain rejected: {e}"),
                    ));
                }
            }
        }

        if ignored_lighter_fork {
            // Do not advance `last_records_through` or distrust Core on a stale lighter fork;
            // caller will simply ask again on the next round.
            return Ok(());
        }

        // If the Core's declared tip is at our verified height, its hash must match our chain.
        let (v_h, v_hash) = st.headers.tip();
        if *tip_height == v_h && *tip_hash != v_hash.to_string() {
            return Err(Self::mark_distrusted(
                &mut st,
                format!("tip hash mismatch at height {v_h}: Core claims {tip_hash}, chain has {v_hash}"),
            ));
        }

        // 2. Verify every transaction Merkle proof against the active HeaderChain.
        for p in txs {
            let (tx, proven_h, bh) = Self::verify_tx_proof(&st.headers, p)
                .map_err(|e| Self::mark_distrusted(&mut st, e))?;
            let txid = tx.compute_txid();
            st.txs.insert(
                txid,
                CachedTx {
                    tx,
                    height: proven_h,
                    block_hash: bh,
                    trust: Trust::Verified,
                },
            );
        }

        // 3. Verify every output against its Merkle-proven creating transaction.
        for o in outputs {
            let op = OutPoint::from_str(&o.outpoint)
                .map_err(|e| Self::mark_distrusted(&mut st, format!("bad outpoint {}: {e}", o.outpoint)))?;
            let creating = st
                .txs
                .get(&op.txid)
                .filter(|c| c.trust == Trust::Verified)
                .map(|c| (c.tx.output.get(op.vout as usize).cloned(), c.block_hash, c.height));
            let (txout, bh, height) = match creating {
                Some((Some(out), bh, h)) => (Some(out), Some(bh), h),
                Some((None, _, _)) => {
                    return Err(Self::mark_distrusted(
                        &mut st,
                        format!("outpoint {op} vout out of range for proven tx"),
                    ));
                }
                None if !o.unspent && o.height == 0 => (None, None, 0),
                None => {
                    return Err(Self::mark_distrusted(
                        &mut st,
                        format!("output {op} missing Merkle-proven creating transaction"),
                    ));
                }
            };
            let spent_by = o.spent_by.as_deref().and_then(|s| Txid::from_str(s).ok());
            st.outputs.insert(
                op,
                CachedOutput {
                    txout,
                    unspent: o.unspent,
                    spent_by,
                    height,
                    block_hash: bh,
                    trust: Trust::Verified,
                },
            );
        }

        // 4. Verify every case record and `KIND_ANCHOR` Merkle proof against the active HeaderChain.
        for r in records {
            let (rec, cid) = Self::verify_record_proof(&st.headers, r)
                .map_err(|e| Self::mark_distrusted(&mut st, e))?;
            if let Some(root_hex) = anchor_record_root(&rec.payload) {
                st.anchors
                    .entry(root_hex)
                    .and_modify(|(h, bh, t)| {
                        if rec.height <= *h || *t != Trust::Verified {
                            *h = rec.height;
                            *bh = rec.block_hash;
                            *t = Trust::Verified;
                        }
                    })
                    .or_insert((rec.height, rec.block_hash, Trust::Verified));
            }
            if let Some(cid) = cid {
                let list = st.records.entry(cid).or_default();
                if let Some(slot) = list.iter_mut().find(|x| x.value.txid == rec.txid) {
                    *slot = Trusted::verified(rec);
                } else {
                    list.push(Trusted::verified(rec));
                }
            }
        }
        if *records_through == (0, 0) && *tip_height > 0 && !st.logged_legacy_core {
            st.logged_legacy_core = true;
            crate::say!("Core does not page records; update it");
        }
        let tip_h = st.headers.tip().0;
        st.last_records_through = if records_through.0 > tip_h {
            (tip_h, u32::MAX)
        } else {
            *records_through
        };

        Ok(())
    }

    /// Convenience: runs Stage 1 (`ingest_credible`) followed by Stage 2 (`verify_answer_at`).
    pub fn apply_answer_at(
        &self,
        expected_ask_hash: &str,
        env: &wire::Envelope,
        raw_len: usize,
        now_secs: u32,
    ) -> Result<(), String> {
        self.ingest_credible(expected_ask_hash, env, raw_len)?;
        self.verify_answer_at(expected_ask_hash, env, raw_len, now_secs)
    }

    fn verify_tx_proof(
        chain: &HeaderChain,
        p: &LightTxProof,
    ) -> Result<(Transaction, u32, BlockHash), String> {
        let bh = BlockHash::from_str(&p.block_hash)
            .map_err(|e| format!("bad block_hash {}: {e}", p.block_hash))?;
        let h = chain
            .height_of(&bh)
            .ok_or_else(|| format!("tx proof block {bh} not in verified HeaderChain"))?;
        if h != p.height {
            return Err(format!(
                "tx proof height mismatch: declared {}, chain has {h}",
                p.height
            ));
        }
        let hdr = chain
            .header_at(h)
            .ok_or_else(|| format!("missing header at {h}"))?;
        let pmt = PartialMerkleTree::consensus_decode(&mut p.merkle_path.as_slice())
            .map_err(|e| format!("bad merkle_path: {e}"))?;
        let (tx, proven_h, _) = chain
            .verify_tx(&p.raw, &pmt, hdr)
            .map_err(|e| format!("tx Merkle verification failed: {e}"))?;
        Ok((tx, proven_h, bh))
    }

    fn verify_record_proof(
        chain: &HeaderChain,
        r: &LightRecord,
    ) -> Result<(ProvenRecord, Option<String>), String> {
        let bh = BlockHash::from_str(&r.block_hash)
            .map_err(|e| format!("bad record block_hash {}: {e}", r.block_hash))?;
        let h = chain
            .height_of(&bh)
            .ok_or_else(|| format!("record block {bh} not in verified HeaderChain"))?;
        if h != r.height {
            return Err(format!(
                "record height mismatch: declared {}, chain has {h}",
                r.height
            ));
        }
        let hdr = chain
            .header_at(h)
            .ok_or_else(|| format!("missing header at {h}"))?;
        let pmt = PartialMerkleTree::consensus_decode(&mut r.merkle_path.as_slice())
            .map_err(|e| format!("bad record merkle_path: {e}"))?;
        let (tx, proven_h, _) = chain
            .verify_tx(&r.record, &pmt, hdr)
            .map_err(|e| format!("record Merkle verification failed: {e}"))?;
        let txid = tx.compute_txid();
        if txid.to_string() != r.txid {
            return Err(format!(
                "record txid mismatch: declared {}, actual {txid}",
                r.txid
            ));
        }
        let payload = crate::ledger::record_of(&tx)
            .ok_or_else(|| format!("record tx {txid} carries no Bitaid OP_RETURN"))?;
        let cid = record_case_id(&payload);
        Ok((
            ProvenRecord {
                txid,
                height: proven_h,
                block_hash: bh,
                payload,
            },
            cid,
        ))
    }

    /// Sends one `LightAsk` to the Core over `LocalLink`, waits up to `timeout` for the matching
    /// `LightAnswer`, ingests it as `Credible`, and verifies it into `Verified`.
    pub fn sync_once_at(
        &self,
        txids: Vec<String>,
        outpoints: Vec<String>,
        case_id: Option<String>,
        from_height: u32,
        timeout: Duration,
        now_secs: u32,
    ) -> Result<(), String> {
        self.sync_once_cursor_at(txids, outpoints, case_id, from_height, 0, timeout, now_secs)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn sync_once_cursor_at(
        &self,
        txids: Vec<String>,
        outpoints: Vec<String>,
        case_id: Option<String>,
        from_height: u32,
        from_index: u32,
        timeout: Duration,
        now_secs: u32,
    ) -> Result<(), String> {
        let _sync_guard = self.syncing.lock().unwrap();
        let req_id = hex::encode(rand::random::<[u8; 16]>());
        let ask = Msg::LightAsk {
            id: req_id.clone(),
            locator: self.build_locator(),
            txids,
            outpoints,
            case_id,
            from_height,
            from_index,
        };
        let ask_hash = light_ask_hash(&ask);
        let tip_h = self.height();
        let raw = wire::sign(&self.keys, tip_h, ask);
        self.asks.fetch_add(1, Ordering::Relaxed);
        let link_id = match *self.core_link_id.lock().unwrap() {
            Some(id) => {
                self.link.send_to(id, &raw)?;
                id
            }
            None => self.link.send_outbound(&raw)?,
        };

        let deadline = Instant::now() + timeout;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err("LightAsk timed out waiting for Core answer".into());
            }
            let Some((lid, env)) = self.link.recv_answer(left) else {
                return Err("LightAsk timed out waiting for Core answer".into());
            };
            if lid != link_id {
                continue;
            }
            if let Msg::LightAnswer {
                ref id,
                ask_hash: ref ah,
                ..
            } = env.msg
            {
                if id != &req_id || ah != &ask_hash {
                    continue;
                }
                return self.apply_answer_at(&ask_hash, &env, 0, now_secs);
            }
        }
    }

    /// Queries independent `TipSource`s (distinct verified keys, none equal to `core_pubkey`) for
    /// tip agreement and — when `outpoints` is non-empty — independent unspent confirmation (§7.2).
    ///
    /// Survives a fresh block or brief two-way race: if any independent source is ahead or has a
    /// different hash at our verified tip height, refreshes from the Core ONCE and re-checks.
    /// Fails only if the Core is still behind or still disagrees after that refresh.
    pub fn check_tip_and_unspent_at(
        &self,
        outpoints: &[OutPoint],
        now_secs: u32,
    ) -> Result<(u32, BlockHash), String> {
        self.check_tip_and_unspent_inner(outpoints, true, now_secs)
    }

    fn check_tip_and_unspent_inner(
        &self,
        outpoints: &[OutPoint],
        allow_refresh: bool,
        now_secs: u32,
    ) -> Result<(u32, BlockHash), String> {
        let (v_h, v_hash) = {
            let st = self.state.lock().unwrap();
            if st.distrusted {
                return Err(format!(
                    "Core is distrusted ({})",
                    st.distrust_reason.as_deref().unwrap_or("prior proof failure")
                ));
            }
            st.headers.tip()
        };

        let sources = self.tip_sources.lock().unwrap();
        let mut seen_keys: HashSet<String> = HashSet::new();
        let mut agreed_tip: HashSet<String> = HashSet::new();
        let mut unspent_votes: HashMap<OutPoint, HashSet<String>> = HashMap::new();
        let mut errors: Vec<String> = Vec::new();
        let mut needs_refresh: Option<String> = None;
        let now = Instant::now();

        for src in sources.iter() {
            let pk = src.pubkey().trim().to_ascii_lowercase();
            if pk.is_empty() || pk == self.core_pubkey || !seen_keys.insert(pk.clone()) {
                continue;
            }
            // Tip-only calls may reuse a cached reading ONLY if it is fresh AND at >= v_h
            // (a cached reading below a newer verified tip is refetched, not treated as lagging).
            let cached_tip = if outpoints.is_empty() {
                let st = self.state.lock().unwrap();
                st.tip_checks
                    .get(&pk)
                    .filter(|(h, _, at)| {
                        *h >= v_h
                            && now.saturating_duration_since(*at)
                                < Duration::from_secs(TIP_FRESH_SECS)
                    })
                    .map(|(h, bh, _)| (*h, *bh))
            } else {
                None
            };

            let check = match cached_tip {
                Some((height, hash)) => TipCheck {
                    height,
                    hash,
                    unspent: HashMap::new(),
                },
                None => match src.check(outpoints) {
                    Ok(c) => {
                        self.state
                            .lock()
                            .unwrap()
                            .tip_checks
                            .insert(pk.clone(), (c.height, c.hash, now));
                        c
                    }
                    Err(e) => {
                        errors.push(format!("{}: {e}", crate::pre(&pk, 12)));
                        continue;
                    }
                },
            };

            if check.height > v_h {
                needs_refresh = Some(format!(
                    "independent source {} is ahead at {} ({}), Core at {v_h} ({v_hash})",
                    crate::pre(&pk, 12),
                    check.height,
                    check.hash
                ));
                break;
            }
            if check.height == v_h && check.hash != v_hash {
                needs_refresh = Some(format!(
                    "independent source {} disagrees at height {v_h}: {} vs Core {v_hash}",
                    crate::pre(&pk, 12),
                    check.hash
                ));
                break;
            }
            if check.height == v_h && check.hash == v_hash {
                agreed_tip.insert(pk.clone());
                for op in outpoints {
                    match check.unspent.get(op) {
                        Some(&true) => {
                            unspent_votes.entry(*op).or_default().insert(pk.clone());
                        }
                        Some(&false) => {
                            let msg = format!(
                                "sign gate FAILED: independent source {} reports output {op} SPENT",
                                crate::pre(&pk, 12)
                            );
                            crate::say!("FAIL: {msg}");
                            return Err(msg);
                        }
                        None => {
                            errors.push(format!(
                                "{}: omitted status for {op}",
                                crate::pre(&pk, 12)
                            ));
                        }
                    }
                }
            } else {
                let st = self.state.lock().unwrap();
                if st.headers.hash_at(check.height).is_some_and(|h| h != check.hash) {
                    let msg = format!(
                        "tip cross-check FAILED: independent source {} forks at {}: {}",
                        crate::pre(&pk, 12),
                        check.height,
                        check.hash
                    );
                    crate::say!("FAIL: {msg}");
                    return Err(msg);
                }
                errors.push(format!(
                    "{}: lagging at {} < {v_h}",
                    crate::pre(&pk, 12),
                    check.height
                ));
            }
        }
        drop(sources);

        if let Some(reason) = needs_refresh {
            if allow_refresh {
                let op_strs: Vec<String> = outpoints.iter().map(|o| o.to_string()).collect();
                if let Err(e) = self.sync_once_at(
                    vec![],
                    op_strs,
                    None,
                    0,
                    Duration::from_secs(REFRESH_TIMEOUT_SECS),
                    now_secs,
                ) {
                    let msg = format!("tip cross-check FAILED ({reason}); Core refresh failed: {e}");
                    crate::say!("FAIL: {msg}");
                    return Err(msg);
                }
                return self.check_tip_and_unspent_inner(outpoints, false, now_secs);
            }
            let msg = format!("tip cross-check FAILED after refresh: {reason}");
            crate::say!("FAIL: {msg}");
            return Err(msg);
        }

        if agreed_tip.len() < MIN_TIP_SOURCES {
            let msg = format!(
                "tip cross-check incomplete: {}/{} independent sources agree on ({v_h}, {v_hash}) [{}]",
                agreed_tip.len(),
                MIN_TIP_SOURCES,
                errors.join("; ")
            );
            crate::say!("FAIL: {msg}");
            return Err(msg);
        }

        for op in outpoints {
            let votes = unspent_votes.get(op).map(|s| s.len()).unwrap_or(0);
            if votes < MIN_TIP_SOURCES {
                let msg = format!(
                    "sign gate FAILED: only {votes}/{MIN_TIP_SOURCES} independent sources confirm {op} unspent"
                );
                crate::say!("FAIL: {msg}");
                return Err(msg);
            }
        }

        Ok((v_h, v_hash))
    }

    fn now_secs() -> u32 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as u32
    }
}

/// Extracts the 32-byte anchor root hex from a `KIND_ANCHOR` OP_RETURN payload.
fn anchor_record_root(payload: &[u8]) -> Option<String> {
    if payload.len() == 37
        && &payload[..4] == crate::ledger::MAGIC
        && payload[4] == crate::ledger::KIND_ANCHOR
    {
        Some(hex::encode(&payload[5..37]))
    } else {
        None
    }
}

/// Extracts the 32-byte case id hex from a Bitaid OP_RETURN record payload (INCIDENT, POST, TIER).
fn record_case_id(payload: &[u8]) -> Option<String> {
    if payload.len() < 37 || &payload[..4] != crate::ledger::MAGIC {
        return None;
    }
    match payload[4] {
        crate::ledger::KIND_INCIDENT | crate::ledger::KIND_POST | crate::ledger::KIND_TIER => {
            Some(hex::encode(&payload[5..37]))
        }
        _ => None,
    }
}

impl ChainSource for CoreLight {
    fn height(&self) -> u32 {
        let st = self.state.lock().unwrap();
        st.headers.tip().0.max(st.credible_tip.0)
    }

    fn block_hash(&self, height: u32) -> Option<String> {
        let st = self.state.lock().unwrap();
        if let Some(h) = st.headers.hash_at(height) {
            return Some(h.to_string());
        }
        if st.credible_tip.0 == height {
            return Some(st.credible_tip.1.clone());
        }
        None
    }

    fn utxo(&self, op: &OutPoint) -> Option<Trusted<TxOut>> {
        let st = self.state.lock().unwrap();
        let c = st.outputs.get(op)?;
        if !c.unspent {
            return None;
        }
        let txout = c.txout.clone()?;
        Some(Trusted {
            value: txout,
            trust: c.trust,
        })
    }

    fn verified_utxo(&self, op: &OutPoint) -> Result<TxOut, String> {
        let st = self.state.lock().unwrap();
        if st.distrusted {
            return Err("Core is distrusted".into());
        }
        let c = st
            .outputs
            .get(op)
            .ok_or_else(|| format!("output {op} not in verified cache"))?;
        if c.trust != Trust::Verified {
            return Err(format!("output {op} is only Credible, not Verified"));
        }
        if !c.unspent {
            return Err(format!("output {op} is spent"));
        }
        if let Some(bh) = c.block_hash {
            if st.headers.height_of(&bh).is_none() {
                return Err(format!("output {op} block {bh} no longer on active chain"));
            }
        }
        c.txout
            .clone()
            .ok_or_else(|| format!("output {op} missing proven creating txout"))
    }

    fn tx_height(&self, txid: &Txid) -> Option<Trusted<u32>> {
        let st = self.state.lock().unwrap();
        let c = st.txs.get(txid)?;
        Some(Trusted {
            value: c.height,
            trust: c.trust,
        })
    }

    fn confirmations(&self, txid: &Txid) -> u32 {
        let st = self.state.lock().unwrap();
        let Some(c) = st.txs.get(txid) else {
            return 0;
        };
        let tip = st.headers.tip().0.max(st.credible_tip.0);
        if tip >= c.height && c.height > 0 {
            tip - c.height + 1
        } else {
            0
        }
    }

    fn verified_confirmations(&self, txid: &Txid) -> Result<u32, String> {
        let st = self.state.lock().unwrap();
        if st.distrusted {
            return Err("Core is distrusted".into());
        }
        let c = st
            .txs
            .get(txid)
            .ok_or_else(|| format!("tx {txid} not in verified cache"))?;
        if c.trust != Trust::Verified {
            return Err(format!("tx {txid} is only Credible, not Verified"));
        }
        let h = st
            .headers
            .height_of(&c.block_hash)
            .ok_or_else(|| format!("tx {txid} block {} not on active chain", c.block_hash))?;
        let tip = st.headers.tip().0;
        Ok(tip.saturating_sub(h) + 1)
    }

    fn paid_to(&self, txid: &Txid, spk: &ScriptBuf) -> Option<Trusted<u64>> {
        let st = self.state.lock().unwrap();
        let c = st.txs.get(txid)?;
        let sum: u64 = c
            .tx
            .output
            .iter()
            .filter(|o| &o.script_pubkey == spk)
            .map(|o| o.value.to_sat())
            .sum();
        (sum > 0).then_some(Trusted {
            value: sum,
            trust: c.trust,
        })
    }

    fn has_op_return(&self, txid: &Txid, payload: &[u8]) -> bool {
        let st = self.state.lock().unwrap();
        st.txs
            .get(txid)
            .and_then(|c| crate::ledger::record_of(&c.tx))
            .is_some_and(|p| p == payload)
    }

    fn verified_has_op_return(&self, txid: &Txid, payload: &[u8]) -> Result<bool, String> {
        let st = self.state.lock().unwrap();
        if st.distrusted {
            return Err("Core is distrusted".into());
        }
        let c = st
            .txs
            .get(txid)
            .ok_or_else(|| format!("tx {txid} not in verified cache"))?;
        if c.trust != Trust::Verified {
            return Err(format!("tx {txid} is only Credible, not Verified"));
        }
        if st.headers.height_of(&c.block_hash).is_none() {
            return Err(format!("tx {txid} block {} not on active chain", c.block_hash));
        }
        Ok(crate::ledger::record_of(&c.tx).is_some_and(|p| p == payload))
    }

    fn case_records(&self, case_id: &str, from_height: u32) -> Vec<Trusted<ProvenRecord>> {
        let st = self.state.lock().unwrap();
        st.records
            .get(case_id)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter(|r| r.value.height >= from_height)
            .collect()
    }

    fn tip_cross_checked(&self) -> Result<(u32, BlockHash), String> {
        self.check_tip_and_unspent_at(&[], Self::now_secs())
    }

    fn sign_gate(&self, required_txids: &[Txid], required_ops: &[OutPoint]) -> Result<(), String> {
        // 1. Anti-omission + independent unspent quorum: >= 2 independent sources agree on tip
        //    (refreshing from Core once if a fresh block landed) AND confirm every required output
        //    is unspent.
        self.check_tip_and_unspent_at(required_ops, Self::now_secs())?;
        // 2. Every required transaction must be Merkle-proven on the active HeaderChain.
        for txid in required_txids {
            self.verified_confirmations(txid)?;
        }
        // 3. Every required output must be Merkle-proven on the active HeaderChain and unspent.
        for op in required_ops {
            self.verified_utxo(op)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gossip::Gossip;
    use crate::light_server::{answer_ask, LightBackend};
    use bitcoin::absolute::LockTime;
    use bitcoin::block::Version;
    use bitcoin::consensus::Encodable;
    use bitcoin::hashes::Hash;
    use bitcoin::secp256k1::Secp256k1;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{Amount, CompactTarget, Sequence, TxIn, TxMerkleNode, Witness};
    use std::sync::Arc;

    const REGTEST_BITS: u32 = 0x207fffff;

    fn encode_tx(tx: &Transaction) -> Vec<u8> {
        let mut raw = Vec::new();
        tx.consensus_encode(&mut raw).unwrap();
        raw
    }

    fn encode_header(h: &Header) -> Vec<u8> {
        let mut raw = Vec::new();
        h.consensus_encode(&mut raw).unwrap();
        raw
    }

    fn mine_block(prev: BlockHash, txs: &[Transaction], time: u32) -> (Header, BlockHash) {
        let txids: Vec<_> = txs.iter().map(|t| t.compute_txid()).collect();
        let root = bitcoin::merkle_tree::calculate_root(txids.iter().copied()).unwrap();
        let mut h = Header {
            version: Version::TWO,
            prev_blockhash: prev,
            merkle_root: TxMerkleNode::from_byte_array(root.to_byte_array()),
            time,
            bits: CompactTarget::from_consensus(REGTEST_BITS),
            nonce: 0,
        };
        let target = h.target();
        while h.validate_pow(target).is_err() {
            h.nonce = h.nonce.wrapping_add(1);
        }
        let bh = h.block_hash();
        (h, bh)
    }

    fn make_tx(tag: u32, outputs: Vec<TxOut>) -> Transaction {
        Transaction {
            version: TxVersion::TWO,
            lock_time: LockTime::from_consensus(tag),
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::from_bytes(vec![0x04, (tag & 0xff) as u8, 0x11, 0x22, 0x33]),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: outputs,
        }
    }

    struct MemBlock {
        height: u32,
        header: Header,
        hash: BlockHash,
        txs: Vec<Transaction>,
    }

    struct MemChain {
        blocks: Mutex<Vec<MemBlock>>,
        unspent: Mutex<HashMap<OutPoint, u32>>,
        case_records: Mutex<HashMap<String, Vec<(String, u32)>>>,
        unprovable: Mutex<HashSet<String>>,
    }

    impl MemChain {
        fn new(genesis: Header, gen_tx: Transaction) -> Self {
            let hash = genesis.block_hash();
            Self {
                blocks: Mutex::new(vec![MemBlock {
                    height: 0,
                    header: genesis,
                    hash,
                    txs: vec![gen_tx],
                }]),
                unspent: Mutex::new(HashMap::new()),
                case_records: Mutex::new(HashMap::new()),
                unprovable: Mutex::new(HashSet::new()),
            }
        }

        fn push(&self, txs: Vec<Transaction>, time: u32) -> (u32, Header, BlockHash) {
            let mut b = self.blocks.lock().unwrap();
            let prev = b.last().unwrap().hash;
            let height = b.last().unwrap().height + 1;
            let (header, hash) = mine_block(prev, &txs, time);
            b.push(MemBlock {
                height,
                header,
                hash,
                txs,
            });
            (height, header, hash)
        }

        fn reorg_from(&self, from_h: u32, blocks: Vec<(Vec<Transaction>, u32)>) {
            let mut b = self.blocks.lock().unwrap();
            b.retain(|blk| blk.height < from_h);
            for (txs, time) in blocks {
                let prev = b.last().unwrap().hash;
                let height = b.last().unwrap().height + 1;
                let (header, hash) = mine_block(prev, &txs, time);
                b.push(MemBlock {
                    height,
                    header,
                    hash,
                    txs,
                });
            }
        }
    }

    impl LightBackend for MemChain {
        fn tip(&self) -> Result<(u32, String), String> {
            let b = self.blocks.lock().unwrap();
            let last = b.last().ok_or("empty")?;
            Ok((last.height, last.hash.to_string()))
        }
        fn active_header_height(&self, bh: &str) -> Option<u32> {
            self.blocks
                .lock()
                .unwrap()
                .iter()
                .find(|x| x.hash.to_string() == bh)
                .map(|x| x.height)
        }
        fn block_hash_at(&self, h: u32) -> Option<String> {
            self.blocks
                .lock()
                .unwrap()
                .iter()
                .find(|x| x.height == h)
                .map(|x| x.hash.to_string())
        }
        fn raw_header(&self, bh: &str) -> Option<Vec<u8>> {
            self.blocks
                .lock()
                .unwrap()
                .iter()
                .find(|x| x.hash.to_string() == bh)
                .map(|x| encode_header(&x.header))
        }
        fn raw_tx_and_block(&self, txid: &str) -> Option<(Vec<u8>, String, u32)> {
            let b = self.blocks.lock().unwrap();
            for blk in b.iter() {
                for tx in &blk.txs {
                    if tx.compute_txid().to_string() == txid {
                        return Some((encode_tx(tx), blk.hash.to_string(), blk.height));
                    }
                }
            }
            None
        }
        fn merkle_proof(&self, txid: &str, bh: &str) -> Option<Vec<u8>> {
            if self.unprovable.lock().unwrap().contains(txid) {
                return None;
            }
            let b = self.blocks.lock().unwrap();
            let blk = b.iter().find(|x| x.hash.to_string() == bh)?;
            let txids: Vec<_> = blk.txs.iter().map(|t| t.compute_txid()).collect();
            let matches: Vec<bool> = txids.iter().map(|t| t.to_string() == txid).collect();
            if !matches.iter().any(|m| *m) {
                return None;
            }
            let pmt = PartialMerkleTree::from_txids(&txids, &matches);
            Some(bitcoin::consensus::encode::serialize(&pmt))
        }
        fn output_state(&self, op: &OutPoint) -> Result<Option<u32>, String> {
            Ok(self.unspent.lock().unwrap().get(op).copied())
        }
        fn case_record_txs(&self, case_id: &str, from_height: u32) -> Vec<(String, u32, u32)> {
            self.case_records
                .lock()
                .unwrap()
                .get(case_id)
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .filter(|(_, h)| *h >= from_height)
                .map(|(txid, h)| (txid, h, 0))
                .collect()
        }
        fn anchor_record_txs(&self, from_height: u32) -> Vec<(String, u32, u32)> {
            let b = self.blocks.lock().unwrap();
            let mut out = Vec::new();
            for blk in b.iter() {
                if blk.height < from_height {
                    continue;
                }
                for (pos, tx) in blk.txs.iter().enumerate() {
                    if let Some(p) = crate::ledger::record_of(tx) {
                        if anchor_record_root(&p).is_some() {
                            out.push((tx.compute_txid().to_string(), blk.height, pos as u32));
                        }
                    }
                }
            }
            out
        }
    }

    struct StaticSource {
        pubkey: String,
        state: Mutex<(u32, BlockHash, HashMap<OutPoint, bool>)>,
    }

    impl TipSource for StaticSource {
        fn pubkey(&self) -> &str {
            &self.pubkey
        }
        fn check(&self, outpoints: &[OutPoint]) -> Result<TipCheck, String> {
            let g = self.state.lock().unwrap();
            let mut unspent = HashMap::new();
            for op in outpoints {
                if let Some(&u) = g.2.get(op) {
                    unspent.insert(*op, u);
                }
            }
            Ok(TipCheck {
                height: g.0,
                hash: g.1,
                unspent,
            })
        }
    }

    #[test]
    fn credible_verified_sign_gate_unspent_quorum_fresh_block_and_reorg() {
        let secp = Secp256k1::new();
        let core_kp = Keypair::new(&secp, &mut rand::thread_rng());
        let phone_kp = Keypair::new(&secp, &mut rand::thread_rng());
        let w1_kp = Keypair::new(&secp, &mut rand::thread_rng());
        let w2_kp = Keypair::new(&secp, &mut rand::thread_rng());
        let w3_kp = Keypair::new(&secp, &mut rand::thread_rng());
        let core_pk = hex::encode(core_kp.x_only_public_key().0.serialize());
        let w1_pk = hex::encode(w1_kp.x_only_public_key().0.serialize());
        let w2_pk = hex::encode(w2_kp.x_only_public_key().0.serialize());
        let w3_pk = hex::encode(w3_kp.x_only_public_key().0.serialize());

        let base_time = 1_700_000_000u32;
        let gen_tx = make_tx(0, vec![]);
        let (genesis, _) = mine_block(BlockHash::all_zeros(), &[gen_tx.clone()], base_time);
        let chain = Arc::new(MemChain::new(genesis, gen_tx));

        let bond_spk = ScriptBuf::from_bytes(vec![0x51, 0x20, 0x77, 0x88]);
        let fund_tx = make_tx(
            1,
            vec![TxOut {
                value: Amount::from_sat(300_000),
                script_pubkey: bond_spk.clone(),
            }],
        );
        let fund_txid = fund_tx.compute_txid();
        let fund_op = OutPoint {
            txid: fund_txid,
            vout: 0,
        };
        let (_h1, _, _) = chain.push(vec![fund_tx], base_time + 60);

        let tx_to_orphan = make_tx(2, vec![]);
        let orphan_txid = tx_to_orphan.compute_txid();
        let (h2, _, h2_hash) = chain.push(vec![tx_to_orphan], base_time + 120);
        assert_eq!(h2, 2);
        chain.unspent.lock().unwrap().insert(fund_op, 2);

        // Live Core responder thread so fresh-block refresh actually round-trips over LocalLink!
        let core_g = Gossip::start(Some("127.0.0.1:0"), &[], None).unwrap();
        let addr = core_g.listen_addr().unwrap().to_string();
        let phone_g = Gossip::start(None, std::slice::from_ref(&addr), None).unwrap();
        assert_eq!(core_g.wait_links(1, Duration::from_secs(5)), 1);
        assert_eq!(phone_g.wait_links(1, Duration::from_secs(5)), 1);

        let core_link = core_g.local_link();
        let chain_srv = chain.clone();
        std::thread::spawn(move || loop {
            if let Some((lid, env)) = core_link.recv_ask(Duration::from_secs(5)) {
                if let Ok((_, signed)) = answer_ask(&*chain_srv, &core_kp, &env.msg) {
                    let _ = core_link.send_to(lid, &signed);
                }
            }
        });

        let light = CoreLight::new(
            Network::Regtest,
            0,
            genesis,
            core_pk.clone(),
            phone_g.local_link(),
            phone_kp,
        )
        .unwrap();

        // Stage 1 (Credible) vs Stage 2 (Verified).
        let ask = Msg::LightAsk {
            id: "aa".repeat(16),
            locator: light.build_locator(),
            txids: vec![orphan_txid.to_string()],
            outpoints: vec![fund_op.to_string()],
            case_id: None,
            from_height: 0,
            from_index: 0,
        };
        let ask_hash = light_ask_hash(&ask);
        let (_, signed) = answer_ask(&*chain, &core_kp, &ask).unwrap();
        let env = wire::verify(&signed).unwrap();

        light.ingest_credible(&ask_hash, &env, signed.len()).unwrap();
        assert_eq!(light.utxo(&fund_op).unwrap().trust, Trust::Credible);
        assert_eq!(light.output_status(&fund_op).unwrap().3, Trust::Credible);
        assert!(light.verified_utxo(&fund_op).is_err());
        assert!(light.sign_gate(&[fund_txid], &[fund_op]).is_err());

        light
            .verify_answer_at(&ask_hash, &env, signed.len(), base_time + 300)
            .unwrap();
        assert_eq!(light.utxo(&fund_op).unwrap().trust, Trust::Verified);
        assert_eq!(light.verified_utxo(&fund_op).unwrap().script_pubkey, bond_spk);
        assert!(light.sign_gate(&[fund_txid], &[fund_op]).is_err());

        // Add 2 independent sources agreeing on tip AND unspent status (plus Core's own key ignored).
        let mut unspent_map = HashMap::new();
        unspent_map.insert(fund_op, true);
        let s1 = Arc::new(StaticSource {
            pubkey: w1_pk,
            state: Mutex::new((h2, h2_hash, unspent_map.clone())),
        });
        let s2 = Arc::new(StaticSource {
            pubkey: w2_pk,
            state: Mutex::new((h2, h2_hash, unspent_map.clone())),
        });
        let fake_core_src = StaticSource {
            pubkey: core_pk,
            state: Mutex::new((h2, h2_hash, unspent_map.clone())),
        };
        struct ArcSrc(Arc<StaticSource>);
        impl TipSource for ArcSrc {
            fn pubkey(&self) -> &str {
                self.0.pubkey()
            }
            fn check(&self, ops: &[OutPoint]) -> Result<TipCheck, String> {
                self.0.check(ops)
            }
        }
        light.add_tip_source(Box::new(ArcSrc(s1.clone())));
        light.add_tip_source(Box::new(fake_core_src));
        assert!(
            light.sign_gate(&[fund_txid], &[fund_op]).is_err(),
            "Core's own key must not count as a 2nd independent source"
        );
        light.add_tip_source(Box::new(ArcSrc(s2.clone())));
        light
            .check_tip_and_unspent_at(&[fund_op], base_time + 300)
            .unwrap();

        // Compromised Core still says unspent, but 1 independent source says SPENT -> BLOCKED!
        s2.state.lock().unwrap().2.insert(fund_op, false);
        assert!(
            light
                .check_tip_and_unspent_at(&[fund_op], base_time + 300)
                .is_err(),
            "independent source reporting SPENT must block sign_gate"
        );
        s2.state.lock().unwrap().2.insert(fund_op, true);

        // Fresh block lands (height 3) between Core's last answer and the tip sources:
        // Tip sources are at height 3 while phone is at height 2 -> triggers 1 Core refresh -> PASSES!
        let (h3, _, h3_hash) = chain.push(vec![make_tx(3, vec![])], base_time + 180);
        assert_eq!(h3, 3);
        *s1.state.lock().unwrap() = (h3, h3_hash, unspent_map.clone());
        *s2.state.lock().unwrap() = (h3, h3_hash, unspent_map.clone());
        let (checked_h, checked_bh) = light
            .check_tip_and_unspent_at(&[fund_op], base_time + 360)
            .expect("fresh block must survive via single Core refresh");
        assert_eq!((checked_h, checked_bh), (h3, h3_hash));
        assert!(!light.is_distrusted());

        // True Core omission: a 3rd source is ahead at height 4 that Core does NOT have -> BLOCKS
        // after refresh, without permanently distrusting the Core.
        light.add_tip_source(Box::new(StaticSource {
            pubkey: w3_pk,
            state: Mutex::new((h3 + 1, BlockHash::all_zeros(), unspent_map)),
        }));
        assert!(light
            .check_tip_and_unspent_at(&[fund_op], base_time + 400)
            .is_err());
        assert!(
            !light.is_distrusted(),
            "omission / ahead source must block signing without permanently distrusting Core"
        );

        // Reorg eviction: Core reorgs from height 2, dropping `orphan_txid`.
        chain.reorg_from(
            2,
            vec![
                (vec![make_tx(10, vec![])], base_time + 130),
                (vec![make_tx(11, vec![])], base_time + 190),
                (vec![make_tx(12, vec![])], base_time + 250),
            ],
        );
        light
            .sync_once_at(
                vec![],
                vec![],
                None,
                0,
                Duration::from_secs(5),
                base_time + 420,
            )
            .unwrap();
        assert_eq!(light.verified_tip().0, 4);
        assert!(light.verified_confirmations(&orphan_txid).is_err());
        assert_eq!(light.verified_confirmations(&fund_txid).unwrap(), 4);
    }

    #[test]
    fn bad_merkle_proof_distrusts_core_permanently_and_wrong_signer_rejected() {
        let secp = Secp256k1::new();
        let core_kp = Keypair::new(&secp, &mut rand::thread_rng());
        let wrong_kp = Keypair::new(&secp, &mut rand::thread_rng());
        let phone_kp = Keypair::new(&secp, &mut rand::thread_rng());
        let core_pk = hex::encode(core_kp.x_only_public_key().0.serialize());

        let base_time = 1_700_000_000u32;
        let gen_tx = make_tx(0, vec![]);
        let (genesis, _) = mine_block(BlockHash::all_zeros(), &[gen_tx.clone()], base_time);
        let chain = Arc::new(MemChain::new(genesis, gen_tx));
        let tx1 = make_tx(1, vec![]);
        let tx1_id = tx1.compute_txid();
        let (_, _, _) = chain.push(vec![tx1], base_time + 60);

        let g = Gossip::start(None, &[], None).unwrap();
        let light = CoreLight::new(
            Network::Regtest,
            0,
            genesis,
            core_pk,
            g.local_link(),
            phone_kp,
        )
        .unwrap();

        let ask = Msg::LightAsk {
            id: "cc".repeat(16),
            locator: light.build_locator(),
            txids: vec![tx1_id.to_string()],
            outpoints: vec![],
            case_id: None,
            from_height: 0,
            from_index: 0,
        };
        let ask_hash = light_ask_hash(&ask);
        let (mut ans, _) = answer_ask(&*chain, &core_kp, &ask).unwrap();

        // Answer signed by wrong key is rejected without distrusting the real Core.
        let wrong_signed = wire::sign(&wrong_kp, 1, ans.clone());
        let wrong_env = wire::verify(&wrong_signed).unwrap();
        assert!(light
            .apply_answer_at(&ask_hash, &wrong_env, wrong_signed.len(), base_time + 120)
            .is_err());
        assert!(!light.is_distrusted());

        // Corrupt the Merkle path and sign with the real Core's key -> permanent distrust.
        if let Msg::LightAnswer { ref mut txs, .. } = ans {
            txs[0].merkle_path = vec![0xde, 0xad, 0xbe, 0xef];
        }
        let bad_signed = wire::sign(&core_kp, 1, ans);
        let bad_env = wire::verify(&bad_signed).unwrap();

        assert!(light
            .apply_answer_at(&ask_hash, &bad_env, bad_signed.len(), base_time + 120)
            .is_err());
        assert!(light.is_distrusted());
        assert!(light.sign_gate(&[tx1_id], &[]).is_err());
    }

    #[test]
    fn rpc_satisfies_chain_source_trait() {
        fn assert_chain_source<T: ChainSource>() {}
        assert_chain_source::<Rpc>();
        assert_chain_source::<CoreLight>();
    }

    #[test]
    fn anchor_records_verified_through_light_ask_and_evicted_on_reorg() {
        let secp = Secp256k1::new();
        let core_kp = Keypair::new(&secp, &mut rand::thread_rng());
        let phone_kp = Keypair::new(&secp, &mut rand::thread_rng());
        let core_pk = hex::encode(core_kp.x_only_public_key().0.serialize());

        let base_time = 1_700_000_000u32;
        let gen_tx = make_tx(0, vec![]);
        let (genesis, _) = mine_block(BlockHash::all_zeros(), &[gen_tx.clone()], base_time);
        let chain = Arc::new(MemChain::new(genesis, gen_tx));

        let root_bytes = [0x42u8; 32];
        let root_hex = hex::encode(root_bytes);
        let anc_payload = crate::ledger::anchor_record(&root_bytes);
        let mut spk = vec![0x6a, anc_payload.len() as u8];
        spk.extend_from_slice(&anc_payload);
        let anc_tx = make_tx(
            1,
            vec![TxOut {
                value: Amount::from_sat(0),
                script_pubkey: ScriptBuf::from_bytes(spk),
            }],
        );
        let (h1, _, _) = chain.push(vec![anc_tx], base_time + 60);
        assert_eq!(h1, 1);

        let core_g = Gossip::start(Some("127.0.0.1:0"), &[], None).unwrap();
        let addr = core_g.listen_addr().unwrap().to_string();
        let phone_g = Gossip::start(None, std::slice::from_ref(&addr), None).unwrap();
        assert_eq!(core_g.wait_links(1, Duration::from_secs(5)), 1);
        assert_eq!(phone_g.wait_links(1, Duration::from_secs(5)), 1);

        let core_link = core_g.local_link();
        let chain_srv = chain.clone();
        std::thread::spawn(move || loop {
            if let Some((lid, env)) = core_link.recv_ask(Duration::from_secs(5)) {
                if let Ok((_, signed)) = answer_ask(&*chain_srv, &core_kp, &env.msg) {
                    let _ = core_link.send_to(lid, &signed);
                }
            }
        });

        let light = CoreLight::new(
            Network::Regtest,
            0,
            genesis,
            core_pk,
            phone_g.local_link(),
            phone_kp,
        )
        .unwrap();

        light
            .sync_once_at(vec![], vec![], None, 1, Duration::from_secs(5), base_time + 120)
            .unwrap();
        assert_eq!(light.anchored(&root_hex), Some(1));

        // Reorg from height 1 without the anchor tx -> anchor must be evicted.
        chain.reorg_from(
            1,
            vec![
                (vec![make_tx(10, vec![])], base_time + 70),
                (vec![make_tx(11, vec![])], base_time + 130),
            ],
        );
        light
            .sync_once_at(vec![], vec![], None, 1, Duration::from_secs(5), base_time + 200)
            .unwrap();
        assert_eq!(light.verified_tip().0, 2);
        assert_eq!(light.anchored(&root_hex), None);
    }

    #[test]
    fn anchor_pagination_does_not_drop_records_past_cap() {
        let secp = Secp256k1::new();
        let core_kp = Keypair::new(&secp, &mut rand::thread_rng());
        let phone_kp = Keypair::new(&secp, &mut rand::thread_rng());
        let core_pk = hex::encode(core_kp.x_only_public_key().0.serialize());

        let base_time = 1_700_000_000u32;
        let gen_tx = make_tx(0, vec![]);
        let (genesis, _) = mine_block(BlockHash::all_zeros(), &[gen_tx.clone()], base_time);
        let chain = Arc::new(MemChain::new(genesis, gen_tx));

        // Create 70 blocks (> LIGHT_MAX_RECORDS = 64), each with 1 KIND_ANCHOR record.
        let mut expected: Vec<(String, u32)> = Vec::new();
        for i in 1..=70u32 {
            let mut root_bytes = [0u8; 32];
            root_bytes[..4].copy_from_slice(&i.to_le_bytes());
            let anc_payload = crate::ledger::anchor_record(&root_bytes);
            let mut spk = vec![0x6a, anc_payload.len() as u8];
            spk.extend_from_slice(&anc_payload);
            let tx = make_tx(
                i,
                vec![TxOut {
                    value: Amount::from_sat(0),
                    script_pubkey: ScriptBuf::from_bytes(spk),
                }],
            );
            let (h, _, _) = chain.push(vec![tx], base_time + i * 10);
            expected.push((hex::encode(root_bytes), h));
        }

        let core_g = Gossip::start(Some("127.0.0.1:0"), &[], None).unwrap();
        let addr = core_g.listen_addr().unwrap().to_string();
        let phone_g = Gossip::start(None, std::slice::from_ref(&addr), None).unwrap();
        assert_eq!(core_g.wait_links(1, Duration::from_secs(5)), 1);
        assert_eq!(phone_g.wait_links(1, Duration::from_secs(5)), 1);

        let core_link = core_g.local_link();
        let chain_srv = chain.clone();
        std::thread::spawn(move || loop {
            if let Some((lid, env)) = core_link.recv_ask(Duration::from_secs(5)) {
                if let Ok((_, signed)) = answer_ask(&*chain_srv, &core_kp, &env.msg) {
                    let _ = core_link.send_to(lid, &signed);
                }
            }
        });

        let light = CoreLight::new(
            Network::Regtest,
            0,
            genesis,
            core_pk,
            phone_g.local_link(),
            phone_kp,
        )
        .unwrap();

        light
            .sync_anchors_at(Duration::ZERO, base_time + 1000)
            .unwrap();
        assert!(
            light.ask_count() >= 2,
            "70 records (> 64 cap) must paginate across at least 2 LightAsks"
        );
        for (root_hex, h) in &expected {
            assert_eq!(
                light.anchored(root_hex),
                Some(*h),
                "anchor at height {h} must not be dropped by 64-record cap"
            );
        }
    }

    #[test]
    fn single_block_70_plus_1_paginates_by_cursor_and_stops_on_unprovable_record() {
        let secp = Secp256k1::new();
        let core_kp = Keypair::new(&secp, &mut rand::thread_rng());
        let phone_kp = Keypair::new(&secp, &mut rand::thread_rng());
        let core_pk = hex::encode(core_kp.x_only_public_key().0.serialize());

        let base_time = 1_700_000_000u32;
        let gen_tx = make_tx(0, vec![]);
        let (genesis, _) = mine_block(BlockHash::all_zeros(), &[gen_tx.clone()], base_time);
        let chain = Arc::new(MemChain::new(genesis, gen_tx));

        let mk_anchor_tx = |id: u32| -> (Transaction, String) {
            let mut root_bytes = [0u8; 32];
            root_bytes[..4].copy_from_slice(&id.to_le_bytes());
            let anc_payload = crate::ledger::anchor_record(&root_bytes);
            let mut spk = vec![0x6a, anc_payload.len() as u8];
            spk.extend_from_slice(&anc_payload);
            let tx = make_tx(
                id,
                vec![TxOut {
                    value: Amount::from_sat(0),
                    script_pubkey: ScriptBuf::from_bytes(spk),
                }],
            );
            (tx, hex::encode(root_bytes))
        };

        // Block 1 holds 70 anchor records (> LIGHT_MAX_RECORDS = 64) in ONE block; Block 2 holds 1.
        let mut blk1_txs = Vec::new();
        let mut expected: Vec<(String, u32)> = Vec::new();
        let mut blocked_txid = String::new();
        for i in 1..=70u32 {
            let (tx, root_hex) = mk_anchor_tx(i);
            if i == 67 {
                blocked_txid = tx.compute_txid().to_string();
            }
            blk1_txs.push(tx);
            expected.push((root_hex, 1));
        }
        let (h1, _, _) = chain.push(blk1_txs, base_time + 60);
        assert_eq!(h1, 1);

        let (tx71, root71) = mk_anchor_tx(71);
        let (h2, _, _) = chain.push(vec![tx71], base_time + 120);
        assert_eq!(h2, 2);
        expected.push((root71, 2));

        // Simulate a transient Core proof failure on record #67 (index 66 in block 1):
        // Core must stop BEFORE #67 (records_through = (1, 65)), never sign past it!
        chain.unprovable.lock().unwrap().insert(blocked_txid.clone());

        let core_g = Gossip::start(Some("127.0.0.1:0"), &[], None).unwrap();
        let addr = core_g.listen_addr().unwrap().to_string();
        let phone_g = Gossip::start(None, std::slice::from_ref(&addr), None).unwrap();
        assert_eq!(core_g.wait_links(1, Duration::from_secs(5)), 1);
        assert_eq!(phone_g.wait_links(1, Duration::from_secs(5)), 1);

        let core_link = core_g.local_link();
        let chain_srv = chain.clone();
        std::thread::spawn(move || loop {
            if let Some((lid, env)) = core_link.recv_ask(Duration::from_secs(5)) {
                if let Ok((_, signed)) = answer_ask(&*chain_srv, &core_kp, &env.msg) {
                    let _ = core_link.send_to(lid, &signed);
                }
            }
        });

        let light = CoreLight::new(
            Network::Regtest,
            0,
            genesis,
            core_pk,
            phone_g.local_link(),
            phone_kp,
        )
        .unwrap();

        // Round 1: gets 1..=64 (page 1), then 65..=66 (page 2) and stops before unprovable #67.
        light
            .sync_anchors_at(Duration::ZERO, base_time + 200)
            .unwrap();
        assert!(light.ask_count() >= 2);
        for (root_hex, h) in &expected[..66] {
            assert_eq!(light.anchored(root_hex), Some(*h));
        }
        assert_eq!(
            light.anchored(&expected[66].0),
            None,
            "unprovable record #67 must not be silently skipped"
        );
        assert_eq!(
            light.anchored(&expected[70].0),
            None,
            "block 2 record #71 must wait until #67 is proved"
        );

        // Clear the transient hiccup -> Round 2 resumes right at (1, 66) and delivers #67..=#71!
        chain.unprovable.lock().unwrap().remove(&blocked_txid);
        light
            .sync_anchors_at(Duration::ZERO, base_time + 260)
            .unwrap();
        for (root_hex, h) in &expected {
            assert_eq!(
                light.anchored(root_hex),
                Some(*h),
                "all 71 records (70 in block 1 + 1 in block 2) must arrive"
            );
        }
    }

    #[test]
    fn overlapping_same_locator_answers_and_lighter_fork_do_not_distrust() {
        let secp = Secp256k1::new();
        let core_kp = Keypair::new(&secp, &mut rand::thread_rng());
        let phone_kp = Keypair::new(&secp, &mut rand::thread_rng());
        let core_pk = hex::encode(core_kp.x_only_public_key().0.serialize());

        let base_time = 1_700_000_000u32;
        let gen_tx = make_tx(0, vec![]);
        let (genesis, _) = mine_block(BlockHash::all_zeros(), &[gen_tx.clone()], base_time);
        let chain = Arc::new(MemChain::new(genesis, gen_tx));
        let (h1, _, h1_hash) = chain.push(vec![make_tx(1, vec![])], base_time + 60);
        assert_eq!(h1, 1);

        let g = Gossip::start(None, &[], None).unwrap();
        let light = CoreLight::new(
            Network::Regtest,
            0,
            genesis,
            core_pk,
            g.local_link(),
            phone_kp,
        )
        .unwrap();

        // Sync to height 1 first.
        let ask1 = Msg::LightAsk {
            id: "01".repeat(16),
            locator: light.build_locator(),
            txids: vec![],
            outpoints: vec![],
            case_id: None,
            from_height: 0,
            from_index: 0,
        };
        let ah1 = light_ask_hash(&ask1);
        let (_, s1) = answer_ask(&*chain, &core_kp, &ask1).unwrap();
        light
            .apply_answer_at(&ah1, &wire::verify(&s1).unwrap(), s1.len(), base_time + 100)
            .unwrap();
        assert_eq!(light.verified_tip(), (1, h1_hash));

        // Two overlapping asks built on the SAME locator (at height 1):
        // Core answers ask_a at height 2, then block 3 lands and Core answers ask_b at height 3.
        let loc_at_1 = light.build_locator();
        let (h2, _, _) = chain.push(vec![make_tx(2, vec![])], base_time + 120);
        assert_eq!(h2, 2);
        let ask_a = Msg::LightAsk {
            id: "0a".repeat(16),
            locator: loc_at_1.clone(),
            txids: vec![],
            outpoints: vec![],
            case_id: None,
            from_height: 0,
            from_index: 0,
        };
        let ah_a = light_ask_hash(&ask_a);
        let (_, sa) = answer_ask(&*chain, &core_kp, &ask_a).unwrap();

        let (h3, _, h3_hash) = chain.push(vec![make_tx(3, vec![])], base_time + 180);
        assert_eq!(h3, 3);
        let ask_b = Msg::LightAsk {
            id: "0b".repeat(16),
            locator: loc_at_1,
            txids: vec![],
            outpoints: vec![],
            case_id: None,
            from_height: 0,
            from_index: 0,
        };
        let ah_b = light_ask_hash(&ask_b);
        let (_, sb) = answer_ask(&*chain, &core_kp, &ask_b).unwrap();

        // Deliver in REVERSE order: height-3 answer arrives first, height-2 answer arrives second.
        light
            .apply_answer_at(&ah_b, &wire::verify(&sb).unwrap(), sb.len(), base_time + 240)
            .unwrap();
        assert_eq!(light.verified_tip(), (3, h3_hash));

        // Second (older/overlapping) answer must be a clean no-op, NOT a distrust!
        light
            .apply_answer_at(&ah_a, &wire::verify(&sa).unwrap(), sa.len(), base_time + 240)
            .unwrap();
        assert!(!light.is_distrusted());
        assert_eq!(light.verified_tip(), (3, h3_hash));

        // A valid lighter fork (height 2 on a competing branch, less work than our height 3)
        // must be ignored, NOT distrusted!
        let (fork_h2, fork_h2_hash) = mine_block(h1_hash, &[make_tx(99, vec![])], base_time + 125);
        let ask_c = Msg::LightAsk {
            id: "0c".repeat(16),
            locator: vec![h1_hash.to_string()],
            txids: vec![],
            outpoints: vec![],
            case_id: None,
            from_height: 0,
            from_index: 0,
        };
        let ah_c = light_ask_hash(&ask_c);
        let lighter_ans = Msg::LightAnswer {
            id: "0c".repeat(16),
            ask_hash: ah_c.clone(),
            tip_height: 2,
            tip_hash: fork_h2_hash.to_string(),
            headers_from: 2,
            headers: vec![encode_header(&fork_h2)],
            txs: vec![],
            outputs: vec![],
            records: vec![],
            records_through: (2, u32::MAX),
            covers: vec![],
        };
        let sc = wire::sign(&core_kp, 2, lighter_ans);
        light
            .apply_answer_at(&ah_c, &wire::verify(&sc).unwrap(), sc.len(), base_time + 240)
            .unwrap();
        assert!(!light.is_distrusted());
        assert_eq!(light.verified_tip(), (3, h3_hash));
    }
}
