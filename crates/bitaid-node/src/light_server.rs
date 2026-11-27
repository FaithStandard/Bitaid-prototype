//! Core-side handler for link-local `LightAsk` requests (Specification §7.2, `design/phone_light.md`).
//!
//! Answers each `LightAsk` from the Core's own `bitcoind` (`Rpc`), signs the `LightAnswer` with
//! the Core's identity key, and returns it on the same link (never flooded, never stored in the
//! gossip replay log).

use crate::chain::Rpc;
use crate::gossip::LocalLink;
use crate::wire::{
    self, light_ask_hash, LightCover, LightOutput, LightRecord, LightTxProof, Msg,
    LIGHT_MAX_ANSWER_BYTES, LIGHT_MAX_HEADERS, LIGHT_MAX_OUTPUTS, LIGHT_MAX_RECORDS, LIGHT_MAX_TXS,
};
use bitcoin::secp256k1::Keypair;
use bitcoin::OutPoint;
use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

/// Read-only chain data needed to build a `LightAnswer`. Implemented for `Rpc` (live `bitcoind`)
/// and for in-memory test chains.
pub trait LightBackend: Send + Sync {
    fn tip(&self) -> Result<(u32, String), String>;
    fn active_header_height(&self, block_hash: &str) -> Option<u32>;
    fn block_hash_at(&self, height: u32) -> Option<String>;
    fn raw_header(&self, block_hash: &str) -> Option<Vec<u8>>;
    fn raw_tx_and_block(&self, txid: &str) -> Option<(Vec<u8>, String, u32)>;
    fn merkle_proof(&self, txid: &str, block_hash: &str) -> Option<Vec<u8>>;
    /// Returns `Ok(Some(confirmations))` if `op` is unspent, `Ok(None)` if spent or missing.
    fn output_state(&self, op: &OutPoint) -> Result<Option<u32>, String>;
    /// Returns `(txid_hex, height)` for all on-chain Bitaid records of `case_id` at `height >= from_height`.
    fn case_record_txs(&self, case_id: &str, from_height: u32) -> Vec<(String, u32)>;
}

impl LightBackend for Rpc {
    fn tip(&self) -> Result<(u32, String), String> {
        let h = self.height();
        let hash = self
            .block_hash_at(h)
            .ok_or_else(|| format!("cannot read tip hash at height {h}"))?;
        Ok((h, hash))
    }

    fn active_header_height(&self, block_hash: &str) -> Option<u32> {
        Rpc::active_header_height(self, block_hash)
    }

    fn block_hash_at(&self, height: u32) -> Option<String> {
        Rpc::block_hash_at(self, height)
    }

    fn raw_header(&self, block_hash: &str) -> Option<Vec<u8>> {
        Rpc::raw_header(self, block_hash)
    }

    fn raw_tx_and_block(&self, txid: &str) -> Option<(Vec<u8>, String, u32)> {
        Rpc::raw_tx_and_block(self, txid)
    }

    fn merkle_proof(&self, txid: &str, block_hash: &str) -> Option<Vec<u8>> {
        Rpc::merkle_proof(self, txid, block_hash)
    }

    fn output_state(&self, op: &OutPoint) -> Result<Option<u32>, String> {
        self.utxo_state(op).map(|opt| opt.map(|(_, conf)| conf))
    }

    fn case_record_txs(&self, case_id: &str, from_height: u32) -> Vec<(String, u32)> {
        self.ledger(|l| {
            let mut out = Vec::new();
            for inc in &l.incidents {
                if inc.case == case_id && inc.height >= from_height {
                    out.push((inc.txid.to_string(), inc.height));
                }
            }
            for post in &l.postings {
                if post.case == case_id && post.at.height >= from_height {
                    out.push((post.at.op.txid.to_string(), post.at.height));
                }
            }
            for tier in &l.tiers {
                if tier.case == case_id && tier.height >= from_height {
                    out.push((tier.txid.to_string(), tier.height));
                }
            }
            out
        })
    }
}

/// Builds and signs a `LightAnswer` for `ask` using `backend`.
///
/// Guarantees:
/// - Headers start at `common_ancestor + 1` (resolved from `ask.locator` on the active chain),
///   capped at `LIGHT_MAX_HEADERS`, with `headers_from` set to `headers[0]`'s height.
/// - Every requested `outpoint`'s creating transaction is included in `txs` (and `covers`) so the
///   client derives output value and scriptPubKey from a Merkle-proven transaction.
/// - The signed envelope respects `LIGHT_MAX_ANSWER_BYTES` (trimming trailing headers if needed).
pub fn answer_ask<B: LightBackend>(
    backend: &B,
    keys: &Keypair,
    ask: &Msg,
) -> Result<(Msg, Vec<u8>), String> {
    let Msg::LightAsk {
        id,
        locator,
        txids,
        outpoints,
        case_id,
        from_height,
    } = ask
    else {
        return Err("expected Msg::LightAsk".into());
    };
    ask.check_light_bounds(0)?;

    let ask_hash = light_ask_hash(ask);
    let (tip_height, tip_hash) = backend.tip()?;

    // 1. Resolve common ancestor from block locator (newest-first).
    let mut headers: Vec<Vec<u8>> = Vec::new();
    let mut headers_from = tip_height;
    if !locator.is_empty() {
        let common = locator
            .iter()
            .find_map(|h| backend.active_header_height(h));
        if let Some(common_h) = common {
            let start_h = common_h.saturating_add(1);
            if start_h <= tip_height {
                let end_h = tip_height.min(start_h.saturating_add(LIGHT_MAX_HEADERS as u32 - 1));
                headers_from = start_h;
                for h in start_h..=end_h {
                    let Some(bh) = backend.block_hash_at(h) else {
                        break;
                    };
                    let Some(raw) = backend.raw_header(&bh) else {
                        break;
                    };
                    if raw.len() != 80 {
                        break;
                    }
                    headers.push(raw);
                }
                if headers.is_empty() {
                    headers_from = tip_height;
                }
            }
        }
    }

    // 2. Collect deduplicated txids: explicitly requested txids + creating txids of requested outpoints.
    let mut want_txids: Vec<String> = Vec::new();
    let mut seen_txids: HashSet<String> = HashSet::new();
    for txid in txids {
        if want_txids.len() >= LIGHT_MAX_TXS {
            break;
        }
        if seen_txids.insert(txid.clone()) {
            want_txids.push(txid.clone());
        }
    }
    let parsed_ops: Vec<(String, Option<OutPoint>)> = outpoints
        .iter()
        .take(LIGHT_MAX_OUTPUTS)
        .map(|s| (s.clone(), OutPoint::from_str(s).ok()))
        .collect();
    for (_, op) in &parsed_ops {
        if want_txids.len() >= LIGHT_MAX_TXS {
            break;
        }
        if let Some(op) = op {
            let txid = op.txid.to_string();
            if seen_txids.insert(txid.clone()) {
                want_txids.push(txid);
            }
        }
    }

    let mut txs: Vec<LightTxProof> = Vec::new();
    let mut covers: Vec<LightCover> = Vec::new();
    let mut tx_heights: HashMap<String, u32> = HashMap::new();
    for txid in &want_txids {
        let Some((raw, block_hash, height)) = backend.raw_tx_and_block(txid) else {
            continue;
        };
        let Some(merkle_path) = backend.merkle_proof(txid, &block_hash) else {
            continue;
        };
        tx_heights.insert(txid.clone(), height);
        txs.push(LightTxProof {
            raw,
            height,
            block_hash,
            merkle_path,
        });
        covers.push(LightCover::Tx(txid.clone()));
    }

    // 3. Output spend status (value & script come from the creating tx in `txs`).
    let mut outputs: Vec<LightOutput> = Vec::new();
    for (op_str, op) in &parsed_ops {
        let Some(op) = op else {
            continue;
        };
        let creating_h = tx_heights.get(&op.txid.to_string()).copied().unwrap_or(0);
        let (unspent, height) = match backend.output_state(op) {
            Ok(Some(conf)) if conf > 0 => {
                let h = if creating_h > 0 {
                    creating_h
                } else {
                    tip_height.saturating_add(1).saturating_sub(conf)
                };
                (true, h)
            }
            Ok(Some(_)) | Ok(None) => (false, creating_h),
            Err(_) => continue,
        };
        outputs.push(LightOutput {
            outpoint: op_str.clone(),
            unspent,
            spent_by: None,
            height,
        });
        covers.push(LightCover::Output(op_str.clone()));
    }

    // 4. Case on-chain records from `from_height`.
    let mut records: Vec<LightRecord> = Vec::new();
    if let Some(cid) = case_id {
        let mut recs = backend.case_record_txs(cid, *from_height);
        recs.sort_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.cmp(&b.0)));
        recs.dedup_by(|a, b| a.0 == b.0);
        for (txid, _h) in recs.into_iter().take(LIGHT_MAX_RECORDS) {
            let Some((raw, block_hash, height)) = backend.raw_tx_and_block(&txid) else {
                continue;
            };
            let Some(merkle_path) = backend.merkle_proof(&txid, &block_hash) else {
                continue;
            };
            records.push(LightRecord {
                txid: txid.clone(),
                height,
                block_hash,
                merkle_path,
                record: raw,
            });
            covers.push(LightCover::Record(txid));
        }
    }

    // 5. Sign and ensure the serialized envelope stays within `LIGHT_MAX_ANSWER_BYTES`.
    // If oversized, trim trailing headers so the client still gets a contiguous prefix and can
    // follow up with an updated locator.
    loop {
        let ans = Msg::LightAnswer {
            id: id.clone(),
            ask_hash: ask_hash.clone(),
            tip_height,
            tip_hash: tip_hash.clone(),
            headers_from: if headers.is_empty() {
                tip_height
            } else {
                headers_from
            },
            headers: headers.clone(),
            txs: txs.clone(),
            outputs: outputs.clone(),
            records: records.clone(),
            covers: covers.clone(),
        };
        let signed = wire::sign(keys, tip_height, ans.clone());
        if signed.len() <= LIGHT_MAX_ANSWER_BYTES {
            ans.check_light_bounds(signed.len())?;
            return Ok((ans, signed));
        }
        if headers.is_empty() {
            return Err(format!(
                "LightAnswer exceeds byte cap even with 0 headers ({} > {LIGHT_MAX_ANSWER_BYTES})",
                signed.len()
            ));
        }
        let next_len = headers.len() / 2;
        headers.truncate(next_len);
    }
}

/// Spawns a background thread that answers incoming link-local `LightAsk` messages from `rpc`
/// and returns each signed `LightAnswer` on the originating link.
pub fn spawn(link: LocalLink, rpc: Arc<Rpc>, keys: Keypair) {
    let _ = std::thread::Builder::new()
        .name("bitaid-light-server".into())
        .spawn(move || loop {
            let Some((link_id, env)) = link.recv_ask(Duration::from_secs(60)) else {
                continue;
            };
            match answer_ask(&*rpc, &keys, &env.msg) {
                Ok((_, signed)) => {
                    if let Err(e) = link.send_to(link_id, &signed) {
                        crate::say!("light-server: send to link {link_id} failed ({e})");
                    }
                }
                Err(e) => {
                    crate::say!("light-server: cannot answer ask on link {link_id} ({e})");
                }
            }
        });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gossip::Gossip;
    use bitaid_core::light::HeaderChain;
    use bitcoin::absolute::LockTime;
    use bitcoin::block::{Header, Version};
    use bitcoin::consensus::{Decodable, Encodable};
    use bitcoin::hashes::Hash;
    use bitcoin::merkle_tree::PartialMerkleTree;
    use bitcoin::secp256k1::Secp256k1;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{
        Amount, BlockHash, CompactTarget, Network, ScriptBuf, Sequence, Transaction, TxIn,
        TxMerkleNode, TxOut, Witness,
    };
    use std::sync::Mutex;

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
                script_sig: ScriptBuf::from_bytes(vec![0x04, (tag & 0xff) as u8, 0xaa, 0xbb, 0xcc]),
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
    }

    impl MemChain {
        fn new(genesis: Header, genesis_tx: Transaction) -> Self {
            let hash = genesis.block_hash();
            Self {
                blocks: Mutex::new(vec![MemBlock {
                    height: 0,
                    header: genesis,
                    hash,
                    txs: vec![genesis_tx],
                }]),
                unspent: Mutex::new(HashMap::new()),
                case_records: Mutex::new(HashMap::new()),
            }
        }

        fn push_block(&self, txs: Vec<Transaction>, time: u32) -> (u32, Header, BlockHash) {
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

        fn replace_from(&self, from_height: u32, new_blocks: Vec<(Vec<Transaction>, u32)>) {
            let mut b = self.blocks.lock().unwrap();
            b.retain(|blk| blk.height < from_height);
            for (txs, time) in new_blocks {
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
            let last = b.last().ok_or("empty chain")?;
            Ok((last.height, last.hash.to_string()))
        }

        fn active_header_height(&self, block_hash: &str) -> Option<u32> {
            let b = self.blocks.lock().unwrap();
            b.iter()
                .find(|blk| blk.hash.to_string() == block_hash)
                .map(|blk| blk.height)
        }

        fn block_hash_at(&self, height: u32) -> Option<String> {
            let b = self.blocks.lock().unwrap();
            b.iter()
                .find(|blk| blk.height == height)
                .map(|blk| blk.hash.to_string())
        }

        fn raw_header(&self, block_hash: &str) -> Option<Vec<u8>> {
            let b = self.blocks.lock().unwrap();
            b.iter()
                .find(|blk| blk.hash.to_string() == block_hash)
                .map(|blk| encode_header(&blk.header))
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

        fn merkle_proof(&self, txid: &str, block_hash: &str) -> Option<Vec<u8>> {
            let b = self.blocks.lock().unwrap();
            let blk = b.iter().find(|blk| blk.hash.to_string() == block_hash)?;
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

        fn case_record_txs(&self, case_id: &str, from_height: u32) -> Vec<(String, u32)> {
            self.case_records
                .lock()
                .unwrap()
                .get(case_id)
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .filter(|(_, h)| *h >= from_height)
                .collect()
        }
    }

    #[test]
    fn core_answers_light_ask_over_link_local_and_phone_verifies_including_reorg() {
        let secp = Secp256k1::new();
        let core_kp = Keypair::new(&secp, &mut rand::thread_rng());
        let phone_kp = Keypair::new(&secp, &mut rand::thread_rng());

        // Build a 4-block regtest-PoW chain with a funded output tx and a Bitaid INCIDENT record tx.
        let base_time = 1_700_000_000u32;
        let gen_tx = make_tx(
            0,
            vec![TxOut {
                value: Amount::from_sat(5_000_000_000),
                script_pubkey: ScriptBuf::new(),
            }],
        );
        let (genesis, genesis_hash) = mine_block(BlockHash::all_zeros(), &[gen_tx.clone()], base_time);
        let chain = Arc::new(MemChain::new(genesis, gen_tx));

        let bond_spk = ScriptBuf::from_bytes(vec![0x51, 0x20, 0x42, 0x42]);
        let fund_tx = make_tx(
            1,
            vec![TxOut {
                value: Amount::from_sat(250_000),
                script_pubkey: bond_spk.clone(),
            }],
        );
        let fund_txid = fund_tx.compute_txid();
        let fund_op = OutPoint {
            txid: fund_txid,
            vout: 0,
        };
        let other_tx = make_tx(
            2,
            vec![TxOut {
                value: Amount::from_sat(10_000),
                script_pubkey: ScriptBuf::new(),
            }],
        );
        let (h1, _, _) = chain.push_block(vec![fund_tx.clone(), other_tx.clone()], base_time + 60);
        assert_eq!(h1, 1);

        let case_bytes = [0xabu8; 32];
        let case_id = hex::encode(case_bytes);
        let inc_payload = crate::ledger::incident_record(&case_bytes);
        let mut op_ret = vec![0x6a, inc_payload.len() as u8];
        op_ret.extend_from_slice(&inc_payload);
        let inc_tx = make_tx(
            3,
            vec![TxOut {
                value: Amount::from_sat(0),
                script_pubkey: ScriptBuf::from_bytes(op_ret),
            }],
        );
        let inc_txid = inc_tx.compute_txid();
        let (h2, _, _) = chain.push_block(vec![inc_tx.clone()], base_time + 120);
        assert_eq!(h2, 2);

        let filler_tx = make_tx(
            4,
            vec![TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: ScriptBuf::new(),
            }],
        );
        let (h3, _, h3_hash) = chain.push_block(vec![filler_tx], base_time + 180);
        assert_eq!(h3, 3);

        chain.unspent.lock().unwrap().insert(fund_op, 3);
        chain
            .case_records
            .lock()
            .unwrap()
            .insert(case_id.clone(), vec![(inc_txid.to_string(), h2)]);

        // Start a Core and a Phone on local TCP gossip links.
        let core_gossip = Gossip::start(Some("127.0.0.1:0"), &[], None).unwrap();
        let addr = core_gossip.listen_addr().unwrap().to_string();
        let phone_gossip = Gossip::start(None, std::slice::from_ref(&addr), None).unwrap();
        assert_eq!(core_gossip.wait_links(1, Duration::from_secs(5)), 1);
        assert_eq!(phone_gossip.wait_links(1, Duration::from_secs(5)), 1);

        // Spawn Core responder over link-local channel using MemChain.
        let core_link = core_gossip.local_link();
        let backend_clone = chain.clone();
        std::thread::spawn(move || {
            for _ in 0..2 {
                if let Some((lid, env)) = core_link.recv_ask(Duration::from_secs(5)) {
                    let (_, signed) = answer_ask(&*backend_clone, &core_kp, &env.msg).unwrap();
                    core_link.send_to(lid, &signed).unwrap();
                }
            }
        });

        // Phone starts anchored at genesis.
        let mut phone_headers = HeaderChain::new(Network::Regtest, 0, genesis).unwrap();
        let phone_link = phone_gossip.local_link();

        let ask = Msg::LightAsk {
            id: "11".repeat(16),
            locator: vec![genesis_hash.to_string()],
            txids: vec![],
            outpoints: vec![fund_op.to_string()],
            case_id: Some(case_id.clone()),
            from_height: 1,
        };
        let ask_hash = light_ask_hash(&ask);
        let ask_raw = wire::sign(&phone_kp, 0, ask);
        phone_link.send_outbound(&ask_raw).unwrap();

        let (_, ans_env) = phone_link
            .recv_answer(Duration::from_secs(5))
            .expect("phone receives LightAnswer");
        assert_eq!(ans_env.sender, hex::encode(core_kp.x_only_public_key().0.serialize()));

        let Msg::LightAnswer {
            ask_hash: got_ask_hash,
            tip_height,
            tip_hash,
            headers_from,
            headers,
            txs,
            outputs,
            records,
            covers,
            ..
        } = ans_env.msg
        else {
            panic!("expected LightAnswer");
        };
        assert_eq!(got_ask_hash, ask_hash);
        assert_eq!(tip_height, 3);
        assert_eq!(tip_hash, h3_hash.to_string());
        assert_eq!(headers_from, 1);
        assert_eq!(headers.len(), 3);

        // Phone verifies headers against PoW + MTP + linkage.
        let decoded_headers: Vec<Header> = headers
            .iter()
            .map(|b| Header::consensus_decode(&mut b.as_slice()).unwrap())
            .collect();
        phone_headers
            .apply_fork_at(&decoded_headers, Some(base_time + 300))
            .unwrap();
        assert_eq!(phone_headers.tip(), (3, h3_hash));

        // Phone verifies the creating tx proof for `fund_op` and derives value & scriptPubKey.
        assert_eq!(txs.len(), 1);
        let pmt = PartialMerkleTree::consensus_decode(&mut txs[0].merkle_path.as_slice()).unwrap();
        let bh: BlockHash = txs[0].block_hash.parse().unwrap();
        let hdr = phone_headers
            .header_at(phone_headers.height_of(&bh).unwrap())
            .unwrap();
        let (proven_tx, proven_h, confs) = phone_headers.verify_tx(&txs[0].raw, &pmt, hdr).unwrap();
        assert_eq!(proven_tx.compute_txid(), fund_txid);
        assert_eq!(proven_h, 1);
        assert_eq!(confs, 3);
        assert_eq!(proven_tx.output[0].value.to_sat(), 250_000);
        assert_eq!(proven_tx.output[0].script_pubkey, bond_spk);

        // Output status matches, and covers lists Tx, Output, and Record with typed variants.
        assert_eq!(outputs.len(), 1);
        assert!(outputs[0].unspent);
        assert_eq!(outputs[0].height, 1);
        assert_eq!(records.len(), 1);
        let rec_pmt =
            PartialMerkleTree::consensus_decode(&mut records[0].merkle_path.as_slice()).unwrap();
        let rec_bh: BlockHash = records[0].block_hash.parse().unwrap();
        let rec_hdr = phone_headers
            .header_at(phone_headers.height_of(&rec_bh).unwrap())
            .unwrap();
        let (proven_rec_tx, rec_h, _) = phone_headers
            .verify_tx(&records[0].record, &rec_pmt, rec_hdr)
            .unwrap();
        assert_eq!(proven_rec_tx.compute_txid(), inc_txid);
        assert_eq!(rec_h, 2);
        assert_eq!(crate::ledger::record_of(&proven_rec_tx), Some(inc_payload));
        assert!(covers.contains(&LightCover::Tx(fund_txid.to_string())));
        assert!(covers.contains(&LightCover::Output(fund_op.to_string())));
        assert!(covers.contains(&LightCover::Record(inc_txid.to_string())));

        // Now simulate a 2-block reorg on the Core from height 2 (fork to height 4).
        let reorg_tx2 = make_tx(20, vec![]);
        let reorg_tx3 = make_tx(21, vec![]);
        let reorg_tx4 = make_tx(22, vec![]);
        chain.replace_from(
            2,
            vec![
                (vec![reorg_tx2], base_time + 130),
                (vec![reorg_tx3], base_time + 190),
                (vec![reorg_tx4], base_time + 250),
            ],
        );

        // Phone sends a locator [h3, h2, h1, genesis] -> Core finds common ancestor at h1 -> returns h2..=h4.
        let locator: Vec<String> = (0..=3)
            .rev()
            .map(|h| phone_headers.hash_at(h).unwrap().to_string())
            .collect();
        let ask2 = Msg::LightAsk {
            id: "22".repeat(16),
            locator,
            txids: vec![],
            outpoints: vec![],
            case_id: None,
            from_height: 0,
        };
        let ask2_raw = wire::sign(&phone_kp, 3, ask2);
        phone_link.send_outbound(&ask2_raw).unwrap();

        let (_, ans2_env) = phone_link
            .recv_answer(Duration::from_secs(5))
            .expect("phone receives reorg LightAnswer");
        let Msg::LightAnswer {
            tip_height: tip2,
            tip_hash: tip2_hash,
            headers_from: from2,
            headers: hdrs2,
            ..
        } = ans2_env.msg
        else {
            panic!("expected LightAnswer");
        };
        assert_eq!(tip2, 4);
        assert_eq!(from2, 2);
        assert_eq!(hdrs2.len(), 3);
        let decoded2: Vec<Header> = hdrs2
            .iter()
            .map(|b| Header::consensus_decode(&mut b.as_slice()).unwrap())
            .collect();
        phone_headers
            .apply_fork_at(&decoded2, Some(base_time + 400))
            .unwrap();
        assert_eq!(phone_headers.tip().0, 4);
        assert_eq!(phone_headers.tip().1.to_string(), tip2_hash);

        // Confirm zero gossip store pollution.
        assert_eq!(core_gossip.store_len(), 0);
        assert_eq!(phone_gossip.store_len(), 0);
    }

    /// Live regtest integration test (run when `BITAID_RPC` points to a running regtest `bitcoind`).
    #[test]
    #[ignore = "requires live regtest bitcoind via BITAID_RPC"]
    fn regtest_core_answers_light_ask_and_verifies() {
        let rpc = Rpc::from_env();
        let secp = Secp256k1::new();
        let core_kp = Keypair::new(&secp, &mut rand::thread_rng());
        let h0 = rpc.height();
        let h0_hash = rpc.block_hash_at(h0).unwrap();
        let h0_raw = rpc.raw_header(&h0_hash).unwrap();
        let h0_hdr = Header::consensus_decode(&mut h0_raw.as_slice()).unwrap();

        // Fund an output with a Bitaid INCIDENT record and confirm it.
        let case_bytes = [0x5au8; 32];
        let case_id = hex::encode(case_bytes);
        let spk = rpc.new_spk().unwrap();
        let op = rpc
            .fund_with_record(&spk, 10_000, &crate::ledger::incident_record(&case_bytes))
            .unwrap();
        rpc.confirm(&[op.txid]);

        let ask = Msg::LightAsk {
            id: "99".repeat(16),
            locator: vec![h0_hash],
            txids: vec![],
            outpoints: vec![op.to_string()],
            case_id: Some(case_id),
            from_height: h0,
        };
        let (ans, signed) = answer_ask(&rpc, &core_kp, &ask).unwrap();
        assert_eq!(wire::verify(&signed).unwrap().msg, ans);

        let Msg::LightAnswer {
            headers_from,
            headers,
            txs,
            outputs,
            records,
            ..
        } = ans
        else {
            panic!("expected LightAnswer");
        };
        let mut hc = HeaderChain::new(Network::Regtest, h0, h0_hdr).unwrap();
        let decoded: Vec<Header> = headers
            .iter()
            .map(|b| Header::consensus_decode(&mut b.as_slice()).unwrap())
            .collect();
        let now_ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;
        assert!(headers_from >= h0);
        hc.apply_fork_at(&decoded, Some(now_ts + 60)).unwrap();

        assert_eq!(txs.len(), 1);
        let pmt = PartialMerkleTree::consensus_decode(&mut txs[0].merkle_path.as_slice()).unwrap();
        let bh: BlockHash = txs[0].block_hash.parse().unwrap();
        let hdr = hc.header_at(hc.height_of(&bh).unwrap()).unwrap();
        let (proven, _, _) = hc.verify_tx(&txs[0].raw, &pmt, hdr).unwrap();
        assert_eq!(proven.compute_txid(), op.txid);
        assert_eq!(proven.output[op.vout as usize].value.to_sat(), 10_000);
        assert!(outputs.iter().any(|o| o.outpoint == op.to_string() && o.unspent));
        assert!(records.iter().any(|r| r.txid == op.txid.to_string()));
    }
}
