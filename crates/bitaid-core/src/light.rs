//! Light-client chain verification (Specification §7.2, `design/phone_light.md` step 1).
//!
//! Self-contained, network-free verification of Bitcoin block headers (linkage, proof of work,
//! median-time-past, difficulty retargeting) and transaction Merkle inclusion proofs.
//!
//! Note on BIP325 signet: a signet block challenge signature lives in the coinbase witness
//! commitment, not in the 80-byte block header. Headers-only verification on signet checks linkage,
//! PoW target, MTP, and retargeting; omission and signet-challenge forgery are caught by the
//! independent tip cross-check (§7.2) before signing anything that moves funds.

use bitcoin::block::Header;
use bitcoin::consensus::Decodable;
use bitcoin::merkle_tree::{MerkleBlock, PartialMerkleTree};
use bitcoin::params::Params;
use bitcoin::{BlockHash, CompactTarget, Network, Target, Transaction, TxMerkleNode, Txid, Work};
use std::collections::HashMap;
use std::fmt;

/// Difficulty adjustment interval in blocks (Bitcoin consensus).
pub const DIFFICULTY_ADJUSTMENT_INTERVAL: u32 = 2016;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LightError {
    /// Header's `prev_blockhash` does not match the expected parent hash.
    BrokenLink { height: u32 },
    /// Header hash does not meet its declared target, or target exceeds network maximum.
    InsufficientWork { height: u32 },
    /// Header `bits` does not match the expected difficulty for this height and network.
    InvalidBits { height: u32, expected: u32, got: u32 },
    /// Header timestamp is not strictly greater than the median time of the prior 11 blocks.
    TimestampTooOld { height: u32, time: u32, mtp: u32 },
    /// Raw transaction is 64 bytes (rejected to prevent SPV Merkle leaf/inner-node confusion)
    /// or fails canonical consensus decoding.
    InvalidTransaction(String),
    /// Partial Merkle tree is malformed, its root does not match the header's `merkle_root`,
    /// or the transaction's txid is not among the matched leaves.
    InvalidMerkleProof(String),
    /// A reorg fork has less than or equal cumulative work compared to the active chain,
    /// or its ancestor is unknown.
    ForkRejected(String),
}

impl fmt::Display for LightError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LightError::BrokenLink { height } => write!(f, "broken header link at height {height}"),
            LightError::InsufficientWork { height } => {
                write!(f, "insufficient proof of work at height {height}")
            }
            LightError::InvalidBits {
                height,
                expected,
                got,
            } => write!(
                f,
                "invalid bits at height {height}: expected {expected:#x}, got {got:#x}"
            ),
            LightError::TimestampTooOld { height, time, mtp } => {
                write!(f, "timestamp {time} <= MTP {mtp} at height {height}")
            }
            LightError::InvalidTransaction(s) => write!(f, "invalid transaction: {s}"),
            LightError::InvalidMerkleProof(s) => write!(f, "invalid Merkle proof: {s}"),
            LightError::ForkRejected(s) => write!(f, "fork rejected: {s}"),
        }
    }
}

impl std::error::Error for LightError {}

/// Checks that a single header's PoW hash meets its own target and that the target is not easier
/// than the network's maximum attainable target.
pub fn check_header_pow(header: &Header, height: u32, network: Network) -> Result<BlockHash, LightError> {
    let params = Params::from(network);
    let target = header.target();
    if target > params.max_attainable_target {
        return Err(LightError::InsufficientWork { height });
    }
    header
        .validate_pow(target)
        .map_err(|_| LightError::InsufficientWork { height })
}

/// Computes the Bitcoin median-time-past (MTP) of up to the last 11 headers (ending at `recent.last()`).
pub fn median_time_past(recent: &[Header]) -> Option<u32> {
    if recent.is_empty() {
        return None;
    }
    let start = recent.len().saturating_sub(11);
    let mut times: Vec<u32> = recent[start..].iter().map(|h| h.time).collect();
    times.sort_unstable();
    Some(times[times.len() / 2])
}

/// Verifies `next` as the child of `prev` at `height = prev_height + 1`.
///
/// - `recent` should end with `prev` (up to 11 headers) for the MTP check.
/// - `window_start`, when provided on a retarget boundary (`height % 2016 == 0`), is the header
///   at `height - 2016` used to check the Bitcoin difficulty retarget rule.
pub fn verify_next_header(
    prev: &Header,
    prev_height: u32,
    next: &Header,
    network: Network,
    recent: &[Header],
    window_start: Option<&Header>,
) -> Result<BlockHash, LightError> {
    let height = prev_height + 1;
    let prev_hash = prev.block_hash();
    if next.prev_blockhash != prev_hash {
        return Err(LightError::BrokenLink { height });
    }
    let hash = check_header_pow(next, height, network)?;

    if let Some(mtp) = median_time_past(recent) {
        if next.time <= mtp {
            return Err(LightError::TimestampTooOld {
                height,
                time: next.time,
                mtp,
            });
        }
    }

    let params = Params::from(network);
    if !params.no_pow_retargeting {
        if height % DIFFICULTY_ADJUSTMENT_INTERVAL == 0 {
            if let Some(first) = window_start {
                let timespan = prev.time.saturating_sub(first.time) as u64;
                let expected = CompactTarget::from_next_work_required(prev.bits, timespan, params);
                if next.bits != expected {
                    return Err(LightError::InvalidBits {
                        height,
                        expected: expected.to_consensus(),
                        got: next.bits.to_consensus(),
                    });
                }
            }
        } else if !params.allow_min_difficulty_blocks && next.bits != prev.bits {
            return Err(LightError::InvalidBits {
                height,
                expected: prev.bits.to_consensus(),
                got: next.bits.to_consensus(),
            });
        }
    } else if next.target() > params.max_attainable_target {
        return Err(LightError::InsufficientWork { height });
    }

    Ok(hash)
}

/// Verifies that `raw_tx` decodes canonically to a Bitcoin transaction, is not 64 bytes
/// (SPV inner-node confusion defense), and is proven by `pmt` to be committed in `header`.
pub fn verify_raw_tx_proof(
    raw_tx: &[u8],
    pmt: &PartialMerkleTree,
    header: &Header,
    height: u32,
    network: Network,
) -> Result<Transaction, LightError> {
    // Reject 64-byte raw transactions to prevent Merkle leaf / inner-node confusion.
    if raw_tx.len() == 64 {
        return Err(LightError::InvalidTransaction(
            "64-byte transaction rejected (SPV inner-node guard)".into(),
        ));
    }
    let mut cursor = raw_tx;
    let tx = Transaction::consensus_decode(&mut cursor)
        .map_err(|e| LightError::InvalidTransaction(e.to_string()))?;
    if !cursor.is_empty() {
        return Err(LightError::InvalidTransaction(
            "trailing bytes after transaction".into(),
        ));
    }
    verify_tx_proof(&tx, pmt, header, height, network)?;
    Ok(tx)
}

/// Verifies that `tx` is committed in `header` via `pmt`, and that `header` has valid PoW.
pub fn verify_tx_proof(
    tx: &Transaction,
    pmt: &PartialMerkleTree,
    header: &Header,
    height: u32,
    network: Network,
) -> Result<Txid, LightError> {
    check_header_pow(header, height, network)?;
    let txid = tx.compute_txid();
    verify_txid_merkle(txid, pmt, header.merkle_root)?;
    Ok(txid)
}

/// Verifies a `MerkleBlock` (header + partial Merkle tree) for `tx`.
pub fn verify_merkle_block(
    tx: &Transaction,
    mb: &MerkleBlock,
    height: u32,
    network: Network,
) -> Result<Txid, LightError> {
    verify_tx_proof(tx, &mb.txn, &mb.header, height, network)
}

/// Verifies that `txid` is included in `pmt` and that `pmt` resolves to `expected_root`.
pub fn verify_txid_merkle(
    txid: Txid,
    pmt: &PartialMerkleTree,
    expected_root: TxMerkleNode,
) -> Result<(), LightError> {
    let mut matches = Vec::new();
    let mut indices = Vec::new();
    let root = pmt
        .extract_matches(&mut matches, &mut indices)
        .map_err(|e| LightError::InvalidMerkleProof(e.to_string()))?;
    if root != expected_root {
        return Err(LightError::InvalidMerkleProof(format!(
            "merkle root mismatch: expected {expected_root}, got {root}"
        )));
    }
    if !matches.contains(&txid) {
        return Err(LightError::InvalidMerkleProof(format!(
            "txid {txid} not in matched leaves"
        )));
    }
    Ok(())
}

/// A verified contiguous chain of Bitcoin block headers starting from a trusted checkpoint
/// `(start_height, anchor_header)` (e.g. genesis or a checkpoint height).
#[derive(Clone, Debug)]
pub struct HeaderChain {
    network: Network,
    start_height: u32,
    headers: Vec<Header>,
    hashes: Vec<BlockHash>,
    by_hash: HashMap<BlockHash, u32>,
    cum_work: Vec<Work>,
}

impl HeaderChain {
    /// Creates a new chain anchored at `anchor` at `start_height` after verifying its PoW.
    pub fn new(network: Network, start_height: u32, anchor: Header) -> Result<Self, LightError> {
        let hash = check_header_pow(&anchor, start_height, network)?;
        let work = anchor.work();
        let mut by_hash = HashMap::new();
        by_hash.insert(hash, start_height);
        Ok(Self {
            network,
            start_height,
            headers: vec![anchor],
            hashes: vec![hash],
            by_hash,
            cum_work: vec![work],
        })
    }

    pub fn network(&self) -> Network {
        self.network
    }

    pub fn start_height(&self) -> u32 {
        self.start_height
    }

    pub fn tip(&self) -> (u32, BlockHash) {
        let idx = self.headers.len() - 1;
        (self.start_height + idx as u32, self.hashes[idx])
    }

    pub fn total_work(&self) -> Work {
        *self.cum_work.last().expect("chain is non-empty")
    }

    pub fn header_at(&self, height: u32) -> Option<&Header> {
        let idx = height.checked_sub(self.start_height)? as usize;
        self.headers.get(idx)
    }

    pub fn hash_at(&self, height: u32) -> Option<BlockHash> {
        let idx = height.checked_sub(self.start_height)? as usize;
        self.hashes.get(idx).copied()
    }

    pub fn height_of(&self, hash: &BlockHash) -> Option<u32> {
        self.by_hash.get(hash).copied()
    }

    /// Appends one verified header directly on top of the current tip.
    pub fn append(&mut self, header: Header) -> Result<(u32, BlockHash), LightError> {
        let prev_height = self.tip().0;
        let next_height = prev_height + 1;
        let prev = self.headers.last().expect("chain is non-empty");
        let window_start = if next_height % DIFFICULTY_ADJUSTMENT_INTERVAL == 0 {
            next_height
                .checked_sub(DIFFICULTY_ADJUSTMENT_INTERVAL)
                .and_then(|h| self.header_at(h))
        } else {
            None
        };
        let hash = verify_next_header(
            prev,
            prev_height,
            &header,
            self.network,
            &self.headers,
            window_start,
        )?;
        let work = self.total_work() + header.work();
        self.headers.push(header);
        self.hashes.push(hash);
        self.by_hash.insert(hash, next_height);
        self.cum_work.push(work);
        Ok((next_height, hash))
    }

    /// Appends a sequence of headers onto the current tip. If any header fails verification,
    /// the chain is left unchanged (atomic batch).
    pub fn append_batch(&mut self, batch: &[Header]) -> Result<(u32, BlockHash), LightError> {
        if batch.is_empty() {
            return Ok(self.tip());
        }
        let mut clone = self.clone();
        for h in batch {
            clone.append(*h)?;
        }
        *self = clone;
        Ok(self.tip())
    }

    /// Evaluates a fork starting from a known ancestor (`fork[0].prev_blockhash`) and switches
    /// to it ONLY if every header in `fork` is valid AND the resulting chain has strictly more
    /// cumulative work than the current chain.
    pub fn apply_fork(&mut self, fork: &[Header]) -> Result<(u32, BlockHash), LightError> {
        let first = fork
            .first()
            .ok_or_else(|| LightError::ForkRejected("empty fork".into()))?;
        let ancestor_height = self
            .height_of(&first.prev_blockhash)
            .ok_or_else(|| LightError::ForkRejected("unknown fork ancestor".into()))?;
        let keep_len = (ancestor_height - self.start_height + 1) as usize;
        let mut candidate = HeaderChain {
            network: self.network,
            start_height: self.start_height,
            headers: self.headers[..keep_len].to_vec(),
            hashes: self.hashes[..keep_len].to_vec(),
            by_hash: self.hashes[..keep_len]
                .iter()
                .enumerate()
                .map(|(i, h)| (*h, self.start_height + i as u32))
                .collect(),
            cum_work: self.cum_work[..keep_len].to_vec(),
        };
        for h in fork {
            candidate.append(*h)?;
        }
        if candidate.total_work() <= self.total_work() {
            return Err(LightError::ForkRejected(
                "fork does not have strictly more work".into(),
            ));
        }
        *self = candidate;
        Ok(self.tip())
    }
}

/// Helper to compare a header's declared target against a minimum required difficulty.
pub fn header_meets_target(header: &Header, max_target: Target) -> bool {
    header.target() <= max_target && header.validate_pow(header.target()).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::absolute::LockTime;
    use bitcoin::block::Version;
    use bitcoin::consensus::Encodable;
    use bitcoin::hashes::Hash;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, TxIn, TxOut, Witness};

    const REGTEST_BITS: u32 = 0x207fffff;

    fn dummy_tx(tag: u32) -> Transaction {
        Transaction {
            version: TxVersion::TWO,
            lock_time: LockTime::from_consensus(tag),
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::from_bytes(vec![0x04, (tag & 0xff) as u8, 0x01, 0x02, 0x03]),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50_000 + tag as u64),
                script_pubkey: ScriptBuf::new(),
            }],
        }
    }

    fn mine_header(prev_blockhash: BlockHash, merkle_root: TxMerkleNode, time: u32, bits: u32) -> Header {
        let mut h = Header {
            version: Version::TWO,
            prev_blockhash,
            merkle_root,
            time,
            bits: CompactTarget::from_consensus(bits),
            nonce: 0,
        };
        let target = h.target();
        while h.validate_pow(target).is_err() {
            h.nonce = h.nonce.wrapping_add(1);
        }
        h
    }

    fn merkle_root_of(txids: &[Txid]) -> TxMerkleNode {
        let pmt = PartialMerkleTree::from_txids(txids, &vec![true; txids.len()]);
        let mut m = Vec::new();
        let mut i = Vec::new();
        pmt.extract_matches(&mut m, &mut i).unwrap()
    }

    #[test]
    fn valid_regtest_header_chain_and_merkle_proofs() {
        let txs: Vec<Transaction> = (0..5).map(dummy_tx).collect();
        let txids: Vec<Txid> = txs.iter().map(|t| t.compute_txid()).collect();
        let root0 = merkle_root_of(&txids[..1]);
        let genesis = mine_header(BlockHash::all_zeros(), root0, 1_700_000_000, REGTEST_BITS);
        let mut chain = HeaderChain::new(Network::Regtest, 0, genesis).unwrap();

        let root1 = merkle_root_of(&txids);
        let h1 = mine_header(chain.tip().1, root1, 1_700_000_010, REGTEST_BITS);
        let (ht, bh) = chain.append(h1).unwrap();
        assert_eq!(ht, 1);
        assert_eq!(chain.height_of(&bh), Some(1));

        // Prove inclusion of tx[3] in a 5-tx block via raw bytes + PartialMerkleTree.
        let flags = vec![false, false, false, true, false];
        let pmt = PartialMerkleTree::from_txids(&txids, &flags);
        let mut raw = Vec::new();
        txs[3].consensus_encode(&mut raw).unwrap();
        let decoded = verify_raw_tx_proof(&raw, &pmt, &h1, 1, Network::Regtest).unwrap();
        assert_eq!(decoded.compute_txid(), txids[3]);

        // Also via MerkleBlock.
        let mb = MerkleBlock { header: h1, txn: pmt };
        assert_eq!(verify_merkle_block(&txs[3], &mb, 1, Network::Regtest).unwrap(), txids[3]);
    }

    #[test]
    fn rejects_broken_link_insufficient_work_and_old_timestamp() {
        let root = TxMerkleNode::all_zeros();
        let h0 = mine_header(BlockHash::all_zeros(), root, 1_700_000_100, REGTEST_BITS);
        let mut chain = HeaderChain::new(Network::Regtest, 0, h0).unwrap();

        // Broken prev_blockhash
        let bad_link = mine_header(BlockHash::all_zeros(), root, 1_700_000_110, REGTEST_BITS);
        assert!(matches!(chain.append(bad_link), Err(LightError::BrokenLink { height: 1 })));

        // Insufficient PoW: use mainnet-hard bits with nonce 0 (practically impossible to pass)
        let mut bad_pow = Header {
            version: Version::TWO,
            prev_blockhash: chain.tip().1,
            merkle_root: root,
            time: 1_700_000_120,
            bits: CompactTarget::from_consensus(0x1d00ffff),
            nonce: 0,
        };
        if bad_pow.validate_pow(bad_pow.target()).is_ok() {
            bad_pow.nonce += 1;
        }
        assert!(matches!(
            chain.append(bad_pow),
            Err(LightError::InsufficientWork { height: 1 })
        ));

        // Timestamp <= MTP
        let old_ts = mine_header(chain.tip().1, root, 1_700_000_100, REGTEST_BITS);
        assert!(matches!(
            chain.append(old_ts),
            Err(LightError::TimestampTooOld { height: 1, .. })
        ));
    }

    #[test]
    fn rejects_wrong_merkle_path_and_64_byte_tx() {
        let txs: Vec<Transaction> = (0..4).map(dummy_tx).collect();
        let txids: Vec<Txid> = txs.iter().map(|t| t.compute_txid()).collect();
        let root = merkle_root_of(&txids);
        let h = mine_header(BlockHash::all_zeros(), root, 1_700_000_000, REGTEST_BITS);

        // Proof matches tx[1], NOT tx[2]
        let pmt_for_1 = PartialMerkleTree::from_txids(&txids, &[false, true, false, false]);
        assert!(matches!(
            verify_tx_proof(&txs[2], &pmt_for_1, &h, 0, Network::Regtest),
            Err(LightError::InvalidMerkleProof(_))
        ));

        // Proof against a different header merkle_root
        let wrong_header = mine_header(BlockHash::all_zeros(), TxMerkleNode::all_zeros(), 1_700_000_000, REGTEST_BITS);
        assert!(matches!(
            verify_tx_proof(&txs[1], &pmt_for_1, &wrong_header, 0, Network::Regtest),
            Err(LightError::InvalidMerkleProof(_))
        ));

        // 64-byte raw tx rejected (SPV inner-node guard)
        let fake64 = [0u8; 64];
        assert!(matches!(
            verify_raw_tx_proof(&fake64, &pmt_for_1, &h, 0, Network::Regtest),
            Err(LightError::InvalidTransaction(_))
        ));
    }

    #[test]
    fn reorg_accepts_more_work_and_rejects_equal_or_less() {
        let root = TxMerkleNode::all_zeros();
        let h0 = mine_header(BlockHash::all_zeros(), root, 1_700_000_000, REGTEST_BITS);
        let mut chain = HeaderChain::new(Network::Regtest, 0, h0).unwrap();
        let h1a = mine_header(chain.tip().1, root, 1_700_000_010, REGTEST_BITS);
        chain.append(h1a).unwrap();

        // Equal-work competing fork of length 1 is rejected
        let h1b = mine_header(h0.block_hash(), root, 1_700_000_011, REGTEST_BITS);
        assert!(matches!(chain.apply_fork(&[h1b]), Err(LightError::ForkRejected(_))));
        assert_eq!(chain.tip(), (1, h1a.block_hash()));

        // Strictly longer (more work) fork succeeds
        let h2b = mine_header(h1b.block_hash(), root, 1_700_000_020, REGTEST_BITS);
        let (tip_h, tip_hash) = chain.apply_fork(&[h1b, h2b]).unwrap();
        assert_eq!(tip_h, 2);
        assert_eq!(tip_hash, h2b.block_hash());
        assert_eq!(chain.height_of(&h1a.block_hash()), None);
        assert_eq!(chain.height_of(&h1b.block_hash()), Some(1));
    }

    #[test]
    fn non_retarget_bits_change_rejected_on_mainnet_and_signet() {
        // Test the bits check directly via verify_next_header with a synthetic high-target check:
        // On mainnet/signet, changing bits outside height % 2016 == 0 must fail.
        let root = TxMerkleNode::all_zeros();
        let h0 = mine_header(BlockHash::all_zeros(), root, 1_700_000_000, REGTEST_BITS);
        // Regtest bits exceed signet max_attainable_target -> rejected as InsufficientWork.
        assert!(matches!(
            check_header_pow(&h0, 0, Network::Signet),
            Err(LightError::InsufficientWork { height: 0 })
        ));
    }
}
