//! Arbitration (Specification §10): the deterministic parts every party recomputes for itself —
//! panel sizes, the seat draw from a block hash, the two-thirds supermajority, the asymmetric
//! penalty and the tier commitment.
use crate::case::{Alerted, Rostered};
use crate::chain::Rpc;
use crate::wire::{self, Ballot, Envelope, Msg};
use bitaid_core::hashes::tagged;
use bitaid_core::outputs::{self, bond_leaf, seizure_leaf};
use bitaid_core::scripts::KeyPolicy;
use bitaid_core::tree::ScriptTree;
use bitaid_core::txbuild;
use bitcoin::secp256k1::{Message, Secp256k1, XOnlyPublicKey};
use bitcoin::{OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
use std::collections::{BTreeMap, HashMap};
use std::str::FromStr;

/// Panel size of a tier: 3 at first instance, 7, 15, 31, then doubling (§10.5).
/// Review stages are numbered above every arbitration tier: stage s is tier REVIEW_BASE + s (§10.3).
pub const REVIEW_BASE: u32 = 100;
/// Panels of the staged review: 30 in production, 5 at prototype scale.
pub const REVIEW_PANEL: usize = 5;
pub const REVIEW_STAGES: u32 = 3;
/// What a seizure prepays for keeping its case's evidence (§12 item 5): up to 20 years beyond the
/// standard five at the case's cold-storage rate. One fixed figure at prototype scale, standing in for
/// the rate the base-slot holders quote.
pub const RETENTION_SATS: u64 = 200_000;

pub fn is_review(tier: u32) -> bool {
    tier > REVIEW_BASE
}

pub fn panel_size(tier: u32) -> usize {
    if is_review(tier) {
        return REVIEW_PANEL;
    }
    match tier {
        0 | 1 => 3,
        2 => 7,
        3 => 15,
        4 => 31,
        n => 31 * 2usize.pow(n - 4) + (2usize.pow(n - 4) - 1),
    }
}

/// Fee per seat at a tier: the base plus 25% per tier above the first (§10.5).
pub fn seat_fee(base: u64, tier: u32) -> u64 {
    // review panels are not paid per seat: arbitrators review to keep their coherence current, and
    // reviewers share the 3× premium only when a fraud is confirmed (§10.3, §12)
    if is_review(tier) {
        return 0;
    }
    base * (100 + 25 * (tier.saturating_sub(1) as u64)) / 100
}

/// Seats drawn from the offers by randomness from a block mined after offers closed (§10.2):
/// each offer is ranked by tagged_hash(block hash ‖ case ‖ tier ‖ offerer); the lowest `n` win.
/// Speed of offering buys nothing, and anyone holding the offers and the block can check the draw.
pub fn draw(block_hash: &str, case: &str, tier: u32, offers: &[String], n: usize) -> Vec<String> {
    let mut ranked: Vec<([u8; 32], String)> = offers
        .iter()
        .map(|o| {
            let mut b = hex::decode(block_hash).unwrap_or_default();
            b.extend_from_slice(case.as_bytes());
            b.extend_from_slice(&tier.to_le_bytes());
            b.extend_from_slice(o.as_bytes());
            (tagged("Bitaid/seat-draw", &b), o.clone())
        })
        .collect();
    ranked.sort();
    ranked.dedup_by(|a, b| a.1 == b.1);
    ranked.into_iter().take(n).map(|x| x.1).collect()
}

/// A verdict's identity for counting: two arbitrators agree when they give the same answers — each
/// seat's class, the outcome and misuse — whatever order they list the acts in and whichever second of
/// the footage they cite (review finding D-7).
/// Whether a seat offer names a live output under the bond script its own keys and the case's oracle
/// key give: a standing test, by the chain, for a message from a key not yet seen in a case.
pub fn offer_backed(rpc: &Rpc, oracle: &XOnlyPublicKey, m: &Msg) -> bool {
    let Some(b) = Bond::from_offer(m) else { return false };
    rpc.utxo(&b.op).is_some_and(|o| o.script_pubkey == b.tree(oracle).script_pubkey())
}

/// A ballot's fault findings in one form, whatever order or repetition they were written in: one per
/// seat, the gravest, and of those the lowest harmed seat. Everything that reads findings reads these.
pub fn canon_faults(v: &Ballot) -> Vec<wire::Fault> {
    let mut f = v.faults.clone();
    // by seat, then gravest first, then harmed (None before Some, low before high)
    f.sort_by(|x, y| (x.seat, std::cmp::Reverse(x.severity), x.harmed).cmp(&(y.seat, std::cmp::Reverse(y.severity), y.harmed)));
    f.dedup_by(|x, y| x.seat == y.seat);
    f
}

pub fn verdict_key(v: &Ballot) -> Vec<u8> {
    let mut c = v.clone();
    for a in &mut c.acts {
        a.footage = None;
    }
    c.acts.sort_by(|x, y| {
        (x.seat, format!("{:?}", x.class)).cmp(&(y.seat, format!("{:?}", y.class)))
    });
    c.acts.dedup_by(|x, y| x.seat == y.seat && x.class == y.class);
    c.faults = canon_faults(v);
    let mut b = Vec::new();
    ciborium::into_writer(&c, &mut b).unwrap();
    b
}

/// The verdict that at least two thirds of the panel gave, if any (§10.5: every tier decides by ⅔).
pub fn supermajority(n: usize, votes: &[Ballot]) -> Option<Ballot> {
    supermajority_of(n, votes, 2, 3)
}

/// A verdict held by at least num/den of the `n` seats.
pub fn supermajority_of(n: usize, votes: &[Ballot], num: usize, den: usize) -> Option<Ballot> {
    let need = (num * n).div_ceil(den);
    for v in votes {
        let k = verdict_key(v);
        if votes.iter().filter(|x| verdict_key(x) == k).count() >= need {
            return Some(v.clone());
        }
    }
    None
}

/// The isolation penalty factor for a dissenter on a panel of `n` where a share `p` dissented (§10.4):
/// 2 + 2·(1/3 − p)/(1/3 − 1/n), p clamped to [1/n, 1/3], capped at 4; 2 on panels of 3.
pub fn penalty_factor(n: usize, dissenters: usize) -> f64 {
    if n <= 3 {
        return 2.0;
    }
    let nf = n as f64;
    let p = (dissenters as f64 / nf).clamp(1.0 / nf, 1.0 / 3.0);
    (2.0 + 2.0 * ((1.0 / 3.0 - p) / (1.0 / 3.0 - 1.0 / nf))).min(4.0)
}

/// The tier commitment (B.2): a hash of the case, the tier, the roster and every revealed answer,
/// carried in one OP_RETURN. The oracle attests a tier's verdict only once this is on chain.
pub fn tier_commitment(
    case: &str,
    tier: u32,
    seats: &[String],
    reveals: &[(String, Ballot)],
) -> [u8; 32] {
    tier_commitment_with(case, tier, seats, reveals, &[])
}

/// The tier commitment with the seats counted as committed on time (none: the earlier form).
pub fn tier_commitment_with(
    case: &str,
    tier: u32,
    seats: &[String],
    reveals: &[(String, Ballot)],
    committed: &[String],
) -> [u8; 32] {
    let mut b = case.as_bytes().to_vec();
    b.extend_from_slice(&tier.to_le_bytes());
    let mut s = seats.to_vec();
    s.sort();
    for x in s {
        b.extend_from_slice(x.as_bytes());
    }
    let mut r: Vec<(String, Vec<u8>)> = reveals
        .iter()
        .map(|(k, v)| (k.clone(), verdict_key(v)))
        .collect();
    r.sort();
    for (k, v) in r {
        b.extend_from_slice(k.as_bytes());
        b.extend_from_slice(&v);
    }
    if !committed.is_empty() {
        let mut c = committed.to_vec();
        c.sort();
        c.dedup();
        b.extend_from_slice(b"committed");
        for x in c {
            b.extend_from_slice(x.as_bytes());
        }
    }
    tagged("Bitaid/tier-commitment", &b)
}

// =================================================================== penalties and the seizure output

/// Penalty steps in tenths of the seat fee: half-fee steps from 2× to 4×, then the same ratios doubled
/// up to 4× × 32 (momentum, §10.4). A penalty is rounded down to a step, so each seat pre-signs one
/// forfeiture per step it could owe, not one per possible amount.
pub const STEP_SET: [u64; 25] = [
    20, 25, 30, 35, 40, 50, 60, 70, 80, 100, 120, 140, 160, 200, 240, 280, 320, 400, 480, 560, 640,
    800, 960, 1120, 1280,
];

/// The step (tenths) for a factor, rounded down; at least 2×.
pub fn step_of(factor: f64) -> u64 {
    let t = (factor * 10.0 + 1e-9) as u64;
    STEP_SET
        .iter()
        .rev()
        .find(|s| **s <= t)
        .copied()
        .unwrap_or(20)
}

/// The steps up to `max` (tenths), in order.
pub fn steps_upto(max: u64) -> Vec<u64> {
    STEP_SET.iter().filter(|s| **s <= max).copied().collect()
}

/// Momentum (§10.4): decay per vote served, the margin over the pool's normal error weight, and the cap
/// on doublings (2^5 = 32×). Provisional, as in the Specification.
pub const LAMBDA: f64 = 0.99;
pub const MARGIN: f64 = 1.5;
pub const MAX_DOUBLINGS: f64 = 5.0;

/// The penalty multiplier at momentum `d`: 2^D, capped at 32×.
pub fn multiplier(d: f64) -> f64 {
    2f64.powf(d.clamp(0.0, MAX_DOUBLINGS))
}

/// The largest step a seat taken at momentum `d` could owe: the 4× isolation penalty times 2^D.
/// A seat's case unit (§10.2): at least twice what the verdict can move and at least the largest
/// penalty the seat could owe; no floor of its own.
pub fn unit_value(case_value: u64, max: u64, fee: u64) -> u64 {
    (2 * case_value).max(max * fee / 10)
}

/// The review sampling rate in basis points (§10.3): 5% up to 0.01 BTC, 10% up to 0.1 BTC, 20% up to
/// 1 BTC, 40% above, and at least 40% when the final panel was split.
pub fn review_rate_bp(case_value: u64, split: bool) -> u64 {
    // the bands are in full-size sats: a run with divided amounts (BITAID_SAT_SCALE) keeps its rates
    let k = 1_000_000 / crate::sats(1_000_000).max(1);
    let r = match case_value * k {
        0..=1_000_000 => 500,
        1_000_001..=10_000_000 => 1_000,
        10_000_001..=100_000_000 => 2_000,
        _ => 4_000,
    };
    if split {
        r.max(4_000)
    } else {
        r
    }
}

/// Whether the draw seeded by `block_hash` selects `case` for review at `rate_bp`.
pub fn review_drawn(case: &str, block_hash: &str, rate_bp: u64) -> bool {
    let mut b = hex::decode(block_hash).unwrap_or_default();
    b.extend(hex::decode(case).unwrap_or_default());
    let h = tagged("Bitaid/review-draw", &b);
    u64::from_be_bytes(h[..8].try_into().unwrap()) % 10_000 < rate_bp
}

pub fn max_step(d: f64) -> u64 {
    step_of(4.0 * multiplier(d))
}

/// Relative timelock of the seizure output's fallback leaf: one year of blocks (§12, B.1).
pub const SEIZURE_LOCK: u32 = 52_560;

/// The case's seizure output: a majority of its archivists and the oracle pool distribute it; after a
/// year the first archivist alone (the prototype stands one key in for the harmed parties' aggregate).
pub fn seizure_tree(
    archivists: &[String],
    oracle: &XOnlyPublicKey,
    parties: &XOnlyPublicKey,
) -> Option<(ScriptTree, KeyPolicy)> {
    let mut ks: Vec<XOnlyPublicKey> = archivists.iter().filter_map(|a| wire::xonly(a)).collect();
    ks.sort();
    ks.dedup();
    if ks.is_empty() {
        return None;
    }
    let pol = KeyPolicy::of(ks.len() / 2 + 1, ks);
    let secp = Secp256k1::verification_only();
    // after the lock, the case's parties together (their aggregate key), never one archivist
    Some((
        outputs::seizure(&secp, &pol, oracle, parties, SEIZURE_LOCK),
        pol,
    ))
}

/// Blocks after an entry bond's seizure confirms before its owner's cold key alone may take it back
/// out of the holding output: longer than a staged review can take, so a bond seized for a review that
/// then confirms is moved long before, while one seized without a confirmed review goes back (B.1).
pub const HOLD_RETURN: u32 = 12_960;

/// Where an entry bond's seizure goes first (B.1). Two leaves, no key path: the oracle pool together
/// with a majority of the archivist committee named when the arbitrator joined, who move it into the
/// seizure output of the case a confirmed review found against the arbitrator, each only after its
/// own replay; or the arbitrator's cold key alone, HOLD_RETURN blocks after the seizure confirmed. A
/// captured pool alone can push an entry bond in here, but not take it out.
pub fn holding_tree(
    oracle: &XOnlyPublicKey,
    holders: &[XOnlyPublicKey],
    cold: &XOnlyPublicKey,
) -> Option<(ScriptTree, KeyPolicy)> {
    let first = *holders.first()?;
    let _ = first;
    let pol = KeyPolicy::of(holders.len() / 2 + 1, holders.to_vec());
    let secp = Secp256k1::verification_only();
    Some((
        ScriptTree::new(
            &secp,
            bitaid_core::scripts::nums(),
            vec![
                bitaid_core::scripts::policy_and(&pol, oracle),
                bitaid_core::scripts::after_relative(HOLD_RETURN, cold),
            ],
        ),
        pol,
    ))
}

/// The archivist committee for entry bonds joining at a block: up to 9 announced archivists, drawn by
/// that block's hash (§10.8, B.1; the specification weights the draw by archival labor score, which
/// the prototype does not keep).
pub fn holding_committee(archivists: &[String], block_hash: &str) -> Vec<String> {
    let mut v: Vec<(Vec<u8>, String)> = archivists
        .iter()
        .map(|a| {
            let h = <bitcoin::hashes::sha256::Hash as bitcoin::hashes::Hash>::hash(
                format!("{block_hash}{a}").as_bytes(),
            );
            (bitcoin::hashes::Hash::to_byte_array(h).to_vec(), a.clone())
        })
        .collect();
    v.sort();
    v.dedup_by(|x, y| x.1 == y.1);
    v.into_iter().take(9).map(|x| x.1).collect()
}

/// The move of a seized entry bond from the holding output into a case's seizure output.
#[allow(clippy::too_many_arguments)]
pub fn holding_move(
    oracle: &XOnlyPublicKey,
    holders: &[XOnlyPublicKey],
    cold: &XOnlyPublicKey,
    seized: &Transaction,
    value: u64,
    seizure: &ScriptBuf,
    keep: Option<(u64, ScriptBuf)>,
) -> Option<(Transaction, [u8; 32])> {
    let (t, _) = holding_tree(oracle, holders, cold)?;
    // what the case is owed to its seizure output; any remainder back under the bond's script
    let outs = match keep {
        Some((due, back)) if due < value => vec![(due, seizure.clone()), (value - due, back)],
        _ => vec![(value, seizure.clone())],
    };
    let tx = txbuild::payout(
        OutPoint {
            txid: seized.compute_txid(),
            vout: 0,
        },
        &outs,
    );
    let d = txbuild::scriptspend_digest(
        &tx,
        0,
        &[txbuild::txout(value, t.script_pubkey())],
        &t.scripts[0],
    );
    Some((tx, d))
}

/// Completes the move with the oracle's co-signature and a majority of the committee's signatures.
pub fn holding_witness(
    oracle: &XOnlyPublicKey,
    holders: &[XOnlyPublicKey],
    cold: &XOnlyPublicKey,
    tx: &mut Transaction,
    osig: &[u8; 64],
    arch: &HashMap<XOnlyPublicKey, Vec<u8>>,
) -> Option<()> {
    let (t, pol) = holding_tree(oracle, holders, cold)?;
    let mut items: Vec<Vec<u8>> = vec![osig.to_vec()];
    if pol.devices.len() == 1 {
        items.push(arch.get(&pol.devices[0])?.clone());
    } else {
        let mut given = 0;
        for d in pol.devices.iter().rev() {
            match arch.get(d).filter(|_| given < pol.threshold) {
                Some(s) => {
                    items.push(s.clone());
                    given += 1;
                }
                None => items.push(vec![]),
            }
        }
        if given < pol.threshold {
            return None;
        }
    }
    items.push(t.scripts[0].to_bytes());
    items.push(t.control(0).serialize());
    tx.input[0].witness = Witness::from_slice(&items);
    Some(())
}

/// A bond as its offer names it.
#[derive(Clone, Debug)]
pub struct Bond {
    pub op: OutPoint,
    pub value: u64,
    pub scoped: XOnlyPublicKey,
    pub cold: XOnlyPublicKey,
    pub fallback: u32,
    pub payout: ScriptBuf,
}

impl Bond {
    pub fn from_offer(m: &Msg) -> Option<Bond> {
        let Msg::SeatOffer {
            bond,
            bond_scoped,
            bond_cold,
            bond_fallback,
            bond_value,
            payout_spk,
            ..
        } = m
        else {
            return None;
        };
        Some(Bond {
            op: OutPoint::from_str(bond).ok()?,
            value: *bond_value,
            scoped: wire::xonly(bond_scoped)?,
            cold: wire::xonly(bond_cold)?,
            fallback: *bond_fallback,
            payout: ScriptBuf::from_hex(payout_spk).ok()?,
        })
    }
    pub fn tree(&self, oracle: &XOnlyPublicKey) -> ScriptTree {
        outputs::bond(
            &Secp256k1::verification_only(),
            &self.scoped,
            &self.cold,
            oracle,
            self.fallback,
        )
    }
    /// The forfeiture of `amount` into the seizure output, the rest re-bonded under the same script,
    /// and the digest the scoped key and the oracle sign (FORFEIT leaf).
    pub fn penalty_tx(
        &self,
        oracle: &XOnlyPublicKey,
        amount: u64,
        seizure: &ScriptBuf,
    ) -> (Transaction, [u8; 32]) {
        let t = self.tree(oracle);
        // a remainder too small to relay is not re-bonded: it goes to the seizure output too
        let outs = if amount + bitaid_core::payouts::DUST > self.value {
            vec![(self.value, seizure.clone())]
        } else {
            vec![
                (amount, seizure.clone()),
                (self.value - amount, t.script_pubkey()),
            ]
        };
        let tx = txbuild::payout(self.op, &outs);
        let d = txbuild::scriptspend_digest(
            &tx,
            0,
            &[txbuild::txout(self.value, t.script_pubkey())],
            &t.scripts[bond_leaf::FORFEIT],
        );
        (tx, d)
    }
    /// A spend of this output by its FORFEIT leaf (the scoped key and the oracle pool) to `outs`,
    /// and the digest both sign.
    pub fn spend_to(&self, oracle: &XOnlyPublicKey, outs: &[(u64, ScriptBuf)]) -> (Transaction, [u8; 32]) {
        let t = self.tree(oracle);
        let tx = txbuild::payout(self.op, outs);
        let d = self.spend_digest(oracle, &tx);
        let _ = &t;
        (tx, d)
    }
    /// The digest the scoped key and the oracle sign for `tx` spending this output by its FORFEIT leaf.
    pub fn spend_digest(&self, oracle: &XOnlyPublicKey, tx: &Transaction) -> [u8; 32] {
        let t = self.tree(oracle);
        txbuild::scriptspend_digest(
            tx,
            0,
            &[txbuild::txout(self.value, t.script_pubkey())],
            &t.scripts[bond_leaf::FORFEIT],
        )
    }
    /// The same keys holding another output (a seat's stake).
    pub fn stake(&self, op: OutPoint, value: u64) -> Bond {
        Bond {
            op,
            value,
            ..self.clone()
        }
    }
    /// The pre-signed forfeitures' digests at a seat fee: one per step up to `max`, the whole unit,
    /// then the seat forfeiture refunding the fee.
    pub fn forfeit_digests(
        &self,
        oracle: &XOnlyPublicKey,
        fee: u64,
        seizure: &ScriptBuf,
        refund: &ScriptBuf,
        max: u64,
    ) -> Vec<[u8; 32]> {
        let mut v: Vec<[u8; 32]> = steps_upto(max)
            .iter()
            .map(|st| self.penalty_tx(oracle, st * fee / 10, seizure).1)
            .collect();
        // the whole unit, co-signed only on a finding confirmed by the staged review (§10.2, B.1)
        v.push(self.penalty_tx(oracle, self.value, seizure).1);
        v.push(self.penalty_tx(oracle, fee, refund).1);
        v
    }
    /// The entry bond's seizure, pre-signed when the arbitrator joins (§10.8, B.1): the whole bond
    /// into the holding output.
    pub fn entry_seizure(
        &self,
        oracle: &XOnlyPublicKey,
        holders: &[XOnlyPublicKey],
    ) -> Option<(Transaction, [u8; 32])> {
        let (t, _) = holding_tree(oracle, holders, &self.cold)?;
        Some(self.penalty_tx(oracle, self.value, &t.script_pubkey()))
    }
    /// A unit's release (§10.2): the whole output back under the bond's script, signed by the cold
    /// key and co-signed by the oracle once the case is closed and the review draw passed it over.
    pub fn release_tx(&self, oracle: &XOnlyPublicKey) -> (Transaction, [u8; 32]) {
        let t = self.tree(oracle);
        let tx = txbuild::payout(self.op, &[(self.value, t.script_pubkey())]);
        let d = txbuild::scriptspend_digest(
            &tx,
            0,
            &[txbuild::txout(self.value, t.script_pubkey())],
            &t.scripts[bond_leaf::WITHDRAW],
        );
        (tx, d)
    }
    /// Completes a release with the cold key's signature and the oracle's co-signature.
    pub fn release_witness(
        &self,
        oracle: &XOnlyPublicKey,
        tx: &mut Transaction,
        cold_sig: &[u8],
        osig: &[u8; 64],
    ) {
        let t = self.tree(oracle);
        tx.input[0].witness = Witness::from_slice(&[
            osig.to_vec(),
            cold_sig.to_vec(),
            t.scripts[bond_leaf::WITHDRAW].to_bytes(),
            t.control(bond_leaf::WITHDRAW).serialize(),
        ]);
    }
    /// Completes a forfeiture with the arbitrator's pre-signature and the oracle's co-signature.
    pub fn witness(
        &self,
        oracle: &XOnlyPublicKey,
        tx: &mut Transaction,
        pre: &[u8],
        osig: &[u8; 64],
    ) {
        let t = self.tree(oracle);
        tx.input[0].witness = Witness::from_slice(&[
            osig.to_vec(),
            pre.to_vec(),
            t.scripts[bond_leaf::FORFEIT].to_bytes(),
            t.control(bond_leaf::FORFEIT).serialize(),
        ]);
    }
}

pub fn schnorr_ok(key: &XOnlyPublicKey, digest: &[u8; 32], sig_hex: &str) -> bool {
    let Ok(b) = hex::decode(sig_hex) else {
        return false;
    };
    let Ok(sig) = bitcoin::secp256k1::schnorr::Signature::from_slice(&b) else {
        return false;
    };
    Secp256k1::verification_only()
        .verify_schnorr(&sig, &Message::from_digest(*digest), key)
        .is_ok()
}

/// One tier as every party can rebuild it from the log.
#[derive(Clone, Debug, Default)]
pub struct Tier {
    /// a stage of the staged review rather than an arbitration tier
    pub review: bool,
    pub escalator: String,
    pub offers: HashMap<String, Bond>,
    /// each offer's stated height
    pub offer_height: HashMap<String, u32>,
    pub seats: Vec<String>,
    pub fee_paid: bool,
    pub reveals: Vec<(String, Ballot)>,
    pub committed: bool,
    /// per seat, its stake and the verified pre-signed forfeitures of it
    pub forfeits: HashMap<String, (Bond, Vec<String>)>,
    /// per seat, the height it was seated at (the Seated or Reseated block)
    pub seat_height: HashMap<String, u32>,
    /// per seat, its momentum when seated (§10.4), from every tier committed on chain before that height
    pub momentum: HashMap<String, f64>,
    /// seats that committed a vote (a commitment without a reveal is charged as incoherent)
    pub committers: Vec<String>,
    /// the transaction carrying the tier commitment
    pub commit_txid: Option<String>,
    /// Forfeits messages, verified once momentum is known: (sender, stake, value, sigs)
    pub raw_forfeits: Vec<(String, String, u64, Vec<String>)>,
    /// opened by a dissenting arbitrator of the tier below, who bought the re-roll itself (§10.4)
    pub challenger: bool,
    /// where a forfeited seat's fee goes back to (the payer's refund script, from the Seated message)
    pub refund: Option<ScriptBuf>,
    /// seats that missed their commit deadline and were replaced
    pub forfeited: Vec<String>,
    /// review stages: seats that accepted (or took the seat by replacement), so owe a finding (§10.3)
    pub accepted: Vec<String>,
    /// the offers the draw was made from, as the Seated message lists them (replacements are drawn
    /// from what is left of these, not from offers that arrived later)
    pub listed: Vec<String>,
}

/// Checks a seat's pre-signed forfeitures: the stake is the seat's case unit, an output of at least
/// `unit_value` under the seat-holder's bond script, and each signature is its scoped key's over that step's forfeiture, the
/// last over its seat forfeiture (the fee back to the payer's refund script).
#[allow(clippy::too_many_arguments)]
pub fn verify_forfeits(
    bond: &Bond,
    stake: &str,
    value: u64,
    sigs: &[String],
    oracle: &XOnlyPublicKey,
    fee: u64,
    seizure: &ScriptBuf,
    refund: &ScriptBuf,
    max: u64,
    case_value: u64,
    rpc: &Rpc,
) -> Option<Bond> {
    let st = bond.stake(OutPoint::from_str(stake).ok()?, value);
    let ds = st.forfeit_digests(oracle, fee, seizure, refund, max);
    (value >= unit_value(case_value, max, fee)
        && sigs.len() == ds.len()
        && ds
            .iter()
            .zip(sigs)
            .all(|(d, g)| schnorr_ok(&bond.scoped, d, g))
        // the named output itself: under the bond script and holding exactly the declared value, or the
        // pre-signed forfeitures (whose signatures commit to that amount) would be void on chain
        && rpc.output_paying(&st.op.txid.to_string(), st.op.vout, &bond.tree(oracle).script_pubkey())
            == Some(value))
        .then_some(st)
}

impl Tier {
    /// The tier's two-thirds verdict once committed on chain; a seat that never revealed counts as no
    /// vote toward the two thirds (the reveal deadline, §10.4).
    pub fn verdict(&self) -> Option<Ballot> {
        if !self.committed {
            return None;
        }
        let v: Vec<Ballot> = self.reveals.iter().map(|x| x.1.clone()).collect();
        // every panel decides at two thirds, review panels too: three in turn overturn a verdict
        // (§10.3); the entry bond and expulsion need 80% at each stage (`Replay::review_strong`)
        supermajority(self.seats.len(), &v)
    }
}

/// Where a case's staged review stands (§10.3).
#[derive(Clone, Debug, PartialEq, Default)]
pub enum ReviewState {
    /// the draw passed the case over, or its block is not yet mined
    #[default]
    NotDrawn,
    /// drawn; stage `s` is due or under way
    Pending(u32),
    /// a stage found nothing wrong at 80% (or no 80% finding): the verdict stands
    Cleared(u32),
    /// three panels in turn found the same different verdict, each at 80%
    Confirmed(Ballot),
}

/// The outcome of a case's review draw.
#[derive(Clone, Debug)]
pub struct ReviewDraw {
    pub height: u32,
    pub split: bool,
    pub rate_bp: u64,
    pub drawn: bool,
}

/// A forfeiture the final ruling calls for.
#[derive(Clone, Debug)]
pub struct Penalty {
    pub arbitrator: String,
    pub tier: u32,
    pub step: u64,
    pub amount: u64,
    pub bond: Bond,
    pub pre: String,
    pub tx: Transaction,
    pub digest: [u8; 32],
}

/// A case's arbitration replayed from the log: every check the pool makes, made again by whoever
/// replays it, so the pool, the archivists and the parties reach the same penalties and distribution.
#[derive(Clone, Debug)]
pub struct Replay {
    pub case: String,
    pub base_fee: u64,
    pub oracle: XOnlyPublicKey,
    pub archivists: Vec<String>,
    /// the case's parties' aggregate key: the seizure output's fallback
    pub parties_key: XOnlyPublicKey,
    /// the parties: caller and seats, with the seats' payout scripts
    pub parties: Vec<(String, Option<ScriptBuf>)>,
    pub tiers: BTreeMap<u32, Tier>,
    /// stages of the staged review, by tier number (REVIEW_BASE + s)
    pub reviews: BTreeMap<u32, Tier>,
    /// who convenes the staged review: the case's first archivist in the prototype
    pub convener: Option<String>,
    /// where the staged review stands, as of the replay
    pub review: ReviewState,
    /// each registered arbitrator's entry bond and its verified pre-signed seizure
    pub entries: HashMap<String, (Bond, String, Vec<XOnlyPublicKey>)>,
    /// per arbitrator, the other cases in which it voted for a verdict a staged review overturned
    pub prior_overturns: HashMap<String, usize>,
    /// the bonded arbitrator that flagged the case, if the draw passed it over (§10.3)
    pub flagger: Option<String>,
    /// each attendee's bond and its pre-signed loser-pays forfeiture (§9), checked
    /// each attendee's bond and its pre-signed forfeitures: [loser-pays fee, lapse (25%), whole bond]
    pub loser_pays: HashMap<String, (Bond, Vec<String>)>,
    /// the case's pots and template, to price a harmed responder's loss (§12)
    pub pots: [u64; 3],
    pub template: wire::Template,
    /// one tier-1 panel fee: what a losing attendee pays
    pub loser_fee: u64,
    /// the number of attending seats
    pub seats_n: usize,
    /// the attending vote reached 80% on its own: an escalation of a settled vote charges no loser
    pub attending_settled: bool,
    /// each attendee's revealed ballot, matching its first commitment
    pub ballots: HashMap<String, Ballot>,
    /// units already released under their bonds' scripts: (tier, arbitrator)
    pub released: Vec<(u32, String)>,
    /// registered arbitrators who sat on none of the case's tiers: those a review could be drawn from
    pub review_pool: usize,
}

impl Replay {
    /// The case replayed, each seat's momentum taken from every case in the log (§10.4) and its
    /// forfeitures verified against the steps that momentum calls for.
    pub fn build(hist: &[Envelope], a: &Alerted, r: &Rostered, rpc: &Rpc) -> Option<Replay> {
        let mut rp = Replay::build_core(hist, a, r, rpc)?;
        let oracle = rp.oracle;
        // entry bonds and their seizures, pre-signed at joining under the registry case (B.1)
        let reg = registry_case();
        for e in hist
            .iter()
            .filter(|e| e.msg.case_id() == Some(reg.as_str()))
        {
            if let Msg::Forfeits {
                sigs,
                stake,
                holders,
                ..
            } = &e.msg
            {
                let holders: Vec<XOnlyPublicKey> =
                    holders.iter().filter_map(|h| wire::xonly(h)).collect();
                let Some(b) = hist.iter().find_map(|x| match &x.msg {
                    Msg::SeatOffer { case_id, .. } if *case_id == reg && x.sender == e.sender => {
                        Bond::from_offer(&x.msg)
                    }
                    _ => None,
                }) else {
                    continue;
                };
                let Some((_, d)) = b.entry_seizure(&oracle, &holders) else {
                    continue;
                };
                if b.op.to_string() == *stake
                    && sigs.first().is_some_and(|g| schnorr_ok(&b.scoped, &d, g))
                {
                    rp.entries
                        .entry(e.sender.clone())
                        .or_insert((b, sigs[0].clone(), holders));
                }
            }
        }
        let logs = ledger(hist, rpc, &crate::case::pool_id(&a.oracle_key, &a.attest_key));
        for (w, cases) in overturned_votes(&logs) {
            let n = cases.iter().filter(|c| **c != rp.case).count();
            rp.prior_overturns.insert(w, n);
        }
        let seizure = rp.seizure_spk();
        let (oracle, base_fee) = (rp.oracle, rp.base_fee);
        let case_value: u64 = a.template.pots.iter().sum();
        for (k, t) in rp.tiers.iter_mut() {
            let fee = seat_fee(base_fee, *k);
            let heights: Vec<(String, u32)> =
                t.seat_height.iter().map(|(s, h)| (s.clone(), *h)).collect();
            for (s, h) in heights {
                t.momentum.insert(s.clone(), momentum(&logs, &s, h));
            }
            let (Some(spk), Some(refund)) = (seizure.as_ref(), t.refund.clone()) else {
                continue;
            };
            for (s, stake, value, sigs) in t.raw_forfeits.clone() {
                let Some(b) = t.offers.get(&s) else { continue };
                if t.forfeits.contains_key(&s) {
                    continue;
                }
                let max = max_step(t.momentum.get(&s).copied().unwrap_or(0.0));
                if let Some(st) = verify_forfeits(
                    b, &stake, value, &sigs, &oracle, fee, spk, &refund, max, case_value, rpc,
                ) {
                    t.forfeits.insert(s, (st, sigs));
                }
            }
        }
        // units already released: a finding after their release falls on the entry bond (§10.8)
        for (k, w, b) in rp.units() {
            if rpc
                .tx_height(&b.release_tx(&oracle).0.compute_txid().to_string())
                .is_some()
            {
                rp.released.push((k, w));
            }
        }
        Some(rp)
    }

    /// The case replayed from the log without momentum: who opened each tier, the draw, fees, reveals,
    /// the commitment on chain.
    pub fn build_core(hist: &[Envelope], a: &Alerted, r: &Rostered, rpc: &Rpc) -> Option<Replay> {
        let oracle = wire::xonly(&a.oracle_key)?;
        let case = a.case_hex.clone();
        let mut parties = vec![(a.caller.clone(), None)];
        for (i, s) in r.seats.iter().enumerate() {
            parties.push((s.clone(), r.payout_spks.get(i).cloned()));
        }
        let mut rp = Replay {
            case: case.clone(),
            base_fee: a.template.arb_fee,
            oracle,
            archivists: r.archivists.clone(),
            parties_key: crate::case::parties_key(a, r),
            parties,
            tiers: BTreeMap::new(),
            reviews: BTreeMap::new(),
            convener: r.archivists.first().cloned(),
            review: ReviewState::NotDrawn,
            entries: HashMap::new(),
            prior_overturns: HashMap::new(),
            flagger: None,
            released: vec![],
            review_pool: usize::MAX,
            loser_pays: HashMap::new(),
            ballots: HashMap::new(),
            loser_fee: loser_fee(a),
            pots: a.template.pots,
            template: a.template.clone(),
            seats_n: r.seats.len(),
            attending_settled: false,
        };
        let mine: Vec<&Envelope> = hist
            .iter()
            .filter(|e| e.msg.case_id() == Some(case.as_str()))
            .collect();
        // the attending vote and each attendee's loser-pays forfeiture (§9)
        let mut bcommits: HashMap<&str, &str> = HashMap::new();
        for e in &mine {
            match &e.msg {
                Msg::BallotCommit { commitment, .. } if r.seats.contains(&e.sender) => {
                    bcommits.entry(e.sender.as_str()).or_insert(commitment.as_str());
                }
                Msg::BallotReveal { ballot, salt, .. } => {
                    let ok = bcommits.get(e.sender.as_str()).is_some_and(|c| {
                        *c == hex::encode(ballot.commitment(&wire::h32(salt).unwrap_or_default(), &e.sender))
                    });
                    if ok {
                        rp.ballots.entry(e.sender.clone()).or_insert(ballot.clone());
                    }
                }
                _ => {}
            }
        }
        let bv: Vec<Ballot> = rp.ballots.values().cloned().collect();
        rp.attending_settled = !bv.is_empty()
            && matches!(
                crate::settle::decide(r.seats.len(), a.template.pots, &a.template, &bv),
                crate::settle::Decision::Settled(_)
            );
        if let Some(spk) = rp.seizure_spk() {
            for e in &mine {
                if let Msg::Forfeits { tier: 0, sigs, .. } = &e.msg {
                    if rp.loser_pays.contains_key(&e.sender) {
                        continue;
                    }
                    let Some(b) = accepted_bond(&mine, &e.sender, rpc) else { continue };
                    // only a complete set counts, every signature valid: the digests are fixed by the
                    // bond and the case, so any complete set is as good as any other, and neither a
                    // partial one sent first nor the order of arrival changes what the bond owes
                    let ds = attendee_forfeit_digests(&b, &oracle, loser_fee(a), &spk);
                    if sigs.len() == ds.len() && ds.iter().zip(sigs).all(|(d, sg)| schnorr_ok(&b.scoped, d, sg)) {
                        rp.loser_pays.insert(e.sender.clone(), (b, sigs.clone()));
                    }
                }
            }
        }
        // tier by tier, since who may open a tier depends on the tier below it
        let max = mine
            .iter()
            .filter_map(|e| match &e.msg {
                Msg::Escalate { tier, .. } if !is_review(*tier) => Some(*tier),
                _ => None,
            })
            .max()
            .unwrap_or(0);
        for k in 1..=max {
            let prev = rp.tiers.get(&(k - 1)).cloned();
            // who opens tier k: a party, or a dissenter of tier k-1 buying the re-roll itself (§10.4)
            let mut opener: Option<(String, bool)> = None;
            for e in &mine {
                let Msg::Escalate { tier, .. } = &e.msg else {
                    continue;
                };
                if *tier != k {
                    continue;
                }
                let s = &e.sender;
                if rp.parties.iter().any(|p| &p.0 == s) {
                    opener = Some((s.clone(), false));
                    break;
                }
                let Some(pt) = prev.as_ref() else {
                    continue;
                };
                let Some(pv) = pt.verdict() else {
                    continue;
                };
                if pt
                    .reveals
                    .iter()
                    .any(|(x, v)| x == s && verdict_key(v) != verdict_key(&pv))
                {
                    opener = Some((s.clone(), true));
                    break;
                }
            }
            // tier 1 is opened on the chain, not in the log: by the party whose posting for the case
            // came first in the chain's order, at the height the market took the case up (§10.6)
            let mut anchor = None;
            if k == 1 {
                let parties: Vec<&str> = rp.parties.iter().map(|p| p.0.as_str()).collect();
                match tier1_opening(rpc, &oracle, &case, &parties) {
                    Some((who, h)) => {
                        opener = Some((who, false));
                        anchor = Some(h);
                    }
                    None => opener = None,
                }
            }
            let Some((escalator, challenger)) = opener else {
                break;
            };
            let t = read_tier(
                &mine,
                &case,
                k,
                &escalator,
                challenger,
                rp.base_fee,
                rpc,
                None,
                None,
                a.template.commit_blocks,
                &oracle,
                anchor,
                a.template.dispute_blocks,
            );
            rp.tiers.insert(k, t);
        }
        // the staged review (§10.3): convened only on a case the draw selected, each stage only after
        // the one before found a different verdict at 80%
        // a flag counts from a registered arbitrator, on a case the draw passed over
        let reg_all = registry(hist);
        if rp.review_draw(a, rpc).is_some_and(|d| !d.drawn) {
            rp.flagger = mine.iter().find_map(|e| match &e.msg {
                Msg::Flag { .. } if reg_all.contains_key(&e.sender) => Some(e.sender.clone()),
                _ => None,
            });
        }
        let seated = rp.review_excluded();
        rp.review_pool = reg_all.keys().filter(|w| !seated.contains(*w)).count();
        for st in 1..=REVIEW_STAGES {
            let k = REVIEW_BASE + st;
            if rp.review_state(a, rpc) != ReviewState::Pending(st) {
                break;
            }
            // the stage's draw block is fixed by the chain, not by whoever convenes it (review): the
            // first valid seating by any of the case's archivists or any registered arbitrator counts,
            // so an opening never seated holds nothing back and no convener chooses a block
            let Some(due) = rp.stage_draw_height(a, rpc, hist, st) else { break };
            let mut convs: Vec<&String> = vec![];
            for e in &mine {
                if matches!(&e.msg, Msg::Seated { tier, .. } if *tier == k)
                    && (r.archivists.contains(&e.sender) || reg_all.contains_key(&e.sender))
                    && !convs.contains(&&e.sender)
                {
                    convs.push(&e.sender);
                }
            }
            let reg = registry(hist);
            let payer = rp.flagger.clone();
            let mut found = None;
            for conv in convs {
            let mut t = read_tier(
                &mine,
                &case,
                k,
                conv,
                false,
                rp.base_fee,
                rpc,
                Some(&reg),
                payer.as_deref(),
                a.template.commit_blocks,
                &oracle,
                None,
                a.template.dispute_blocks,
            );
            t.review = true;
            // each panel independent: drawn only from arbitrators who sat on neither the case nor an
            // earlier stage of its review
            let excluded = rp.review_excluded();
            if t.listed.iter().any(|x| excluded.contains(x)) {
                continue;
            }
            let h = t.seat_height.values().copied().min().unwrap_or(0);
            let off = inactive(hist, h);
            if t.listed.iter().any(|x| off.contains(x)) {
                continue;
            }
            // the block is fixed by the opening (draw_blocks() after it), and the list is the whole
            // eligible pool: everyone registered at least two blocks before the draw who sat on neither
            // the case nor an earlier stage and is not suspended; one may be left out only if its bond
            // is not a live entry bond
            if t.seats.is_empty() {
                continue;
            }
            {
                let at = registry_at(hist, h.saturating_sub(2));
                let listed: std::collections::HashSet<&String> = t.listed.iter().collect();
                // (an entry bond is one the chain registers, unspent at the draw: read the same by
                // every node, then and later)
                let live = |b: &Bond| chain_registered(rpc, &oracle, b, h);
                let complete = at
                    .iter()
                    .filter(|(w, _)| !excluded.contains(*w) && !off.contains(*w))
                    .all(|(w, b)| listed.contains(w) || !live(b));
                let inside = t.listed.iter().all(|w| at.contains_key(w));
                if h != due || !complete || !inside {
                    continue;
                }
            }
            found = Some(t);
            break;
            }
            let Some(t) = found else { break };
            rp.reviews.insert(k, t);
        }
        rp.review = rp.review_state(a, rpc);
        Some(rp)
    }

    /// The seat forfeiture of `seat` on `tier`: its stake pays the fee back to the payer's refund script,
    /// the rest re-bonded (§10.4). Returns the transaction, its digest, the seat's pre-signature and stake.
    pub fn seat_forfeit(
        &self,
        tier: u32,
        seat: &str,
    ) -> Option<(Transaction, [u8; 32], String, Bond)> {
        let t = self.tiers.get(&tier)?;
        let (stake, sigs) = t.forfeits.get(seat)?;
        let (tx, d) = stake.penalty_tx(
            &self.oracle,
            seat_fee(self.base_fee, tier),
            t.refund.as_ref()?,
        );
        Some((tx, d, sigs.last()?.clone(), stake.clone()))
    }

    pub fn seizure_spk(&self) -> Option<ScriptBuf> {
        seizure_tree(&self.archivists, &self.oracle, &self.parties_key).map(|t| t.0.script_pubkey())
    }

    /// The review draw of a closed case (§10.3): the block whose hash seeds it, and whether it selected
    /// the case. None while the case has no committed verdict or the block is not yet mined.
    /// The block a review stage is drawn from, fixed by the chain: stage 1 draw_blocks() after the
    /// review draw (or after the flag, for a flagged case the draw passed over); each later stage
    /// draw_blocks() after the one before had its full commit and reveal windows.
    pub fn stage_draw_height(&self, a: &Alerted, rpc: &Rpc, hist: &[Envelope], st: u32) -> Option<u32> {
        let base = if st == 1 {
            let d = self.review_draw(a, rpc)?;
            if d.drawn {
                d.height
            } else {
                let f = self.flagger.as_ref()?;
                hist.iter()
                    .filter(|e| e.msg.case_id() == Some(a.case_hex.as_str()) && &e.sender == f)
                    .find_map(|e| matches!(e.msg, Msg::Flag { .. }).then_some(e.height))?
                    .max(d.height)
            }
        } else {
            let prev = self.reviews.get(&(REVIEW_BASE + st - 1))?;
            prev.seat_height.values().copied().min()? + a.template.commit_blocks + a.template.reveal_blocks
        };
        Some(base + crate::draw_blocks())
    }

    pub fn review_draw(&self, a: &Alerted, rpc: &Rpc) -> Option<ReviewDraw> {
        let (ft, fv) = self.final_ruling()?;
        // closed at the last tier commitment on chain (a later tier that hung or lapsed included)
        let close = self
            .tiers
            .values()
            .filter_map(|t| t.commit_txid.as_ref().and_then(|x| rpc.tx_height(x)))
            .max()?;
        let height = close + a.template.review_delay.max(1);
        if rpc.height() < height + crate::draw_depth() {
            return None;
        }
        let hash = rpc.block_hash(height)?;
        let fk = verdict_key(&fv);
        let split = self.tiers[&ft]
            .reveals
            .iter()
            .any(|x| verdict_key(&x.1) != fk)
            || self.tiers[&ft].reveals.len() < self.tiers[&ft].seats.len();
        let value: u64 = a.template.pots.iter().sum();
        let rate_bp = match a.template.review_pct {
            None => review_rate_bp(value, split),
            Some(p) => p.min(100) as u64 * 100,
        };
        Some(ReviewDraw {
            height,
            split,
            rate_bp,
            drawn: review_drawn(&self.case, &hash, rate_bp),
        })
    }

    /// Where the case's staged review stands (§10.3): each stage reviews the case afresh; one that finds
    /// the final verdict (or no verdict at 80%) clears it; three that find the same other verdict confirm.
    pub fn review_state(&self, a: &Alerted, rpc: &Rpc) -> ReviewState {
        let Some(dr) = self.review_draw(a, rpc) else {
            return ReviewState::NotDrawn;
        };
        let Some((_, fv)) = self.final_ruling() else {
            return ReviewState::NotDrawn;
        };
        if !dr.drawn && self.flagger.is_none() {
            return ReviewState::NotDrawn;
        }
        let fk = verdict_key(&fv);
        let mut prev: Option<Vec<u8>> = None;
        for st in 1..=REVIEW_STAGES {
            let Some(t) = self.reviews.get(&(REVIEW_BASE + st)) else {
                // a pool too small to draw a first panel from those who did not sit on the case: no
                // review can be held, and the verdict stands (a prototype-scale case)
                if st == 1 && self.review_pool < REVIEW_PANEL {
                    return ReviewState::Cleared(0);
                }
                return ReviewState::Pending(st);
            };
            if !t.committed || (self.flagger.is_some() && !t.fee_paid) {
                return ReviewState::Pending(st);
            }
            let Some(v) = t.verdict() else {
                return ReviewState::Cleared(st);
            };
            let k = verdict_key(&v);
            if k == fk || prev.as_ref().is_some_and(|p| *p != k) {
                return ReviewState::Cleared(st);
            }
            if st == REVIEW_STAGES {
                return ReviewState::Confirmed(v);
            }
            prev = Some(k);
        }
        ReviewState::Cleared(REVIEW_STAGES)
    }

    /// Each seat's case unit: (tier, arbitrator, unit). Every unit the replay verified.
    pub fn units(&self) -> Vec<(u32, String, Bond)> {
        let mut v: Vec<(u32, String, Bond)> = self
            .tiers
            .iter()
            .flat_map(|(k, t)| {
                t.forfeits
                    .iter()
                    .map(move |(s, (b, _))| (*k, s.clone(), b.clone()))
            })
            .collect();
        v.sort_by(|a, b| (a.0, &a.1).cmp(&(b.0, &b.1)));
        v
    }

    /// The units the oracle may release now: the case is closed, the draw passed it over, and the seat
    /// owes no penalty (a penalised unit's remainder is already returned under the bond's script by
    /// its forfeiture) and was not forfeit for a missed deadline. Each with its release digest.
    pub fn releasable(
        &self,
        a: &Alerted,
        rpc: &Rpc,
    ) -> Vec<(u32, String, Bond, Transaction, [u8; 32])> {
        let Some(dr) = self.review_draw(a, rpc) else {
            return vec![];
        };
        // drawn: held until the staged review clears the case, or, if it confirms a different
        // verdict, released except for those who voted for the overturned one (§10.3)
        let state = self.review_state(a, rpc);
        if dr.drawn && !matches!(state, ReviewState::Cleared(_) | ReviewState::Confirmed(_)) {
            return vec![];
        }
        let seized: Vec<(u32, String)> = match state {
            ReviewState::Confirmed(_) => self.overturned_voters(),
            _ => vec![],
        };
        let pens = self.penalties();
        self.units()
            .into_iter()
            .filter(|(k, s, _)| {
                !pens.iter().any(|p| p.tier == *k && p.arbitrator == *s)
                    && !self.tiers[k].forfeited.contains(s)
                    && !seized.iter().any(|x| x.0 == *k && x.1 == *s)
            })
            .map(|(k, s, b)| {
                let (tx, d) = b.release_tx(&self.oracle);
                (k, s, b, tx, d)
            })
            .collect()
    }

    /// The final ruling: the last tier that reached two thirds (hung tiers above it decide nothing).
    pub fn final_ruling(&self) -> Option<(u32, Ballot)> {
        self.tiers
            .iter()
            .rev()
            .find_map(|(k, t)| t.verdict().map(|v| (*k, v)))
    }

    /// Every incoherent vote, in every tier, settled against the final ruling (§10.4): the isolation
    /// measured on the final tier's split, rounded down to the half fee, at that vote's own seat fee.
    pub fn penalties(&self) -> Vec<Penalty> {
        let (Some((ft, fv)), Some(spk)) = (self.final_ruling(), self.seizure_spk()) else {
            return vec![];
        };
        let fk = verdict_key(&fv);
        let fin = &self.tiers[&ft];
        let n_f = fin.seats.len();
        let mut out = vec![];
        for (k, t) in &self.tiers {
            if !t.committed {
                continue;
            }
            // each incoherent vote, and each commitment never revealed (charged at the isolation penalty);
            // a hung tier (no two thirds) has no dissenters, only its silent seats (§10.5)
            let hung = t.verdict().is_none();
            let mut owed: Vec<(String, f64)> = vec![];
            for (arb, v) in t.reveals.iter().filter(|_| !hung) {
                let vk = verdict_key(v);
                if vk == fk {
                    continue;
                }
                let agree = fin
                    .reveals
                    .iter()
                    .filter(|x| verdict_key(&x.1) == vk)
                    .count();
                owed.push((arb.clone(), penalty_factor(n_f, agree.max(1))));
            }
            for c in &t.committers {
                if t.seats.contains(c) && !t.reveals.iter().any(|x| &x.0 == c) {
                    owed.push((c.clone(), penalty_factor(n_f, 1)));
                }
            }
            for (arb, factor) in owed {
                let d = t.momentum.get(&arb).copied().unwrap_or(0.0);
                let step = step_of(factor * multiplier(d));
                let fee = seat_fee(self.base_fee, *k);
                let Some((bond, pre)) = t.forfeits.get(&arb) else {
                    continue;
                };
                let Some(i) = steps_upto(max_step(d)).iter().position(|x| *x == step) else {
                    continue;
                };
                let amount = step * fee / 10;
                let (tx, digest) = bond.penalty_tx(&self.oracle, amount, &spk);
                out.push(Penalty {
                    arbitrator: arb.clone(),
                    tier: *k,
                    step,
                    amount,
                    bond: bond.clone(),
                    pre: pre[i].clone(),
                    tx,
                    digest,
                });
            }
        }
        // the loser pays (§9): an attendee whose ballot the final ruling went against pays one tier-1
        // panel fee from its bond, pre-signed at acceptance; tier 0 in the list
        // "against its ballot" is on a disputed point: an answer the attendees disagreed on, where
        // this attendee's answer is not the ruling's; a seat that never revealed pays too, so silence
        // is never the cheaper course (review N5)
        let lf = self.loser_fee;
        let answers = |b: &Ballot| -> Vec<String> {
            let mut v: Vec<String> = (0..self.seats_n)
                .map(|i| {
                    b.acts
                        .iter()
                        .find(|a| a.seat as usize == i)
                        .map_or("None".into(), |a| format!("{:?}", a.class))
                })
                .collect();
            v.push(b.outcome_achieved.to_string());
            v.push(b.misuse.to_string());
            v
        };
        let ruling = answers(&fv);
        let all: Vec<Vec<String>> = self.ballots.values().map(|b| answers(b)).collect();
        let disputed: Vec<usize> = (0..ruling.len())
            .filter(|&i| all.iter().any(|x| x[i] != all[0][i]))
            .collect();
        // a responder the final ruling finds at fault forfeits its bond at the finding's severity
        // (§11.8), by the forfeiture it pre-signed at acceptance; it covers its loser-pays fee
        let mut faulted: Vec<&str> = vec![];
        let mut owes_fee: Vec<&str> = vec![];
        let cf = canon_faults(&fv);
        for f in &cf {
            let Some(w) = self.parties.get(f.seat as usize + 1).map(|p| p.0.as_str()) else { continue };
            let Some((b, pre)) = self.loser_pays.get(w) else { continue };
            let i = fault_sig_index(f.severity);
            let (tx, digest) = fault_tx(b, &self.oracle, f.severity, &spk);
            let Some(sig) = pre.get(i).filter(|sg| schnorr_ok(&b.scoped, &digest, sg)) else { continue };
            if faulted.contains(&w) {
                continue;
            }
            // a finding that would take less than the loser-pays fee takes the fee instead (below)
            if fault_amount(b.value, f.severity) < lf.min(b.value) {
                owes_fee.push(w);
                continue;
            }
            faulted.push(w);
            out.push(Penalty {
                arbitrator: w.to_string(),
                tier: 0,
                step: fault_amount(b.value, f.severity),
                amount: fault_amount(b.value, f.severity),
                bond: b.clone(),
                pre: sig.clone(),
                tx,
                digest,
            });
        }
        for (w, (b, pre)) in &self.loser_pays {
            let pre = &pre[0];
            if faulted.contains(&w.as_str()) {
                continue;
            }
            let lost = match self.ballots.get(w) {
                None => true,
                Some(mine) => {
                    let m = answers(mine);
                    (verdict_key(mine) != fk && disputed.iter().any(|&i| m[i] != ruling[i]))
                        // an accusation the final ruling does not bear out is a lost point like any
                        // other: whoever named a seat at fault that the ruling clears pays the panel
                        // (§9), so two seats cannot veto a settlement for nothing
                        || canon_faults(mine).iter().any(|f| !cf.iter().any(|x| x.seat == f.seat))
                }
            } || owes_fee.contains(&w.as_str());
            // only a vote that did not settle on its own makes a loser: a majority escalating a vote
            // that already had 80% pays its own panel (review)
            if !lost || lf == 0 || self.attending_settled {
                continue;
            }
            let (tx, digest) = loser_pays_tx(b, &self.oracle, lf, &spk);
            out.push(Penalty {
                arbitrator: w.clone(),
                tier: 0,
                step: 0,
                amount: lf.min(b.value),
                bond: b.clone(),
                pre: pre.clone(),
                tx,
                digest,
            });
        }
        // the amount is what the transaction pays the seizure output (a sub-dust remainder folded in
        // makes it the whole bond), never the nominal one (review N9)
        for p in &mut out {
            if let Some(o) = p.tx.output.iter().find(|o| o.script_pubkey == spk) {
                p.amount = o.value.to_sat();
            }
        }
        // one order for everyone (reveals arrive in different orders at different nodes): the
        // distribution spends these outputs in this order, so its txid depends on it
        out.sort_by(|x, y| (x.tier, &x.arbitrator).cmp(&(y.tier, &y.arbitrator)));
        out
    }

    /// What seat `i` receives from the pots when the case settles by verdict `v` (§12: the measure of
    /// a harmed responder's loss).
    pub fn pot_share(&self, v: &Ballot, i: usize) -> u64 {
        use bitaid_core::endings::EndingKind;
        let crate::settle::Decision::Settled(e) =
            crate::settle::decide_panel(self.seats_n, self.pots, &self.template, v)
        else {
            return 0;
        };
        let step = bitaid_core::endings::step_for(self.seats_n) as u64;
        e.iter()
            .map(|x| match &x.kind {
                EndingKind::Split(w) | EndingKind::GoodFaith(w) => {
                    self.pots[x.pot.index()] * w.get(i).copied().unwrap_or(0) as u64 * step / 100
                }
                _ => 0,
            })
            .sum()
    }

    /// Arbitrators of lower tiers who voted as the final ruling where their own panel did not.
    pub fn vindicated(&self) -> Vec<(String, ScriptBuf)> {
        let Some((ft, fv)) = self.final_ruling() else {
            return vec![];
        };
        let fk = verdict_key(&fv);
        let mut out = vec![];
        for (k, t) in &self.tiers {
            if *k >= ft || !t.committed {
                continue;
            }
            if t.verdict().map(|v| verdict_key(&v) == fk).unwrap_or(false) {
                continue;
            }
            for (arb, v) in &t.reveals {
                if verdict_key(v) == fk {
                    if let Some(b) = t.offers.get(arb) {
                        out.push((arb.clone(), b.payout.clone()));
                    }
                }
            }
        }
        out.sort();
        out.dedup();
        out
    }

    /// The seizure output's distribution (§12) over the penalties' outputs. No restitution is due when
    /// an appeal corrected a verdict before it paid out, so: half to the vindicated dissenters; then the
    /// appeal subsidy of §10.4, refunding a re-roll's fees to whoever paid them when the verdict it
    /// re-rolled was contested (none after a unanimous panel); the excess to the party that paid for the
    /// tier that overturned a verdict, or, if none was overturned, to the case's archivists.
    pub fn distribution(&self, pens: &[Penalty]) -> Option<(Transaction, Vec<TxOut>)> {
        let spk = self.seizure_spk()?;
        let total: u64 = pens.iter().map(|p| p.amount).sum();
        if total == 0 {
            return None;
        }
        let mut outs: Vec<(u64, ScriptBuf)> = vec![];
        let vind = self.vindicated();
        let mut left = total;
        // a party's payout script, or that of a dissenter who bought a re-roll (from its offer below)
        let payout_of = |who: &str| {
            self.parties
                .iter()
                .find(|p| p.0 == who)
                .and_then(|p| p.1.clone())
                .or_else(|| {
                    self.tiers.iter().find_map(|(k, t)| {
                        (t.challenger && t.escalator == who)
                            .then(|| self.tiers.get(&(k - 1)).and_then(|p| p.offers.get(who)))
                            .flatten()
                            .map(|b| b.payout.clone())
                    })
                })
        };
        // a fellow responder harmed by the one at fault is repaid its loss first (§12): its share of
        // the pots as the final ruling settles them, never above what the accused forfeited
        // (one finding per accused, the gravest; an accused never pays a harmed seat more than it
        // forfeited, and what the harmed seat took is no longer there for anyone else)
        let mut at_fault: Vec<String> = vec![];
        let mut repaid: u64 = 0;
        if let Some((_, fv)) = self.final_ruling() {
            for f in canon_faults(&fv) {
                let Some(acc) = self.parties.get(f.seat as usize + 1) else { continue };
                at_fault.push(acc.0.clone());
                let Some(h) = f.harmed.filter(|h| *h != f.seat) else { continue };
                let Some(p) = self.parties.get(h as usize + 1).and_then(|p| p.1.clone()) else { continue };
                let forfeited: u64 = pens.iter().filter(|x| x.tier == 0 && x.arbitrator == acc.0).map(|x| x.amount).sum();
                let x = self.pot_share(&fv, h as usize).min(forfeited).min(left);
                if x > 0 {
                    outs.push((x, p));
                    left -= x;
                    repaid += x;
                }
            }
        }
        // the loser pays (§9): what the losing attendees forfeited goes first to whoever paid the
        // tier-1 panel, up to what that panel cost it, unless the payer is among the losers (review N4)
        let losers: Vec<&str> = pens.iter().filter(|p| p.tier == 0).map(|p| p.arbitrator.as_str()).collect();
        let lp: u64 = pens.iter().filter(|p| p.tier == 0).map(|p| p.amount).sum::<u64>().saturating_sub(repaid).min(left);
        if lp > 0 {
            if let Some(t1) = self.tiers.get(&1) {
                if t1.fee_paid && !losers.contains(&t1.escalator.as_str()) {
                    if let Some(p) = payout_of(&t1.escalator) {
                        let x = lp.min(seat_fee(self.base_fee, 1) * t1.seats.len() as u64);
                        outs.push((x, p));
                        left -= x;
                    }
                }
            }
        }
        if !vind.is_empty() {
            let each = left / 2 / vind.len() as u64;
            for (_, p) in &vind {
                outs.push((each, p.clone()));
                left -= each;
            }
        }
        let fk = verdict_key(&self.final_ruling()?.1);
        let (ft, fv) = self.final_ruling()?;
        // the verdict standing before tier k, and whether its panel was split
        let before = |k: u32| -> (Option<Ballot>, bool) {
            for (_, t) in self.tiers.range(..k).rev() {
                if let Some(v) = t.verdict() {
                    let key = verdict_key(&v);
                    let split = t.reveals.iter().any(|x| verdict_key(&x.1) != key);
                    return (Some(v), split);
                }
            }
            (None, true)
        };
        for (k, t) in &self.tiers {
            if *k < 2 || !t.fee_paid || left == 0 || !before(*k).1 {
                continue;
            }
            // a dissenter's fees are refunded only if the larger panel agreed with it
            if t.challenger && !vind.iter().any(|v| v.0 == t.escalator) {
                continue;
            }
            // a seat the final ruling finds at fault is refunded nothing out of what it forfeited
            if at_fault.contains(&t.escalator) {
                continue;
            }
            let Some(p) = payout_of(&t.escalator) else {
                continue;
            };
            let paid = seat_fee(self.base_fee, *k) * t.seats.len() as u64;
            let x = paid.min(left);
            outs.push((x, p));
            left -= x;
        }
        if left > 0 {
            let overturned = before(ft)
                .0
                .map(|v| verdict_key(&v) != verdict_key(&fv))
                .unwrap_or(false);
            // the excess to the parties the overturned verdict harmed: those it classed below what the
            // final ruling finds (Intervention above Documentation above none)
            let rank = |c: &wire::Class| match c {
                wire::Class::Intervention => 2,
                wire::Class::Documentation => 1,
                wire::Class::None => 0,
            };
            let harmed: Vec<ScriptBuf> = match before(ft).0.filter(|_| overturned) {
                Some(old) => fv
                    .acts
                    .iter()
                    .filter(|a| {
                        old.acts
                            .iter()
                            .find(|o| o.seat == a.seat)
                            .map(|o| rank(&a.class) > rank(&o.class))
                            .unwrap_or(false)
                    })
                    .filter_map(|a| {
                        self.parties
                            .get(a.seat as usize + 1)
                            // never a seat the ruling itself finds at fault
                            .filter(|p| !at_fault.contains(&p.0))
                            .and_then(|p| p.1.clone())
                    })
                    .collect(),
                None => vec![],
            };
            match harmed.is_empty() {
                false => {
                    let each = left / harmed.len() as u64;
                    for p in harmed {
                        outs.push((each, p));
                    }
                }
                true => {
                    let mut ks: Vec<XOnlyPublicKey> = self
                        .archivists
                        .iter()
                        .filter_map(|a| wire::xonly(a))
                        .collect();
                    ks.sort();
                    ks.dedup();
                    let secp = Secp256k1::verification_only();
                    let each = left / ks.len().max(1) as u64;
                    for k in ks {
                        outs.push((each, ScriptBuf::new_p2tr(&secp, k, None)));
                    }
                }
            }
        }
        let _ = fk;
        Some(self.dist_tx(pens, outs, &spk))
    }

    /// A distribution of the seizure output: `outs` merged one per recipient, spending the outputs of
    /// `pens` in their order.
    fn dist_tx(
        &self,
        pens: &[Penalty],
        outs: Vec<(u64, ScriptBuf)>,
        spk: &ScriptBuf,
    ) -> (Transaction, Vec<TxOut>) {
        // one output per recipient
        let mut merged: Vec<(u64, ScriptBuf)> = vec![];
        for (v, s) in outs {
            match merged.iter_mut().find(|m| m.1 == s) {
                Some(m) => m.0 += v,
                None => merged.push((v, s)),
            }
        }
        let mut output: Vec<TxOut> = merged
            .iter()
            .filter(|(v, _)| *v > 0)
            .map(|(v, s)| txbuild::txout(*v, s.clone()))
            .collect();
        output.push(txbuild::txout(0, bitaid_core::scripts::p2a()));
        let input = pens
            .iter()
            .map(|p| TxIn {
                previous_output: OutPoint {
                    txid: p.tx.compute_txid(),
                    vout: 0,
                },
                sequence: Sequence(0xffff_fffd),
                ..Default::default()
            })
            .collect();
        let tx = Transaction {
            version: txbuild::VERSION,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input,
            output,
        };
        let prev = pens
            .iter()
            .map(|p| txbuild::txout(p.amount, spk.clone()))
            .collect();
        (tx, prev)
    }

    /// Who may not sit on the next review stage: every seat of the case's tiers (replaced ones too)
    /// and of its earlier review stages.
    pub fn review_excluded(&self) -> std::collections::HashSet<String> {
        self.tiers
            .values()
            .chain(self.reviews.values())
            .flat_map(|t| t.seats.iter().chain(t.forfeited.iter()).cloned())
            .collect()
    }

    /// A confirmed review whose every stage found its verdict at 80%: only such a review takes an
    /// entry bond or expels (§10.3, two bars). Two thirds at each stage overturns and pays restitution
    /// from the units; the higher bar guards the livelihood.
    pub fn review_strong(&self) -> bool {
        let ReviewState::Confirmed(cv) = &self.review else {
            return false;
        };
        let ck = verdict_key(cv);
        (1..=REVIEW_STAGES).all(|st| {
            self.reviews.get(&(REVIEW_BASE + st)).is_some_and(|t| {
                let v: Vec<Ballot> = t.reveals.iter().map(|x| x.1.clone()).collect();
                supermajority_of(t.seats.len(), &v, 4, 5).is_some_and(|b| verdict_key(&b) == ck)
            })
        })
    }

    /// Who voted, on any arbitration tier, for the verdict a confirmed review overturned (§12).
    pub fn overturned_voters(&self) -> Vec<(u32, String)> {
        let (ReviewState::Confirmed(_), Some((_, fv))) = (&self.review, self.final_ruling()) else {
            return vec![];
        };
        let fk = verdict_key(&fv);
        let mut v: Vec<(u32, String)> = self
            .tiers
            .iter()
            .flat_map(|(k, t)| {
                t.reveals
                    .iter()
                    .filter(|x| verdict_key(&x.1) == fk)
                    .map(move |x| (*k, x.0.clone()))
            })
            .collect();
        v.sort();
        v
    }

    /// The forfeitures a confirmed review calls for (§10.2, B.1): the whole case unit of everyone who
    /// voted for the overturned verdict, by the forfeiture each pre-signed for that purpose.
    pub fn review_penalties(&self) -> Vec<Penalty> {
        let Some(spk) = self.seizure_spk() else {
            return vec![];
        };
        let mut out = vec![];
        for (k, w) in self.overturned_voters() {
            if self.released.iter().any(|x| x.0 == k && x.1 == w) {
                continue;
            }
            let Some((bond, pre)) = self.tiers[&k].forfeits.get(&w) else {
                continue;
            };
            // pre-signed in order: the steps, the whole unit, the seat forfeiture
            let Some(sig) = pre.len().checked_sub(2).and_then(|i| pre.get(i)) else {
                continue;
            };
            let (tx, digest) = bond.penalty_tx(&self.oracle, bond.value, &spk);
            out.push(Penalty {
                arbitrator: w,
                tier: k,
                step: 0,
                amount: bond.value,
                bond: bond.clone(),
                pre: sig.clone(),
                tx,
                digest,
            });
        }
        out
    }

    /// After a confirmed review, the entry bonds of those who voted for the overturned verdict (§10.8,
    /// B.1): (arbitrator, bond, pre-signature, seizure, its digest, move to the seizure output, its digest).
    #[allow(clippy::type_complexity)]
    pub fn entry_seizures(
        &self,
        a: &Alerted,
        r: &Rostered,
    ) -> Vec<(
        String,
        Bond,
        String,
        Transaction,
        [u8; 32],
        Transaction,
        [u8; 32],
        u64,
        Vec<XOnlyPublicKey>,
    )> {
        let Some(spk) = self.seizure_spk() else {
            return vec![];
        };
        let voters = self.overturned_voters();
        let n = voters.len().max(1) as u64;
        let due = self.due_before_excess(a, r);
        let mut who: Vec<(String, Option<u64>)> = vec![];
        for (k, w) in &voters {
            if self.prior_overturns.get(w).copied().unwrap_or(0) >= 1 && self.review_strong() {
                // a second confirmed overturn, this one at 80% at every stage: the whole entry bond,
                // and the arbitrator is out (§12)
                who.push((w.clone(), None));
            } else if self.released.iter().any(|x| x.0 == *k && x.1 == *w) {
                // a first offense found after the unit was released: the entry bond pays what the
                // unit would have paid before the excess, its share of it, and keeps the rest
                let unit = self.tiers[k]
                    .forfeits
                    .get(w)
                    .map(|x| x.0.value)
                    .unwrap_or(0);
                who.push((w.clone(), Some(due.div_ceil(n).min(unit))));
            }
        }
        who.sort();
        who.dedup_by(|x, y| x.0 == y.0);
        who.into_iter()
            .filter_map(|(w, part)| {
                let (b, pre, holders) = self.entries.get(&w)?.clone();
                let (tx, d) = b.entry_seizure(&self.oracle, &holders)?;
                let keep = part.map(|p| (p, b.tree(&self.oracle).script_pubkey()));
                let (mv, d2) =
                    holding_move(&self.oracle, &holders, &b.cold, &tx, b.value, &spk, keep)?;
                let paid = part.map(|p| p.min(b.value)).unwrap_or(b.value);
                Some((w, b, pre, tx, d, mv, d2, paid, holders))
            })
            .collect()
    }

    /// What a confirmed review's distribution owes before its excess (§12 items 1–5).
    pub fn due_before_excess(&self, a: &Alerted, r: &Rostered) -> u64 {
        let (ReviewState::Confirmed(cv), Some((_, fv))) = (&self.review, self.final_ruling())
        else {
            return 0;
        };
        let before = Self::paid_under(a, r, &fv);
        let after = Self::paid_under(a, r, cv);
        let mut due: u64 = after
            .iter()
            .map(|(x, s)| {
                let had = before.iter().find(|y| y.1 == *s).map(|y| y.0).unwrap_or(0);
                x.saturating_sub(had)
            })
            .sum();
        let ck = verdict_key(cv);
        let first = self.penalties();
        for (k, t) in &self.tiers {
            for (w, v) in &t.reveals {
                if verdict_key(v) == ck {
                    due += first
                        .iter()
                        .filter(|p| p.tier == *k && p.arbitrator == *w)
                        .map(|p| p.amount)
                        .sum::<u64>()
                        + seat_fee(self.base_fee, *k);
                }
            }
        }
        for t in self.reviews.values() {
            due += 3
                * self.base_fee
                * t.reveals.iter().filter(|x| verdict_key(&x.1) == ck).count() as u64;
        }
        due + self.flagger_due() + crate::sats(RETENTION_SATS)
    }

    /// The flagger's stake back with the review premium, owed only when the review confirmed (§12).
    pub fn flagger_due(&self) -> u64 {
        if self.flagger.is_none() {
            return 0;
        }
        let paid: u64 = self
            .reviews
            .values()
            .filter(|t| t.fee_paid)
            .map(|t| t.seats.len() as u64 * self.base_fee)
            .sum();
        paid + 3 * self.base_fee
    }

    pub fn review_inputs(&self, a: &Alerted, r: &Rostered) -> Vec<Penalty> {
        let mut v = self.review_penalties();
        for (w, b, pre, _, _, mv, d2, paid, _) in self.entry_seizures(a, r) {
            v.push(Penalty {
                arbitrator: w,
                tier: 0,
                step: 0,
                amount: paid,
                bond: b,
                pre,
                tx: mv,
                digest: d2,
            });
        }
        v
    }

    /// What each payout script receives under `v` (the attending-vote payout rules, §9).
    fn paid_under(a: &Alerted, r: &Rostered, v: &Ballot) -> Vec<(u64, ScriptBuf)> {
        let parties = crate::case::terms(a, r).parties;
        let crate::settle::Decision::Settled(ends) =
            crate::settle::decide_panel(r.seats.len(), a.template.pots, &a.template, v)
        else {
            return vec![];
        };
        let mut m: Vec<(u64, ScriptBuf)> = vec![];
        for e in ends {
            for (x, s) in
                bitaid_core::payouts::outputs(&e, a.template.pots[e.pot.index()], &parties)
            {
                match m.iter_mut().find(|y| y.1 == s) {
                    Some(y) => y.0 += x,
                    None => m.push((x, s)),
                }
            }
        }
        m
    }

    /// The distribution of what a confirmed review seized (§12): restitution first — each party paid
    /// the difference between what the overturned verdict paid it and what the confirmed one would
    /// have — then the dissenters who voted for the confirmed verdict, their earlier penalty refunded
    /// with the fee it cost them; then the review premium, 3× the base fee to each reviewer whose
    /// finding was confirmed; retention of the case's evidence; the excess to the harmed parties.
    pub fn review_distribution(
        &self,
        a: &Alerted,
        r: &Rostered,
        pens: &[Penalty],
    ) -> Option<(Transaction, Vec<TxOut>)> {
        let ReviewState::Confirmed(cv) = &self.review else {
            return None;
        };
        let spk = self.seizure_spk()?;
        let (_, fv) = self.final_ruling()?;
        let mut left: u64 = pens.iter().map(|p| p.amount).sum();
        if left == 0 {
            return None;
        }
        let mut outs: Vec<(u64, ScriptBuf)> = vec![];
        let before = Self::paid_under(a, r, &fv);
        let after = Self::paid_under(a, r, cv);
        // the excess goes only to a harmed party that had exhausted the appeals worth making: one for
        // which the next re-roll would have cost more than the amount in dispute (§12); a party that
        // could still have appealed is made whole, and the excess keeps the case's evidence instead
        let (ft, _) = self.final_ruling()?;
        let next_cost = seat_fee(self.base_fee, ft + 1) * panel_size(ft + 1) as u64;
        let mut harmed: Vec<ScriptBuf> = vec![];
        for (x, s) in &after {
            let had = before.iter().find(|y| y.1 == *s).map(|y| y.0).unwrap_or(0);
            if *x > had {
                let owed = (*x - had).min(left);
                outs.push((owed, s.clone()));
                left -= owed;
                if next_cost > *x - had {
                    harmed.push(s.clone());
                }
            }
        }
        // the dissenters vindicated by the review: their penalty back, and the fee it cost them
        let ck = verdict_key(cv);
        let first = self.penalties();
        for (k, t) in &self.tiers {
            for (w, v) in &t.reveals {
                if verdict_key(v) != ck || left == 0 {
                    continue;
                }
                let Some(b) = t.offers.get(w) else { continue };
                let back = first
                    .iter()
                    .filter(|p| p.tier == *k && p.arbitrator == *w)
                    .map(|p| p.amount)
                    .sum::<u64>()
                    + seat_fee(self.base_fee, *k);
                let x = back.min(left);
                outs.push((x, b.payout.clone()));
                left -= x;
            }
        }
        // the premium to the reviewers whose finding was confirmed
        for t in self.reviews.values() {
            for (w, v) in &t.reveals {
                if verdict_key(v) != ck || left == 0 {
                    continue;
                }
                let Some(b) = t.offers.get(w) else { continue };
                let x = (3 * self.base_fee).min(left);
                outs.push((x, b.payout.clone()));
                left -= x;
            }
        }
        // the flagger: its stake back with the premium (§12 item 3)
        if let (Some(fl), true) = (self.flagger.as_ref(), left > 0) {
            if let Some(b) = self.reviews.values().next().and_then(|t| t.offers.get(fl)) {
                let x = self.flagger_due().min(left);
                outs.push((x, b.payout.clone()));
                left -= x;
            }
        }
        // retention of the case's evidence (§12 item 5): a case overturned on review is precedent and
        // review material, and its seizure pays for keeping it, to the base-slot archivists
        let keep = crate::sats(RETENTION_SATS).min(left);
        if keep > 0 {
            let secp = Secp256k1::verification_only();
            let ks: Vec<ScriptBuf> = self
                .archivists
                .iter()
                .filter_map(|x| wire::xonly(x))
                .map(|k| ScriptBuf::new_p2tr(&secp, k, None))
                .collect();
            if !ks.is_empty() {
                let each = keep / ks.len() as u64;
                for k in ks {
                    outs.push((each, k));
                    left -= each;
                }
            }
        }
        if left > 0 {
            let to = if harmed.is_empty() {
                let secp = Secp256k1::verification_only();
                self.archivists
                    .iter()
                    .filter_map(|x| wire::xonly(x))
                    .map(|k| ScriptBuf::new_p2tr(&secp, k, None))
                    .collect()
            } else {
                harmed
            };
            let each = left / to.len().max(1) as u64;
            for s in to {
                outs.push((each, s));
            }
        }
        Some(self.dist_tx(pens, outs, &spk))
    }

    /// Every co-signature a confirmed review calls for: the whole-unit forfeitures and each input of
    /// their distribution, as (txid, input, digest, description).
    pub fn review_due(
        &self,
        a: &Alerted,
        r: &Rostered,
    ) -> Vec<(bitcoin::Txid, usize, [u8; 32], String)> {
        let pens = self.review_inputs(a, r);
        let mut out: Vec<(bitcoin::Txid, usize, [u8; 32], String)> = self
            .review_penalties()
            .iter()
            .map(|p| {
                (
                    p.tx.compute_txid(),
                    0,
                    p.digest,
                    format!(
                        "the forfeiture of the whole {}-sat tier-{} unit of {} (review confirmed)",
                        p.amount,
                        p.tier,
                        crate::pre(&p.arbitrator, 8)
                    ),
                )
            })
            .collect();
        for (w, b, _, tx, d, mv, d2, _, _) in self.entry_seizures(a, r) {
            out.push((
                tx.compute_txid(),
                0,
                d,
                format!(
                    "the seizure of {}'s whole entry bond ({} sats) pre-signed at joining (review confirmed)",
                    crate::pre(&w, 8),
                    b.value
                ),
            ));
            out.push((
                mv.compute_txid(),
                0,
                d2,
                format!(
                    "the move of {}'s seized entry bond into the case's seizure output",
                    crate::pre(&w, 8)
                ),
            ));
        }
        if let Some((dist, prev)) = self.review_distribution(a, r, &pens) {
            for i in 0..dist.input.len() {
                if let Some(d) = self.distribution_digest(&dist, &prev, i) {
                    out.push((
                        dist.compute_txid(),
                        i,
                        d,
                        format!("input {i} of the review seizure's distribution"),
                    ));
                }
            }
        }
        out
    }

    /// The digest of input `i` of the distribution (DISTRIBUTE leaf).
    pub fn distribution_digest(
        &self,
        tx: &Transaction,
        prev: &[TxOut],
        i: usize,
    ) -> Option<[u8; 32]> {
        let (t, _) = seizure_tree(&self.archivists, &self.oracle, &self.parties_key)?;
        Some(txbuild::scriptspend_digest(
            tx,
            i,
            prev,
            &t.scripts[seizure_leaf::DISTRIBUTE],
        ))
    }

    /// Completes input `i` of the distribution: the oracle's co-signature and the archivists' signatures.
    pub fn distribution_witness(
        &self,
        tx: &mut Transaction,
        i: usize,
        osig: &[u8; 64],
        arch: &HashMap<XOnlyPublicKey, Vec<u8>>,
    ) -> Option<()> {
        let (t, pol) = seizure_tree(&self.archivists, &self.oracle, &self.parties_key)?;
        let mut items: Vec<Vec<u8>> = vec![osig.to_vec()];
        if pol.devices.len() == 1 {
            items.push(arch.get(&pol.devices[0])?.clone());
        } else {
            let mut given = 0;
            for d in pol.devices.iter().rev() {
                match arch.get(d).filter(|_| given < pol.threshold) {
                    Some(s) => {
                        items.push(s.clone());
                        given += 1;
                    }
                    None => items.push(vec![]),
                }
            }
            if given < pol.threshold {
                return None;
            }
        }
        items.push(t.scripts[seizure_leaf::DISTRIBUTE].to_bytes());
        items.push(t.control(seizure_leaf::DISTRIBUTE).serialize());
        tx.input[i].witness = Witness::from_slice(&items);
        Some(())
    }
}

// =================================================================== momentum across cases

/// One tier (or review stage) `k` of `case` as the log records it: offers, the draw, replacements,
/// fees, reveals, the on-chain commitment and the seats' pre-signed forfeitures (verified later).
#[allow(clippy::too_many_arguments)]
fn read_tier(
    mine: &[&Envelope],
    case: &str,
    k: u32,
    escalator: &str,
    challenger: bool,
    base_fee: u64,
    rpc: &Rpc,
    registry: Option<&HashMap<String, Bond>>,
    payer: Option<&str>,
    commit_blocks: u32,
    oracle: &XOnlyPublicKey,
    // tier 1: the height the chain gives its opening (the market took the case up), in place of the
    // height its escalator stated
    anchor: Option<u32>,
    // the escalation window, in blocks: commitments confirmed within it of the first compete
    contest: u32,
) -> Tier {
    let mut t = Tier {
        escalator: escalator.to_string(),
        challenger,
        ..Default::default()
    };
    // a review stage is drawn from the whole pool, not from offers for it (§10.3)
    if let Some(reg) = registry {
        t.offers = reg.clone();
    }
    let mut vcommits: HashMap<String, String> = HashMap::new();
    let mut commit_h: HashMap<String, u32> = HashMap::new();
    for e in mine {
        let s = &e.sender;
        match &e.msg {
            Msg::SeatOffer { tier, .. } if *tier == k => {
                // one offer per bond per tier: one arbitrator cannot take several seats under several
                // identities backed by one stake (review)
                if let Some(b) = Bond::from_offer(&e.msg) {
                    if !t.offers.contains_key(s) && !t.offers.values().any(|x| x.op == b.op) {
                        t.offer_height.insert(s.clone(), e.height);
                        t.offers.insert(s.clone(), b);
                    }
                }
            }
            Msg::VerdictCommit {
                tier, commitment, ..
            } if *tier == k => {
                if !vcommits.iter().any(|(w, c)| *c == *commitment && w != s) {
                    vcommits.entry(s.clone()).or_insert(commitment.clone());
                    commit_h.entry(s.clone()).or_insert(e.height);
                }
            }
            _ => {}
        }
    }
    for e in mine {
        if let Msg::Seated {
            tier,
            height,
            block_hash,
            offers,
            seats,
            ..
        } = &e.msg
        {
            if *tier != k || e.sender != escalator || !t.seats.is_empty() {
                continue;
            }
            // a tier's draw block is draw_blocks() after its escalation, as live members check it (D-1);
            // a review stage's is checked by the caller of this function (stage_draw_height)
            let h_esc = anchor.or_else(|| {
                mine.iter().find_map(|x| match &x.msg {
                    Msg::Escalate { tier: et, .. } if *et == k && x.sender == escalator => Some(x.height),
                    _ => None,
                })
            });
            // and nobody draws from a block until it is buried (a reorganisation would change it)
            let block_ok = (registry.is_some() || h_esc.is_some_and(|h| *height == h + crate::draw_blocks()))
                && rpc.height() >= *height + crate::draw_depth();
            // and every listed offer was stated at least two blocks before the draw
            let window_ok = offers.iter().all(|o| t.offer_height.get(o).is_none_or(|oh| oh + 2 <= *height));
            // and every listed offer rests on an entry bond the chain registers, unspent at the draw
            let bonded = registry.is_some()
                || offers.iter().all(|o| t.offers.get(o).is_some_and(|b| chain_registered(rpc, oracle, b, *height)));
            if block_ok
                && window_ok
                && bonded
                && offers.iter().all(|o| t.offers.contains_key(o))
                && draw(block_hash, case, k, offers, panel_size(k)) == *seats
                && rpc.block_hash(*height).as_deref() == Some(block_hash.as_str())
            {
                t.seats = seats.clone();
                t.listed = offers.clone();
                for x in seats {
                    t.seat_height.insert(x.clone(), *height);
                }
                if let Msg::Seated { refund_spk, .. } = &e.msg {
                    t.refund = ScriptBuf::from_hex(refund_spk).ok();
                }
            }
        }
    }
    // each seat's deadline runs from the block confirming its fee, as live members judge it (§10.4)
    let fee_amt = if payer.is_some() {
        base_fee
    } else {
        seat_fee(base_fee, k)
    };
    let fee_payer = payer.unwrap_or(escalator);
    let fee_tx_list: Vec<String> = mine
        .iter()
        .filter_map(|e| match &e.msg {
            Msg::FeePaid { tier, txid, .. } if *tier == k && e.sender == fee_payer => Some(txid.clone()),
            _ => None,
        })
        .collect();
    let offers_now = t.offers.clone();
    let is_review = registry.is_some();
    let deadline = |w: &str, seated_at: u32| -> u32 {
        // a review seat counts from its draw
        if is_review {
            return seated_at.saturating_add(commit_blocks);
        }
        let paid_at = offers_now.get(w).and_then(|o| {
            fee_tx_list
                .iter()
                .filter(|txid| rpc.paid_to(txid, &o.payout) >= fee_amt)
                .filter_map(|txid| rpc.tx_height(txid))
                .min()
        });
        paid_at.unwrap_or(seated_at).saturating_add(commit_blocks)
    };
    // a commitment stated at or after its seat's deadline does not count, live or in the replay
    // (review finding D-5)
    // (review stages only: an arbitration seat is out when, and only when, its seat forfeiture is on
    // the chain, which takes the pool's co-signature; see the replacements below)
    let late: Vec<String> = vcommits
        .keys()
        .filter(|_| is_review)
        .filter(|w| match (t.seat_height.get(*w), commit_h.get(*w)) {
            // the fee confirms at or after the draw, so a commit before draw + commit_blocks is in
            // time without looking the fee up (the lookup is costly in a replay)
            (Some(sh), Some(ch)) => *ch >= sh + commit_blocks && *ch >= deadline(w, *sh),
            _ => false,
        })
        .cloned()
        .collect();
    for w in late {
        vcommits.remove(&w);
    }
    // an arbitration seat's forfeiture, if the chain has it: the transaction its stake pre-signed,
    // which only the pool's co-signature completes, and the block that confirmed it. That, and
    // nothing a sender states, is what says a seat missed its deadline.
    let seat_fee_k = seat_fee(base_fee, k);
    let forfeited_at = |t: &Tier, w: &str| -> Option<u32> {
        let refund = t.refund.as_ref()?;
        let off = t.offers.get(w)?;
        mine.iter().find_map(|e| match &e.msg {
            Msg::Forfeits { tier, stake, value, .. } if *tier == k && e.sender == w => {
                let st = off.stake(OutPoint::from_str(stake).ok()?, *value);
                let (tx, _) = st.penalty_tx(oracle, seat_fee_k, refund);
                rpc.tx_height(&tx.compute_txid().to_string())
            }
            _ => None,
        })
    };
    // a seat that missed its commit deadline, replaced by a draw from the offers left (§10.4); never
    // before the deadline has passed
    for e in mine {
        if let Msg::Reseated {
            tier,
            height,
            block_hash,
            replaced,
            seat,
            from,
            ..
        } = &e.msg
        {
            if *tier != k || e.sender != escalator {
                continue;
            }
            let Some(pos) = t.seats.iter().position(|x| x == replaced) else {
                continue;
            };
            let left: Vec<String> = if from.is_empty() {
                t.listed
                    .iter()
                    .filter(|o| !t.seats.contains(o) && !t.forfeited.contains(o))
                    .cloned()
                    .collect()
            } else {
                // a reviewer that posted a replacement fee, replaced by a draw from those who then
                // offered for the seat, none already on the panel
                let left_it = mine.iter().any(|x| {
                    &x.sender == replaced
                        && matches!(&x.msg, Msg::ReviewAnswer { tier, accept: false, .. } if *tier == k)
                });
                let offered = from.iter().all(|w| {
                    !t.seats.contains(w) && !t.forfeited.contains(w) && mine.iter().any(|x| {
                        &x.sender == w
                            && matches!(&x.msg, Msg::ReviewAnswer { tier, accept: true, seat, .. }
                                    if *tier == k && seat == replaced)
                    })
                });
                if !(left_it && offered) {
                    continue;
                }
                from.clone()
            };
            // a seat that missed its deadline only; a reviewer that paid its way out leaves at once
            // (a review seat that never answers its assignment is replaced within the answer window,
            // before any commit deadline: §10.3, so the deadline applies to arbitration tiers only)
            // an arbitration seat is replaced only once its forfeiture is on the chain, and its
            // replacement is drawn from the block draw_blocks() after the one that confirmed it: the
            // escalator chooses neither whether nor from which block
            let ok = if from.is_empty() && !is_review {
                forfeited_at(&t, replaced).is_some_and(|hf| *height == hf + crate::draw_blocks())
            } else {
                !vcommits.contains_key(replaced)
            };
            if ok
                && rpc.height() >= *height + crate::draw_depth()
                && draw(block_hash, case, k, &left, 1) == vec![seat.clone()]
                && rpc.block_hash(*height).as_deref() == Some(block_hash.as_str())
            {
                vcommits.remove(replaced);
                t.forfeited.push(replaced.clone());
                t.seats[pos] = seat.clone();
                t.seat_height.insert(seat.clone(), *height);
            }
        }
    }
    // a flagged review stage is paid by the flagger, the case fee to each seat (§10.3)
    let fee = if payer.is_some() {
        base_fee
    } else {
        seat_fee(base_fee, k)
    };
    let payer = payer.unwrap_or(escalator);
    // each seat paid its fee by the escalator, in one transaction or several
    let fee_txs: Vec<&String> = mine
        .iter()
        .filter_map(|e| match &e.msg {
            Msg::FeePaid { tier, txid, .. } if *tier == k && e.sender == payer => Some(txid),
            _ => None,
        })
        .collect();
    t.fee_paid = !t.seats.is_empty()
        && (fee == 0
            || t.seats.iter().all(|x| {
                fee_txs
                    .iter()
                    // a seat with no offer on record (a review replacement from outside the
                    // registry) is unpaid, never a panic (review)
                    .any(|txid| t.offers.get(x).is_some_and(|o| rpc.paid_to(txid, &o.payout) >= fee))
            }));
    for e in mine {
        if let Msg::VerdictReveal {
            tier,
            verdict,
            salt,
            ..
        } = &e.msg
        {
            let ok = *tier == k
                && t.seats.contains(&e.sender)
                && !t.reveals.iter().any(|x| x.0 == e.sender)
                && vcommits.get(&e.sender).map(|c| {
                    *c == hex::encode(verdict.commitment(&wire::h32(salt).unwrap_or_default(), &e.sender))
                }) == Some(true);
            if ok {
                t.reveals.push((e.sender.clone(), verdict.clone()));
            }
        }
    }
    // The tier's commitment (§10.4). Anyone may post one: a transaction recording the roster and the
    // reveals it counts. Whoever posts first could leave out a reveal it dislikes, so the first does
    // not win by being first: of the commitments confirmed within the escalation window that the
    // first one opens, the one that counts the most valid reveals stands (the earliest of equals).
    // A seat left out posts one that includes it. The window, and every deadline that runs from the
    // commitment, still runs from the first.
    let mut cands: Vec<(u32, String, Vec<(String, Ballot)>)> = vec![];
    for e in mine {
        if let Msg::TierCommitted { tier, txid, revealed, committed, .. } = &e.msg {
            if *tier != k || !t.fee_paid || cands.iter().any(|c| c.1 == *txid) {
                continue;
            }
            // the reveals the commitment counts: those it lists (each a valid reveal of a seat), or,
            // for a commitment that lists none, every reveal in the log
            let counted: Vec<(String, Ballot)> = if revealed.is_empty() {
                t.reveals.clone()
            } else {
                t.reveals.iter().filter(|x| revealed.contains(&x.0)).cloned().collect()
            };
            if !revealed.is_empty() && counted.len() != revealed.len() {
                continue;
            }
            if rpc.has_op_return(txid, &tier_commitment_with(case, k, &t.seats, &counted, committed)) {
                // one not yet in a block counts as later than any that is
                cands.push((rpc.tx_height(txid).unwrap_or(u32::MAX), txid.clone(), counted));
            }
        }
    }
    cands.sort_by(|x, y| (x.0, &x.1).cmp(&(y.0, &y.1)));
    if let Some((first_h, first_txid, _)) = cands.first().cloned() {
        let best = cands
            .iter()
            .filter(|c| c.0 <= first_h.saturating_add(contest))
            .max_by(|x, y| x.2.len().cmp(&y.2.len()).then((y.0, &y.1).cmp(&(x.0, &x.1))))
            .cloned();
        if let Some((_, _, counted)) = best {
            t.committed = true;
            t.commit_txid = Some(first_txid);
            // a reveal the standing commitment does not count is charged as a missed reveal
            t.reveals = counted;
        }
    }
    t.committers = t
        .seats
        .iter()
        .chain(t.forfeited.iter())
        .filter(|x| vcommits.contains_key(*x))
        .cloned()
        .collect();
    if registry.is_some() {
        // a review seat owes a finding once it accepted, or took the seat by replacement
        t.accepted = t
            .seats
            .iter()
            .filter(|w| {
                mine.iter().any(|x| {
                    (&x.sender == *w
                        && matches!(&x.msg, Msg::ReviewAnswer { tier, accept: true, seat, .. }
                            if *tier == k && seat.is_empty()))
                        || (x.sender == escalator
                            && matches!(&x.msg, Msg::Reseated { tier, seat, from, .. }
                                if *tier == k && seat == *w && !from.is_empty()))
                })
            })
            .cloned()
            .collect();
    }
    for e in mine {
        if let Msg::Forfeits {
            tier,
            stake,
            value,
            sigs,
            ..
        } = &e.msg
        {
            let s = &e.sender;
            if *tier == k && (t.seats.contains(s) || t.forfeited.contains(s)) {
                t.raw_forfeits
                    .push((s.clone(), stake.clone(), *value, sigs.clone()));
            }
        }
    }
    t
}

/// Per arbitrator, the cases in which it voted for a verdict a confirmed staged review overturned.
pub fn overturned_votes(logs: &[TierLog]) -> HashMap<String, Vec<String>> {
    let mut out: HashMap<String, Vec<String>> = HashMap::new();
    for o in logs.iter().filter(|l| l.overturn.is_some()) {
        // the verdict the case stood on before the review: its last two-thirds tier
        let tiers: Vec<&TierLog> = logs
            .iter()
            .filter(|l| l.case == o.case && !l.review && l.height <= o.height)
            .collect();
        let Some(old) = tiers.iter().rev().find_map(|l| {
            let v: Vec<Ballot> = l.reveals.iter().map(|x| x.1.clone()).collect();
            supermajority(l.seats.len(), &v)
        }) else {
            continue;
        };
        let ok = verdict_key(&old);
        for l in &tiers {
            for (w, v) in &l.reveals {
                if verdict_key(v) == ok {
                    let e = out.entry(w.clone()).or_default();
                    if !e.contains(&o.case) {
                        e.push(o.case.clone());
                    }
                }
            }
        }
    }
    out
}

/// Inactivity (§10.3): an arbitrator that left more than 80% of its last 30 review assignments
/// unanswered (at least 5) is suspended: no seats, no review draws.
pub const INACTIVE_WINDOW: usize = 30;
pub const INACTIVE_MIN: usize = 5;

/// Per arbitrator, its review assignments before `height`, in order: true if it answered (accepted or
/// posted a replacement fee), false if it let the window pass.
pub fn assignments(hist: &[Envelope], height: u32) -> HashMap<String, Vec<bool>> {
    let mut drawn: Vec<(u32, String, u32, String)> = vec![];
    for e in hist.iter().filter(|e| e.height < height) {
        let Some(c) = e.msg.case_id() else { continue };
        match &e.msg {
            Msg::Seated { tier, seats, .. } if is_review(*tier) => {
                for w in seats {
                    drawn.push((e.height, c.to_string(), *tier, w.clone()));
                }
            }
            Msg::Reseated {
                tier, seat, from, ..
            } if is_review(*tier) && from.is_empty() => {
                drawn.push((e.height, c.to_string(), *tier, seat.clone()));
            }
            _ => {}
        }
    }
    drawn.sort();
    drawn.dedup();
    let mut out: HashMap<String, Vec<bool>> = HashMap::new();
    for (_, c, k, w) in drawn {
        let answered = hist.iter().any(|e| {
            e.sender == w
                && matches!(&e.msg, Msg::ReviewAnswer { case_id, tier, seat, .. }
                    if *case_id == c && *tier == k && seat.is_empty())
        });
        out.entry(w).or_default().push(answered);
    }
    out
}

/// The arbitrators suspended for inactivity as of `height`.
pub fn inactive(hist: &[Envelope], height: u32) -> std::collections::HashSet<String> {
    assignments(hist, height)
        .into_iter()
        .filter(|(_, v)| {
            let last = &v[v.len().saturating_sub(INACTIVE_WINDOW)..];
            let silent = last.iter().filter(|x| !**x).count();
            last.len() >= INACTIVE_MIN && silent * 5 > last.len() * 4
        })
        .map(|(w, _)| w)
        .collect()
}

/// The case id under which arbitrators register their bonds (the prototype's stand-in for the pool's
/// registry of bonds on chain).
pub fn registry_case() -> String {
    hex::encode(tagged("Bitaid/arbitrator-registry", b""))
}

/// The arbitrators registered by `height`: their first seat offer stated at or before it.
pub fn registry_at(hist: &[Envelope], height: u32) -> HashMap<String, Bond> {
    let mut m: HashMap<String, Bond> = HashMap::new();
    for e in hist {
        if let Msg::SeatOffer { .. } = &e.msg {
            if e.height <= height {
                if let Some(b) = Bond::from_offer(&e.msg) {
                    m.entry(e.sender.clone()).or_insert(b);
                }
            }
        }
    }
    m
}

/// The entry bond's floor, 0.1 BTC provisional (§2.2, §10.2).
pub const ENTRY_BOND: u64 = 10_000_000;

/// The case's roster as the chain pins it: the caller's roster whose incident transaction confirmed
/// (every version spends the same funding output, so at most one can). Before any confirms, the
/// caller's latest. Every role reads the roster through this, so a roster the caller publishes after
/// the co-signature changes nothing (review N2).
pub fn pinned_roster(hist: &[Envelope], a: &Alerted, rpc: &Rpc) -> Option<Rostered> {
    let mut latest = None;
    for e in hist.iter().rev() {
        if let Msg::Roster { case_id, .. } = &e.msg {
            if *case_id != a.case_hex || e.sender != a.caller {
                continue;
            }
            let Some(r) = Rostered::from_msg(&e.msg) else { continue };
            if rpc.tx_height(&r.incident_txid.to_string()).is_some() {
                return Some(r);
            }
            latest.get_or_insert(r);
        }
    }
    latest
}

/// One tier-1 panel fee: what an attendee whose ballot a panel rules against pays (§9, loser pays).
pub fn loser_fee(a: &Alerted) -> u64 {
    panel_size(1) as u64 * seat_fee(a.template.arb_fee, 1)
}

/// An attendee's loser-pays forfeiture: its bond pays `fee` into the case's seizure output, the rest
/// re-bonded (the same forfeiture leaf as an arbitrator's penalties).
pub fn loser_pays_tx(bond: &Bond, oracle: &XOnlyPublicKey, fee: u64, seizure: &ScriptBuf) -> (Transaction, [u8; 32]) {
    bond.penalty_tx(oracle, fee, seizure)
}

/// What a responder's bond forfeits for a fault (§11.8): a lapse a quarter, misconduct the whole.
pub fn fault_amount(value: u64, s: wire::Severity) -> u64 {
    match s {
        wire::Severity::Lapse => value / 4,
        wire::Severity::Misconduct | wire::Severity::Bannable => value,
    }
}

/// Which of an attendee's pre-signed forfeitures a fault takes: [fee, lapse, whole].
pub fn fault_sig_index(s: wire::Severity) -> usize {
    match s {
        wire::Severity::Lapse => 1,
        _ => 2,
    }
}

/// The forfeiture of a responder's bond for a fault, into the case's seizure output.
pub fn fault_tx(bond: &Bond, oracle: &XOnlyPublicKey, s: wire::Severity, seizure: &ScriptBuf) -> (Transaction, [u8; 32]) {
    bond.penalty_tx(oracle, fault_amount(bond.value, s), seizure)
}

/// The digests an attendee pre-signs at acceptance, in order: the loser-pays fee, a lapse, the whole.
pub fn attendee_forfeit_digests(bond: &Bond, oracle: &XOnlyPublicKey, fee: u64, seizure: &ScriptBuf) -> Vec<[u8; 32]> {
    vec![
        loser_pays_tx(bond, oracle, fee, seizure).1,
        fault_tx(bond, oracle, wire::Severity::Lapse, seizure).1,
        fault_tx(bond, oracle, wire::Severity::Misconduct, seizure).1,
    ]
}

/// The bond an attendee accepted the case with, as its Accept states it and the chain shows it.
pub fn accepted_bond(mine: &[&Envelope], who: &str, rpc: &Rpc) -> Option<Bond> {
    mine.iter().find_map(|e| match &e.msg {
        Msg::Accept { bond, bond_scoped, bond_cold, bond_fallback, payout_spk, .. } if e.sender == who => {
            let op = OutPoint::from_str(bond).ok()?;
            let (value, _) = rpc.output(&op)?;
            Some(Bond {
                op,
                value,
                scoped: wire::xonly(bond_scoped)?,
                cold: wire::xonly(bond_cold)?,
                fallback: *bond_fallback,
                payout: ScriptBuf::from_hex(payout_spk).ok()?,
            })
        }
        _ => None,
    })
}

/// Every arbitrator the log knows, by its first seat offer (registration or any case): the pool review
/// panels are drawn from.
pub fn registry(hist: &[Envelope]) -> HashMap<String, Bond> {
    let mut m: HashMap<String, Bond> = HashMap::new();
    for e in hist {
        if let Msg::SeatOffer { .. } = &e.msg {
            if let Some(b) = Bond::from_offer(&e.msg) {
                m.entry(e.sender.clone()).or_insert(b);
            }
        }
    }
    m
}

/// One committed tier of some case, as the ledger of momentum reads it.
#[derive(Clone, Debug)]
pub struct TierLog {
    pub case: String,
    pub tier: u32,
    /// height of the block carrying the tier commitment
    pub height: u32,
    pub seats: Vec<String>,
    pub committers: Vec<String>,
    pub reveals: Vec<(String, Ballot)>,
    /// a review stage: only a seat that accepted and never revealed is charged (§10.3)
    pub review: bool,
    /// a confirmed review: from this height the case stands on this verdict
    pub overturn: Option<Ballot>,
}

/// Every committed tier of every case in the log, ordered by the height of its commitment. Old cases
/// are replayed from the log and the chain, their funding outputs read as created (spent or not).
pub fn ledger(hist: &[Envelope], rpc: &Rpc, oracle_key: &str) -> Vec<TierLog> {
    // per case, the logs read from its messages: kept while the case gets no new message, once every
    // commitment they rest on is confirmed (replaying every case for every seat grows with the log)
    type Cache = HashMap<(String, String, usize), Vec<TierLog>>;
    static CACHE: std::sync::OnceLock<std::sync::Mutex<Cache>> = std::sync::OnceLock::new();
    let cache = CACHE.get_or_init(Default::default);
    let mut counts: HashMap<&str, usize> = HashMap::new();
    for e in hist {
        if let Some(c) = e.msg.case_id() {
            *counts.entry(c).or_default() += 1;
        }
    }
    let mut out = vec![];
    let mut seen = std::collections::HashSet::new();
    for e in hist {
        let Msg::Alert { case_id, .. } = &e.msg else {
            continue;
        };
        if !seen.insert(case_id.clone()) {
            continue;
        }
        let key = (
            case_id.clone(),
            oracle_key.to_string(),
            counts.get(case_id.as_str()).copied().unwrap_or(0),
        );
        if let Some(v) = cache.lock().unwrap().get(&key) {
            out.extend(v.iter().cloned());
            continue;
        }
        let start = out.len();
        let mut complete = true;
        let Ok(a) = Alerted::check(&e.sender, &e.msg, |op| rpc.output(op), oracle_key) else {
            continue;
        };
        let Some(r) = pinned_roster(hist, &a, rpc) else {
            continue;
        };
        let Some(rp) = Replay::build_core(hist, &a, &r, rpc) else {
            continue;
        };
        for (k, t) in rp.tiers {
            let Some(h) = t.commit_txid.as_ref().and_then(|x| rpc.tx_height(x)) else {
                complete &= t.commit_txid.is_none();
                continue;
            };
            out.push(TierLog {
                case: a.case_hex.clone(),
                tier: k,
                height: h,
                seats: t.seats,
                committers: t.committers,
                reveals: t.reveals,
                review: false,
                overturn: None,
            });
        }
        let mut last = 0;
        for (k, t) in rp.reviews.iter() {
            let Some(h) = t.commit_txid.as_ref().and_then(|x| rpc.tx_height(x)) else {
                complete &= t.commit_txid.is_none();
                continue;
            };
            last = last.max(h);
            out.push(TierLog {
                case: a.case_hex.clone(),
                tier: *k,
                height: h,
                seats: t.seats.clone(),
                committers: t.accepted.clone(),
                reveals: t.reveals.clone(),
                review: true,
                overturn: None,
            });
        }
        if let ReviewState::Confirmed(v) = &rp.review {
            out.push(TierLog {
                case: a.case_hex.clone(),
                tier: REVIEW_BASE + REVIEW_STAGES,
                height: last,
                seats: vec![],
                committers: vec![],
                reveals: vec![],
                review: true,
                overturn: Some(v.clone()),
            });
        }
        if complete {
            cache.lock().unwrap().insert(key, out[start..].to_vec());
        }
    }
    out.sort_by(|x, y| (x.height, &x.case, x.tier).cmp(&(y.height, &y.case, y.tier)));
    out
}

/// An arbitrator's momentum D at `height` (§10.4): over every tier committed before that height, in
/// order, each vote it served decays D by λ and adds its error weight (0 if it matched the verdict its
/// case stands on at that height; factor/4 for an incoherent vote, so 1 for a lone dissenter on a large
/// panel; 1 for a commitment never revealed), less the margin times the pool's mean error weight per
/// vote so far; never below zero. A case's standing verdict is its last committed tier with two thirds.
pub fn momentum(logs: &[TierLog], arbitrator: &str, height: u32) -> f64 {
    let before: Vec<&TierLog> = logs.iter().filter(|l| l.height < height).collect();
    let mut standing: HashMap<&str, (&TierLog, Ballot)> = HashMap::new();
    // the verdict a confirmed review overturned, per case
    let mut kept: HashMap<&str, Vec<u8>> = HashMap::new();
    for l in &before {
        // a confirmed review overturns the standing verdict from its last stage on (§10.3)
        if let Some(b) = &l.overturn {
            if let Some((_, old)) = standing.get(l.case.as_str()) {
                kept.insert(l.case.as_str(), verdict_key(old));
            }
            let fin = standing.get(l.case.as_str()).map(|x| x.0).unwrap_or(l);
            standing.insert(l.case.as_str(), (fin, b.clone()));
            continue;
        }
        if l.review {
            continue;
        }
        let v: Vec<Ballot> = l.reveals.iter().map(|x| x.1.clone()).collect();
        if let Some(b) = supermajority(l.seats.len(), &v) {
            standing.insert(l.case.as_str(), (l, b));
        }
    }
    let (mut d, mut sum, mut votes) = (0.0f64, 0.0f64, 0usize);
    for l in &before {
        let Some((fin, fv)) = standing.get(l.case.as_str()) else {
            continue;
        };
        let fk = verdict_key(fv);
        // a tier with no two thirds of its own (hung) charges no one for disagreeing (§10.5)
        let hung = !l.review && supermajority(l.seats.len(), &l.reveals.iter().map(|x| x.1.clone()).collect::<Vec<_>>()).is_none();
        for seat in &l.seats {
            if l.review {
                // a review seat is charged for a finding it owed and never revealed, and, once the
                // three stages confirm an overturn, for a vote to keep the overturned verdict; a vote
                // to overturn that was not confirmed is never charged, so a blocking bloc cannot mark
                // honest reviewers (§10.3, two bars)
                let kept_vote = kept.get(l.case.as_str()).is_some_and(|ok| {
                    l.reveals.iter().any(|x| &x.0 == seat && verdict_key(&x.1) == *ok)
                });
                if kept_vote {
                    let mean = if votes > 0 { sum / votes as f64 } else { 0.0 };
                    if seat == arbitrator {
                        d = (LAMBDA * d + 1.0 - MARGIN * mean).max(0.0);
                    }
                    sum += 1.0;
                    votes += 1;
                    continue;
                }
                if l.reveals.iter().any(|x| &x.0 == seat) || !l.committers.contains(seat) {
                    continue;
                }
                let mean = if votes > 0 { sum / votes as f64 } else { 0.0 };
                if seat == arbitrator {
                    d = (LAMBDA * d + 1.0 - MARGIN * mean).max(0.0);
                }
                sum += 1.0;
                votes += 1;
                continue;
            }
            let e = match l.reveals.iter().find(|x| &x.0 == seat) {
                Some((_, v)) if verdict_key(v) == fk || hung => 0.0,
                Some((_, v)) => {
                    let vk = verdict_key(v);
                    let agree = fin
                        .reveals
                        .iter()
                        .filter(|x| verdict_key(&x.1) == vk)
                        .count();
                    penalty_factor(fin.seats.len(), agree.max(1)) / 4.0
                }
                None if l.committers.contains(seat) => 1.0,
                None => continue,
            };
            let mean = if votes > 0 { sum / votes as f64 } else { 0.0 };
            if seat == arbitrator {
                d = (LAMBDA * d + e - MARGIN * mean).max(0.0);
            }
            sum += e;
            votes += 1;
        }
    }
    d
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{Act, Class};

    fn v(c: &[Class]) -> Ballot {
        Ballot {
            acts: c
                .iter()
                .enumerate()
                .map(|(i, c)| Act {
                    seat: i as u8,
                    class: c.clone(),
                    footage: None,
                })
                .collect(),
            outcome_achieved: true,
            misuse: false, faults: vec![],
        }
    }

    #[test]
    fn sizes_fees_penalties() {
        assert_eq!(
            (panel_size(1), panel_size(2), panel_size(3), panel_size(4)),
            (3, 7, 15, 31)
        );
        assert_eq!(seat_fee(20_000, 1), 20_000);
        assert_eq!(seat_fee(20_000, 2), 25_000);
        assert_eq!(penalty_factor(3, 1), 2.0);
        assert!(
            (penalty_factor(15, 1) - 4.0).abs() < 1e-9,
            "lone dissenter on 15 pays 4x"
        );
        assert!(
            (penalty_factor(15, 5) - 2.0).abs() < 1e-9,
            "a third dissenting pays 2x"
        );
    }

    #[test]
    fn steps() {
        assert_eq!(step_of(2.0), 20);
        assert_eq!(step_of(2.49), 20);
        assert_eq!(step_of(2.5), 25);
        assert_eq!(step_of(3.99), 35);
        assert_eq!(step_of(4.0), 40);
        assert_eq!(step_of(penalty_factor(7, 1)), 40);
        assert_eq!(step_of(penalty_factor(7, 2)), 25);
        assert_eq!(step_of(4.0 * multiplier(1.0)), 80);
        assert_eq!(step_of(2.5 * multiplier(1.5)), 70);
        assert_eq!(max_step(9.0), 1280);
        // inactivity: more than 80% of at least 5 review assignments left unanswered
        let env = |h: u32, who: &str, msg: Msg| crate::wire::Envelope {
            v: 1,
            height: h,
            sender: who.into(),
            msg,
        };
        let mut hist = vec![];
        for i in 0..6u32 {
            let c = format!("{:064x}", i + 1);
            hist.push(env(
                10 + i,
                "conv",
                Msg::Seated {
                    case_id: c.clone(),
                    tier: REVIEW_BASE + 1,
                    height: 10 + i,
                    block_hash: String::new(),
                    offers: vec![],
                    seats: vec!["afk".into(), "busy".into()],
                    sealed_keys: vec![],
                    refund_spk: String::new(),
                },
            ));
            // "busy" answers all but the first draw, "afk" answers only the last
            for (who, ans) in [("busy", i > 0), ("afk", i == 5)] {
                if ans {
                    hist.push(env(
                        10 + i,
                        who,
                        Msg::ReviewAnswer {
                            case_id: c.clone(),
                            tier: REVIEW_BASE + 1,
                            accept: true,
                            fee: 0,
                            seat: String::new(),
                        },
                    ));
                }
            }
        }
        let off = inactive(&hist, 100);
        assert!(off.contains("afk") && !off.contains("busy"));
        assert!(inactive(&hist, 13).is_empty()); // fewer than 5 assignments yet
                                                 // a case unit: twice the case value, or the largest penalty if that is more (§10.2)
        assert_eq!(unit_value(900_000, 40, 20_000), 1_800_000);
        assert_eq!(unit_value(1_000, 1280, 20_000), 2_560_000);
        assert_eq!(steps_upto(40).len(), 5);
    }

    #[test]
    fn draw_is_deterministic_and_order_free() {
        let offers: Vec<String> = (0..9).map(|i| format!("arb{i}")).collect();
        let a = draw("00ff", "case", 1, &offers, 3);
        let mut rev = offers.clone();
        rev.reverse();
        assert_eq!(
            a,
            draw("00ff", "case", 1, &rev, 3),
            "arrival order does not matter"
        );
        assert_ne!(
            a,
            draw("00fe", "case", 1, &offers, 3),
            "another block, another panel"
        );
        assert_eq!(a.len(), 3);
    }

    #[test]
    fn two_thirds() {
        use Class::*;
        let (good, bad) = (
            v(&[Intervention, Documentation]),
            v(&[Documentation, Intervention]),
        );
        assert_eq!(
            supermajority(3, &[good.clone(), good.clone(), bad.clone()]),
            Some(good.clone())
        );
        assert_eq!(
            supermajority(3, &[good.clone(), bad.clone()]),
            Option::None,
            "two of three needed"
        );
        let seven: Vec<Ballot> = (0..7)
            .map(|i| if i < 4 { good.clone() } else { bad.clone() })
            .collect();
        assert_eq!(
            supermajority(7, &seven),
            Option::None,
            "4 of 7 is not two thirds"
        );
    }
}

/// Cases a day each registered arbitrator is taken to hear, for the market's capacity.
pub const HEARINGS_PER_DAY: u64 = 1;

/// Blocks a posting's escrow stays locked at the least (`BITAID_POST_LOCK`, a week by default): what
/// a posting costs whoever makes it, real case or not.
pub fn post_lock() -> u32 {
    std::env::var("BITAID_POST_LOCK").ok().and_then(|v| v.parse().ok()).unwrap_or(4_320)
}

/// The market's opening fee, in sats per seat (`BITAID_FEE0`): a constant of the network, like the
/// height its ledger is read from.
pub fn fee0() -> u64 {
    std::env::var("BITAID_FEE0").ok().and_then(|v| v.parse().ok()).unwrap_or(crate::sats(1_000).max(1))
}

/// The escrow a posting holds its fees in: the bond script of the poster's key (spent with the
/// pool's co-signature to pay the seats drawn, or by the poster alone from the lock height).
pub fn escrow(poster: &XOnlyPublicKey, lock: u32, op: OutPoint, value: u64, payout: ScriptBuf) -> Bond {
    Bond { op, value, scoped: *poster, cold: *poster, fallback: lock, payout }
}

/// Whether a posting on the ledger is one this pool's market counts: tier 1, its escrow under the
/// poster's bond script for this pool's oracle key, holding the whole panel's fees at its bid, locked
/// for at least `post_lock()` blocks from its confirmation.
pub fn posting_valid(p: &crate::ledger::Posting, oracle: &XOnlyPublicKey) -> bool {
    let e = escrow(&p.poster, p.lock, p.at.op, p.at.value, ScriptBuf::new());
    p.tier == 1
        && p.fee > 0
        && p.at.spk == e.tree(oracle).script_pubkey()
        && p.at.value >= p.fee.saturating_mul(panel_size(1) as u64)
        && p.lock >= p.at.height.saturating_add(post_lock())
}

/// The arbitrators registered on the ledger and still bonded at `height`: an entry bond under the
/// bond script of the keys the record names, for this pool's oracle key, unspent.
pub fn registered_at(l: &crate::ledger::Ledger, oracle: &XOnlyPublicKey, height: u32) -> usize {
    l.registrations
        .iter()
        .filter(|r| {
            r.at.height <= height
                && r.at.spent.is_none_or(|s| s > height)
                && r.at.value >= crate::sats(ENTRY_BOND)
                && r.at.spk
                    == Bond {
                        op: r.at.op,
                        value: r.at.value,
                        scoped: r.scoped,
                        cold: r.cold,
                        fallback: r.fallback,
                        payout: ScriptBuf::new(),
                    }
                    .tree(oracle)
                    .script_pubkey()
        })
        .count()
}

/// Whether `b` is an entry bond the chain registers (see `registered_at`), unspent at `height`.
pub fn chain_registered(rpc: &Rpc, oracle: &XOnlyPublicKey, b: &Bond, height: u32) -> bool {
    rpc.sync();
    rpc.ledger(|l| {
        l.registrations.iter().any(|r| {
            r.at.op == b.op
                && r.scoped == b.scoped
                && r.cold == b.cold
                && r.fallback == b.fallback
                && r.at.height <= height
                && r.at.spent.is_none_or(|s| s > height)
                && r.at.value >= crate::sats(ENTRY_BOND)
                && r.at.spk == b.tree(oracle).script_pubkey()
        })
    })
}

/// The fee market (§10.6) at `height`, replayed from the ledger alone: every node with the chain
/// computes the same one. A posting is a confirmed transaction whose escrow holds the panel's fees
/// (see `posting_valid`); it counts from the block that confirmed it, at the highest fee the case has
/// posted. It clears when its escrow is spent before the lock height, which only the pool's
/// co-signature allows, and the pool gives it only to pay the seats drawn; spent from the lock
/// height on, it was withdrawn. Capacity is the arbitrators registered on the ledger, in panels.
pub fn market_at(l: &crate::ledger::Ledger, oracle: &XOnlyPublicKey, height: u32) -> crate::market::Market {
    use crate::market::{Bid, Market};
    // (height, place in the block, posting index, is a spend)
    let mut ev: Vec<(u32, usize, usize, bool)> = vec![];
    for (i, p) in l.postings.iter().enumerate() {
        if !posting_valid(p, oracle) || p.at.height > height {
            continue;
        }
        ev.push((p.at.height, p.at.pos, i, false));
        if let Some(s) = p.at.spent.filter(|s| *s <= height) {
            ev.push((s, usize::MAX, i, true));
        }
    }
    ev.sort();
    let start = std::env::var("BITAID_INDEX_FROM")
        .ok()
        .and_then(|v| v.parse().ok())
        .or(ev.first().map(|x| x.0))
        .unwrap_or(height)
        .min(height);
    let cap = |h: u32| (registered_at(l, oracle, h) as u64 / panel_size(1) as u64).max(1) * HEARINGS_PER_DAY;
    let mut m = Market::new(fee0(), start);
    // each case's postings still standing, to know which one a spend takes away
    let mut held: HashMap<&str, Vec<usize>> = HashMap::new();
    let mut heard: std::collections::HashSet<&str> = Default::default();
    for (h, _, i, spend) in ev {
        m.advance(h, cap(h));
        let p = &l.postings[i];
        let c = p.case.as_str();
        if !spend {
            // a case is heard once: a posting for one already heard is no demand
            if heard.contains(c) {
                continue;
            }
            let best = held.get(c).into_iter().flatten().map(|j| l.postings[*j].fee).max();
            held.entry(c).or_default().push(i);
            if best.is_none_or(|b| p.fee > b) {
                // a hearing must still fit before the escrow unlocks
                let last = p.lock.saturating_sub(crate::draw_blocks() + crate::draw_depth());
                match best {
                    None => {
                        m.post(Bid { case: c.into(), fee: p.fee, weight: 1, posted_at: h, last_hearing: last });
                    }
                    Some(_) => {
                        m.top_up(c, p.fee);
                    }
                }
            }
        } else {
            let v = held.entry(c).or_default();
            v.retain(|j| *j != i);
            if p.at.released {
                // let go with the pool's co-signature (it gives it only for a case not waiting for
                // its hearing): the case stands on what it still has posted, if anything
                if !heard.contains(c) {
                    m.withdraw(c);
                    if let Some(j) = v.iter().copied().max_by_key(|j| l.postings[*j].fee) {
                        let q = &l.postings[j];
                        let last = q.lock.saturating_sub(crate::draw_blocks() + crate::draw_depth());
                        m.post(Bid { case: c.into(), fee: q.fee, weight: 1, posted_at: h, last_hearing: last });
                    }
                }
            } else if h < p.lock {
                // paid out to the seats: heard
                m.clear(c);
                m.withdraw(c);
                v.clear();
                heard.insert(c);
            } else if v.is_empty() {
                m.withdraw(c);
            }
        }
    }
    m.advance(height, cap(height));
    m
}

/// Who opened tier 1 of a case, and at what height, as the chain says: the party whose valid posting
/// for the case comes first in the chain's order, and the height at which the market took the case
/// up (the posting's own block if its fee met the market's, else the step that brought the fee down
/// to it). None while the case has no posting by a party, or still waits as a standing bid.
pub fn tier1_opening(rpc: &Rpc, oracle: &XOnlyPublicKey, case: &str, parties: &[&str]) -> Option<(String, u32)> {
    let tip = rpc.height();
    rpc.ledger(|l| {
        let mut ps: Vec<&crate::ledger::Posting> = l
            .postings
            .iter()
            .filter(|p| p.case == case && posting_valid(p, oracle))
            .filter(|p| parties.contains(&hex::encode(p.poster.serialize()).as_str()))
            .collect();
        ps.sort_by_key(|p| (p.at.height, p.at.pos));
        let who = hex::encode(ps.first()?.poster.serialize());
        let h = market_at(l, oracle, tip).activated(case)?;
        Some((who, h))
    })
}

#[cfg(test)]
mod record_tests {
    use super::*;
    use crate::ledger::{Anchor, Ledger, Posting, Registration};

    fn key(b: u8) -> XOnlyPublicKey {
        bitcoin::secp256k1::Keypair::from_seckey_slice(&Secp256k1::new(), &[b; 32]).unwrap().x_only_public_key().0
    }
    fn op(n: u8) -> OutPoint {
        OutPoint { txid: bitcoin::Txid::from_str(&hex::encode([n; 32])).unwrap(), vout: 0 }
    }

    /// A record alone moves nothing: anyone can write one, so each counts only with the output the
    /// chain shows beside it, under the script its own fields give, holding what it claims.
    #[test]
    fn a_forged_record_counts_for_nothing() {
        let (oracle, poster) = (key(9), key(1));
        let fee = 20_000u64;
        let lock = 1_000 + post_lock();
        let spk = escrow(&poster, lock, op(1), 0, ScriptBuf::new()).tree(&oracle).script_pubkey();
        let good = Posting {
            case: hex::encode([7u8; 32]),
            tier: 1,
            fee,
            poster,
            lock,
            at: Anchor { op: op(1), value: fee * panel_size(1) as u64, spk: spk.clone(), height: 1_000, pos: 0, spent: None, released: false },
        };
        assert!(posting_valid(&good, &oracle));
        // the record names a fee its escrow does not hold
        let mut p = good.clone();
        p.at.value -= 1;
        assert!(!posting_valid(&p, &oracle));
        // the output beside it is not the escrow of the key, lock and oracle the record names
        let mut p = good.clone();
        p.at.spk = escrow(&key(2), lock, op(1), 0, ScriptBuf::new()).tree(&oracle).script_pubkey();
        assert!(!posting_valid(&p, &oracle));
        let mut p = good.clone();
        p.at.spk = escrow(&poster, lock, op(1), 0, ScriptBuf::new()).tree(&key(8)).script_pubkey();
        assert!(!posting_valid(&p, &oracle));
        // an escrow its poster could take back at once holds nothing
        let mut p = good.clone();
        p.lock = 1_001;
        p.at.spk = escrow(&poster, 1_001, op(1), 0, ScriptBuf::new()).tree(&oracle).script_pubkey();
        assert!(!posting_valid(&p, &oracle));

        // a registration counts as capacity only with a whole entry bond under its own keys' script
        let bond = Bond { op: op(2), value: crate::sats(ENTRY_BOND), scoped: key(3), cold: key(4), fallback: 9_000, payout: ScriptBuf::new() };
        let reg = |value: u64, spk: ScriptBuf| Registration {
            scoped: bond.scoped,
            cold: bond.cold,
            fallback: bond.fallback,
            at: Anchor { op: bond.op, value, spk, height: 1_000, pos: 0, spent: None, released: false },
        };
        let real = bond.tree(&oracle).script_pubkey();
        let count = |r: Registration| {
            let mut l = Ledger::default();
            l.registrations.push(r);
            registered_at(&l, &oracle, 1_010)
        };
        assert_eq!(count(reg(bond.value, real.clone())), 1);
        assert_eq!(count(reg(bond.value - 1, real.clone())), 0);
        assert_eq!(count(reg(bond.value, spk.clone())), 0);
        let mut spent = reg(bond.value, real);
        spent.at.spent = Some(1_005);
        assert_eq!(count(spent), 0);
    }
}
