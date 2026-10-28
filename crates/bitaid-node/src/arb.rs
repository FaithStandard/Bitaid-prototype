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

/// A verdict's identity for counting: two arbitrators agree when their answers are identical.
pub fn verdict_key(v: &Ballot) -> Vec<u8> {
    let mut b = Vec::new();
    ciborium::into_writer(v, &mut b).unwrap();
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
    let r = match case_value {
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
) -> Option<(ScriptTree, KeyPolicy)> {
    let mut ks: Vec<XOnlyPublicKey> = archivists.iter().filter_map(|a| wire::xonly(a)).collect();
    ks.sort();
    ks.dedup();
    let first = *ks.first()?;
    let pol = KeyPolicy::of(ks.len() / 2 + 1, ks);
    let secp = Secp256k1::verification_only();
    Some((
        outputs::seizure(&secp, &pol, oracle, &first, SEIZURE_LOCK),
        pol,
    ))
}

/// Where an entry bond's seizure goes first (B.1): an output only the oracle pool can spend, by one
/// leaf `<oracle> CHECKSIG` (no key path), which it spends only into the seizure output of the case a
/// confirmed review found against the arbitrator.
pub fn holding_tree(oracle: &XOnlyPublicKey) -> ScriptTree {
    let leaf = bitcoin::script::Builder::new()
        .push_x_only_key(oracle)
        .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
        .into_script();
    ScriptTree::new(
        &Secp256k1::verification_only(),
        bitaid_core::scripts::nums(),
        vec![leaf],
    )
}

/// The move of a seized entry bond from the holding output into a case's seizure output.
pub fn holding_move(
    oracle: &XOnlyPublicKey,
    seized: &Transaction,
    value: u64,
    seizure: &ScriptBuf,
) -> (Transaction, [u8; 32]) {
    let t = holding_tree(oracle);
    let tx = txbuild::payout(
        OutPoint {
            txid: seized.compute_txid(),
            vout: 0,
        },
        &[(value, seizure.clone())],
    );
    let d = txbuild::scriptspend_digest(
        &tx,
        0,
        &[txbuild::txout(value, t.script_pubkey())],
        &t.scripts[0],
    );
    (tx, d)
}

pub fn holding_witness(oracle: &XOnlyPublicKey, tx: &mut Transaction, osig: &[u8; 64]) {
    let t = holding_tree(oracle);
    tx.input[0].witness = Witness::from_slice(&[
        osig.to_vec(),
        t.scripts[0].to_bytes(),
        t.control(0).serialize(),
    ]);
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
        let outs = if amount >= self.value {
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
    pub fn entry_seizure(&self, oracle: &XOnlyPublicKey) -> (Transaction, [u8; 32]) {
        self.penalty_tx(oracle, self.value, &holding_tree(oracle).script_pubkey())
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
        && rpc.paid_to(&st.op.txid.to_string(), &bond.tree(oracle).script_pubkey()) >= value)
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
        if self.review {
            // each review panel decides at 80% (§10.3)
            supermajority_of(self.seats.len(), &v, 4, 5)
        } else {
            supermajority(self.seats.len(), &v)
        }
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
    pub entries: HashMap<String, (Bond, String)>,
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
            if let Msg::Forfeits { sigs, stake, .. } = &e.msg {
                let Some(b) = hist.iter().find_map(|x| match &x.msg {
                    Msg::SeatOffer { case_id, .. } if *case_id == reg && x.sender == e.sender => {
                        Bond::from_offer(&x.msg)
                    }
                    _ => None,
                }) else {
                    continue;
                };
                let (_, d) = b.entry_seizure(&oracle);
                if b.op.to_string() == *stake
                    && sigs.first().is_some_and(|g| schnorr_ok(&b.scoped, &d, g))
                {
                    rp.entries
                        .entry(e.sender.clone())
                        .or_insert((b, sigs[0].clone()));
                }
            }
        }
        let logs = ledger(hist, rpc, &a.oracle_key);
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
            parties,
            tiers: BTreeMap::new(),
            reviews: BTreeMap::new(),
            convener: r.archivists.first().cloned(),
            review: ReviewState::NotDrawn,
            entries: HashMap::new(),
        };
        let mine: Vec<&Envelope> = hist
            .iter()
            .filter(|e| e.msg.case_id() == Some(case.as_str()))
            .collect();
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
            );
            rp.tiers.insert(k, t);
        }
        // the staged review (§10.3): convened only on a case the draw selected, each stage only after
        // the one before found a different verdict at 80%
        let conv = rp.convener.clone();
        for st in 1..=REVIEW_STAGES {
            let k = REVIEW_BASE + st;
            if rp.review_state(a, rpc) != ReviewState::Pending(st) {
                break;
            }
            let Some(conv) = conv.as_ref() else { break };
            let opened = mine.iter().any(|e| {
                matches!(&e.msg, Msg::Escalate { tier, .. } if *tier == k) && &e.sender == conv
            });
            if !opened {
                break;
            }
            let reg = registry(hist);
            let mut t = read_tier(&mine, &case, k, conv, false, rp.base_fee, rpc, Some(&reg));
            t.review = true;
            // each panel independent: drawn only from arbitrators who sat on neither the case nor an
            // earlier stage of its review
            let excluded = rp.review_excluded();
            if t.listed.iter().any(|x| excluded.contains(x)) {
                break;
            }
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
        seizure_tree(&self.archivists, &self.oracle).map(|t| t.0.script_pubkey())
    }

    /// The review draw of a closed case (§10.3): the block whose hash seeds it, and whether it selected
    /// the case. None while the case has no committed verdict or the block is not yet mined.
    pub fn review_draw(&self, a: &Alerted, rpc: &Rpc) -> Option<ReviewDraw> {
        let (ft, fv) = self.final_ruling()?;
        // closed at the last tier commitment on chain (a later tier that hung or lapsed included)
        let close = self
            .tiers
            .values()
            .filter_map(|t| t.commit_txid.as_ref().and_then(|x| rpc.tx_height(x)))
            .max()?;
        let height = close + a.template.review_delay.max(1);
        if rpc.height() < height {
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
        if !dr.drawn {
            return ReviewState::NotDrawn;
        }
        let fk = verdict_key(&fv);
        let mut prev: Option<Vec<u8>> = None;
        for st in 1..=REVIEW_STAGES {
            let Some(t) = self.reviews.get(&(REVIEW_BASE + st)) else {
                return ReviewState::Pending(st);
            };
            if !t.committed {
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
            // each incoherent vote, and each commitment never revealed (charged at the isolation penalty)
            let mut owed: Vec<(String, f64)> = vec![];
            for (arb, v) in &t.reveals {
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
        // one order for everyone (reveals arrive in different orders at different nodes): the
        // distribution spends these outputs in this order, so its txid depends on it
        out.sort_by(|x, y| (x.tier, &x.arbitrator).cmp(&(y.tier, &y.arbitrator)));
        out
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
        if !vind.is_empty() {
            let each = total / 2 / vind.len() as u64;
            for (_, p) in &vind {
                outs.push((each, p.clone()));
                left -= each;
            }
        }
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
    ) -> Vec<(
        String,
        Bond,
        String,
        Transaction,
        [u8; 32],
        Transaction,
        [u8; 32],
    )> {
        let Some(spk) = self.seizure_spk() else {
            return vec![];
        };
        let mut who: Vec<String> = self.overturned_voters().into_iter().map(|x| x.1).collect();
        who.sort();
        who.dedup();
        who.into_iter()
            .filter_map(|w| {
                let (b, pre) = self.entries.get(&w)?.clone();
                let (tx, d) = b.entry_seizure(&self.oracle);
                let (mv, d2) = holding_move(&self.oracle, &tx, b.value, &spk);
                Some((w, b, pre, tx, d, mv, d2))
            })
            .collect()
    }

    /// What a confirmed review's distribution spends: the whole units, then the entry bonds moved into
    /// the case's seizure output.
    pub fn review_inputs(&self) -> Vec<Penalty> {
        let mut v = self.review_penalties();
        for (w, b, pre, _, _, mv, d2) in self.entry_seizures() {
            v.push(Penalty {
                arbitrator: w,
                tier: 0,
                step: 0,
                amount: b.value,
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
        let crate::settle::Decision::Settled(ends) = crate::settle::decide(
            r.seats.len(),
            a.template.pots,
            &a.template,
            std::slice::from_ref(v),
        ) else {
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
        let mut harmed: Vec<ScriptBuf> = vec![];
        for (x, s) in &after {
            let had = before.iter().find(|y| y.1 == *s).map(|y| y.0).unwrap_or(0);
            if *x > had {
                let owed = (*x - had).min(left);
                outs.push((owed, s.clone()));
                left -= owed;
                harmed.push(s.clone());
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
        // retention of the case's evidence (§12 item 5): a case overturned on review is precedent and
        // review material, and its seizure pays for keeping it, to the base-slot archivists
        let keep = RETENTION_SATS.min(left);
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
        let pens = self.review_inputs();
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
                        &p.arbitrator[..8]
                    ),
                )
            })
            .collect();
        for (w, b, _, tx, d, mv, d2) in self.entry_seizures() {
            out.push((
                tx.compute_txid(),
                0,
                d,
                format!(
                    "the seizure of {}'s whole entry bond ({} sats) pre-signed at joining (review confirmed)",
                    &w[..8],
                    b.value
                ),
            ));
            out.push((
                mv.compute_txid(),
                0,
                d2,
                format!(
                    "the move of {}'s seized entry bond into the case's seizure output",
                    &w[..8]
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
        let (t, _) = seizure_tree(&self.archivists, &self.oracle)?;
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
        let (t, pol) = seizure_tree(&self.archivists, &self.oracle)?;
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
    for e in mine {
        let s = &e.sender;
        match &e.msg {
            Msg::SeatOffer { tier, .. } if *tier == k => {
                if let Some(b) = Bond::from_offer(&e.msg) {
                    t.offers.entry(s.clone()).or_insert(b);
                }
            }
            Msg::VerdictCommit {
                tier, commitment, ..
            } if *tier == k => {
                vcommits.entry(s.clone()).or_insert(commitment.clone());
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
            if offers.iter().all(|o| t.offers.contains_key(o))
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
    // a seat that missed its commit deadline, replaced by a draw from the offers left (§10.4)
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
            if !vcommits.contains_key(replaced)
                && draw(block_hash, case, k, &left, 1) == vec![seat.clone()]
                && rpc.block_hash(*height).as_deref() == Some(block_hash.as_str())
            {
                t.forfeited.push(replaced.clone());
                t.seats[pos] = seat.clone();
                t.seat_height.insert(seat.clone(), *height);
            }
        }
    }
    let fee = seat_fee(base_fee, k);
    // each seat paid its fee by the escalator, in one transaction or several
    let fee_txs: Vec<&String> = mine
        .iter()
        .filter_map(|e| match &e.msg {
            Msg::FeePaid { tier, txid, .. } if *tier == k && e.sender == escalator => Some(txid),
            _ => None,
        })
        .collect();
    t.fee_paid = !t.seats.is_empty()
        && (fee == 0
            || t.seats.iter().all(|x| {
                fee_txs
                    .iter()
                    .any(|txid| rpc.paid_to(txid, &t.offers[x].payout) >= fee)
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
                    *c == hex::encode(verdict.commitment(&wire::h32(salt).unwrap_or_default()))
                }) == Some(true);
            if ok {
                t.reveals.push((e.sender.clone(), verdict.clone()));
            }
        }
    }
    for e in mine {
        if let Msg::TierCommitted { tier, txid, .. } = &e.msg {
            let cm = tier_commitment(case, k, &t.seats, &t.reveals);
            if *tier == k && t.fee_paid && !t.committed && rpc.has_op_return(txid, &cm) {
                t.committed = true;
                t.commit_txid = Some(txid.clone());
            }
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

/// The case id under which arbitrators register their bonds (the prototype's stand-in for the pool's
/// registry of bonds on chain).
pub fn registry_case() -> String {
    hex::encode(tagged("Bitaid/arbitrator-registry", b""))
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
        let Some(r) = hist.iter().rev().find_map(|x| match &x.msg {
            Msg::Roster { case_id: c, .. } if *c == a.case_hex && x.sender == a.caller => {
                Rostered::from_msg(&x.msg)
            }
            _ => None,
        }) else {
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
    for l in &before {
        // a confirmed review overturns the standing verdict from its last stage on (§10.3)
        if let Some(b) = &l.overturn {
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
        for seat in &l.seats {
            if l.review {
                // a review seat is charged only for a finding it owed and never revealed
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
                Some((_, v)) if verdict_key(v) == fk => 0.0,
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
            misuse: false,
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
