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
pub fn panel_size(tier: u32) -> usize {
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
    let need = (2 * n).div_ceil(3);
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
    /// The pre-signed forfeitures' digests at a seat fee: one per step up to `max`, then the seat
    /// forfeiture refunding the fee.
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
        v.push(self.penalty_tx(oracle, fee, refund).1);
        v
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
        supermajority(self.seats.len(), &v)
    }
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
}

impl Replay {
    /// The case replayed, each seat's momentum taken from every case in the log (§10.4) and its
    /// forfeitures verified against the steps that momentum calls for.
    pub fn build(hist: &[Envelope], a: &Alerted, r: &Rostered, rpc: &Rpc) -> Option<Replay> {
        let mut rp = Replay::build_core(hist, a, r, rpc)?;
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
        };
        let mine: Vec<&Envelope> = hist
            .iter()
            .filter(|e| e.msg.case_id() == Some(case.as_str()))
            .collect();
        // tier by tier, since who may open a tier depends on the tier below it
        let max = mine
            .iter()
            .filter_map(|e| match &e.msg {
                Msg::Escalate { tier, .. } => Some(*tier),
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
            let mut t = Tier {
                escalator: escalator.clone(),
                challenger,
                ..Default::default()
            };
            let mut vcommits: HashMap<String, String> = HashMap::new();
            for e in &mine {
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
            for e in &mine {
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
                        && draw(block_hash, &case, k, offers, panel_size(k)) == *seats
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
            for e in &mine {
                if let Msg::Reseated {
                    tier,
                    height,
                    block_hash,
                    replaced,
                    seat,
                    ..
                } = &e.msg
                {
                    if *tier != k || e.sender != escalator {
                        continue;
                    }
                    let Some(pos) = t.seats.iter().position(|x| x == replaced) else {
                        continue;
                    };
                    let left: Vec<String> = t
                        .listed
                        .iter()
                        .filter(|o| !t.seats.contains(o) && !t.forfeited.contains(o))
                        .cloned()
                        .collect();
                    if !vcommits.contains_key(replaced)
                        && draw(block_hash, &case, k, &left, 1) == vec![seat.clone()]
                        && rpc.block_hash(*height).as_deref() == Some(block_hash.as_str())
                    {
                        t.forfeited.push(replaced.clone());
                        t.seats[pos] = seat.clone();
                        t.seat_height.insert(seat.clone(), *height);
                    }
                }
            }
            let fee = seat_fee(rp.base_fee, k);
            // each seat paid its fee by the escalator, in one transaction or several
            let fee_txs: Vec<&String> = mine
                .iter()
                .filter_map(|e| match &e.msg {
                    Msg::FeePaid { tier, txid, .. } if *tier == k && e.sender == escalator => {
                        Some(txid)
                    }
                    _ => None,
                })
                .collect();
            t.fee_paid = !t.seats.is_empty()
                && t.seats.iter().all(|x| {
                    fee_txs
                        .iter()
                        .any(|txid| rpc.paid_to(txid, &t.offers[x].payout) >= fee)
                });
            for e in &mine {
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
                            *c == hex::encode(
                                verdict.commitment(&wire::h32(salt).unwrap_or_default()),
                            )
                        }) == Some(true);
                    if ok {
                        t.reveals.push((e.sender.clone(), verdict.clone()));
                    }
                }
            }
            for e in &mine {
                if let Msg::TierCommitted { tier, txid, .. } = &e.msg {
                    let cm = tier_commitment(&case, k, &t.seats, &t.reveals);
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
            for e in &mine {
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
            rp.tiers.insert(k, t);
        }
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
        Some((tx, prev))
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
}

/// Every committed tier of every case in the log, ordered by the height of its commitment. Old cases
/// are replayed from the log and the chain, their funding outputs read as created (spent or not).
pub fn ledger(hist: &[Envelope], rpc: &Rpc, oracle_key: &str) -> Vec<TierLog> {
    let mut out = vec![];
    let mut seen = std::collections::HashSet::new();
    for e in hist {
        let Msg::Alert { case_id, .. } = &e.msg else {
            continue;
        };
        if !seen.insert(case_id.clone()) {
            continue;
        }
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
                continue;
            };
            out.push(TierLog {
                case: a.case_hex.clone(),
                tier: k,
                height: h,
                seats: t.seats,
                committers: t.committers,
                reveals: t.reveals,
            });
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
