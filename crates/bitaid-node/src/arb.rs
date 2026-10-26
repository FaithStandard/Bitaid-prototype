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

/// Penalty steps in tenths of the seat fee. The isolation factor of §10.4 is rounded down to half a
/// fee, so each seat pre-signs five forfeitures when it takes the seat, not one per possible split.
pub const STEPS: [u64; 5] = [20, 25, 30, 35, 40];

/// The step (tenths) for a factor: rounded down to the half, between 2× and 4×.
pub fn step_of(factor: f64) -> u64 {
    (((factor * 2.0).floor() / 2.0 * 10.0).round() as u64).clamp(20, 40)
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
    /// The same keys holding another output (a challenge bond).
    pub fn stake(&self, op: OutPoint, value: u64) -> Bond {
        Bond {
            op,
            value,
            ..self.clone()
        }
    }
    /// Forfeits the whole output into the seizure output (a challenge bond).
    pub fn forfeit_all(
        &self,
        oracle: &XOnlyPublicKey,
        seizure: &ScriptBuf,
    ) -> (Transaction, [u8; 32]) {
        let t = self.tree(oracle);
        let tx = txbuild::payout(self.op, &[(self.value, seizure.clone())]);
        let d = txbuild::scriptspend_digest(
            &tx,
            0,
            &[txbuild::txout(self.value, t.script_pubkey())],
            &t.scripts[bond_leaf::FORFEIT],
        );
        (tx, d)
    }
    /// The five pre-signed forfeitures' digests at a seat fee, in step order.
    pub fn forfeit_digests(
        &self,
        oracle: &XOnlyPublicKey,
        fee: u64,
        seizure: &ScriptBuf,
    ) -> Vec<[u8; 32]> {
        STEPS
            .iter()
            .map(|st| self.penalty_tx(oracle, st * fee / 10, seizure).1)
            .collect()
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
    /// per seat, its stake and the five verified pre-signed forfeitures of it
    pub forfeits: HashMap<String, (Bond, Vec<String>)>,
    /// when a dissenting arbitrator of the tier below opened this one: its challenge bond
    pub challenge: Option<Challenge>,
}

/// A challenge bond (§10.4): a separate output under the challenger's bond script, its whole value
/// pre-signed to the case's seizure output, forfeited only if the larger panel does not agree.
#[derive(Clone, Debug)]
pub struct Challenge {
    pub stake: Bond,
    pub sig: String,
}

/// A seat's stake, in tenths of the seat fee: the largest penalty step, 4× (more with momentum).
pub const SEAT_STAKE_STEPS: u64 = 40;

/// Checks a seat's pre-signed forfeitures: the stake is an output of at least 4× the fee under the
/// seat-holder's bond script, and each signature is its scoped key's over that step's forfeiture.
#[allow(clippy::too_many_arguments)]
pub fn verify_forfeits(
    bond: &Bond,
    stake: &str,
    value: u64,
    sigs: &[String],
    oracle: &XOnlyPublicKey,
    fee: u64,
    seizure: &ScriptBuf,
    rpc: &Rpc,
) -> Option<Bond> {
    let st = bond.stake(OutPoint::from_str(stake).ok()?, value);
    let ds = st.forfeit_digests(oracle, fee, seizure);
    (value >= SEAT_STAKE_STEPS * fee / 10
        && sigs.len() == ds.len()
        && ds
            .iter()
            .zip(sigs)
            .all(|(d, g)| schnorr_ok(&bond.scoped, d, g))
        && rpc.paid_to(&st.op.txid.to_string(), &bond.tree(oracle).script_pubkey()) >= value)
        .then_some(st)
}

/// The challenge bond, in tenths of the case fee: 3× (§10.4, provisional).
pub const CHALLENGE_STEPS: u64 = 30;

impl Tier {
    pub fn verdict(&self) -> Option<Ballot> {
        if !self.committed || self.reveals.len() < self.seats.len() {
            return None;
        }
        let v: Vec<Ballot> = self.reveals.iter().map(|x| x.1.clone()).collect();
        supermajority(self.seats.len(), &v)
    }
}

/// A forfeiture the final ruling calls for.
#[derive(Clone, Debug)]
pub struct Penalty {
    /// a challenge bond the larger panel did not uphold, rather than an incoherent vote
    pub challenge: bool,
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
    pub fn build(hist: &[Envelope], a: &Alerted, r: &Rostered, rpc: &Rpc) -> Option<Replay> {
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
        let seizure = rp.seizure_spk();
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
            // who opens tier k: a party, or a dissenter of tier k-1 who staked a challenge bond (§10.4)
            let mut opener: Option<(String, Option<Challenge>)> = None;
            for e in &mine {
                let Msg::Escalate { tier, .. } = &e.msg else {
                    continue;
                };
                if *tier != k {
                    continue;
                }
                let s = &e.sender;
                if rp.parties.iter().any(|p| &p.0 == s) {
                    opener = Some((s.clone(), None));
                    break;
                }
                let (Some(pt), Some(spk)) = (prev.as_ref(), seizure.as_ref()) else {
                    continue;
                };
                let (Some(pv), Some(bond)) = (pt.verdict(), pt.offers.get(s)) else {
                    continue;
                };
                let dissented = pt
                    .reveals
                    .iter()
                    .any(|(x, v)| x == s && verdict_key(v) != verdict_key(&pv));
                if !dissented {
                    continue;
                }
                let ch = mine.iter().find_map(|c| match &c.msg {
                    Msg::Challenge {
                        tier,
                        stake,
                        value,
                        sig,
                        ..
                    } if *tier == k && c.sender == *s => {
                        let ch = Challenge {
                            stake: bond.stake(OutPoint::from_str(stake).ok()?, *value),
                            sig: sig.clone(),
                        };
                        let (_, d) = ch.stake.forfeit_all(&oracle, spk);
                        let ok = *value >= CHALLENGE_STEPS * rp.base_fee / 10
                            && rpc.paid_to(
                                &ch.stake.op.txid.to_string(),
                                &bond.tree(&oracle).script_pubkey(),
                            ) >= *value
                            && schnorr_ok(&bond.scoped, &d, sig);
                        ok.then_some(ch)
                    }
                    _ => None,
                });
                if let Some(ch) = ch {
                    opener = Some((s.clone(), Some(ch)));
                    break;
                }
            }
            let Some((escalator, challenge)) = opener else {
                break;
            };
            let mut t = Tier {
                escalator: escalator.clone(),
                challenge,
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
                    }
                }
            }
            let fee = seat_fee(rp.base_fee, k);
            for e in &mine {
                if let Msg::FeePaid { tier, txid, .. } = &e.msg {
                    if *tier == k
                        && e.sender == escalator
                        && !t.fee_paid
                        && !t.seats.is_empty()
                        && t.seats
                            .iter()
                            .all(|x| rpc.paid_to(txid, &t.offers[x].payout) >= fee)
                    {
                        t.fee_paid = true;
                    }
                }
            }
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
                    }
                }
            }
            if let Some(spk) = &seizure {
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
                        let Some(b) = t
                            .offers
                            .get(s)
                            .filter(|_| *tier == k && t.seats.contains(s))
                        else {
                            continue;
                        };
                        if t.forfeits.contains_key(s) {
                            continue;
                        }
                        if let Some(st) =
                            verify_forfeits(b, stake, *value, sigs, &oracle, fee, spk, rpc)
                        {
                            t.forfeits.insert(s.clone(), (st, sigs.clone()));
                        }
                    }
                }
            }
            rp.tiers.insert(k, t);
        }
        Some(rp)
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
                let step = step_of(penalty_factor(n_f, agree.max(1)));
                let fee = seat_fee(self.base_fee, *k);
                let Some((bond, pre)) = t.forfeits.get(arb) else {
                    continue;
                };
                let i = STEPS.iter().position(|x| *x == step).unwrap();
                let amount = step * fee / 10;
                let (tx, digest) = bond.penalty_tx(&self.oracle, amount, &spk);
                out.push(Penalty {
                    challenge: false,
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
            // a challenge the larger panels did not uphold: the challenge bond is forfeit whole
            if let Some(ch) = &t.challenge {
                let prev_vote = self
                    .tiers
                    .get(&(k - 1))
                    .and_then(|p| p.reveals.iter().find(|x| x.0 == t.escalator))
                    .map(|x| verdict_key(&x.1));
                if prev_vote.as_ref() != Some(&fk) {
                    let (tx, digest) = ch.stake.forfeit_all(&self.oracle, &spk);
                    out.push(Penalty {
                        challenge: true,
                        arbitrator: t.escalator.clone(),
                        tier: *k,
                        step: CHALLENGE_STEPS,
                        amount: ch.stake.value,
                        bond: ch.stake.clone(),
                        pre: ch.sig.clone(),
                        tx,
                        digest,
                    });
                }
            }
        }
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
        // a party's payout script, or a challenger's (the payout named in its bond's offer)
        let payout_of = |who: &str| {
            self.parties
                .iter()
                .find(|p| p.0 == who)
                .and_then(|p| p.1.clone())
                .or_else(|| {
                    self.tiers.values().find_map(|t| {
                        t.challenge
                            .as_ref()
                            .filter(|_| t.escalator == who)
                            .map(|c| c.stake.payout.clone())
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
            // a challenger's fees are refunded only if the larger panel agreed with it
            if t.challenge.is_some() && !vind.iter().any(|v| v.0 == t.escalator) {
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
