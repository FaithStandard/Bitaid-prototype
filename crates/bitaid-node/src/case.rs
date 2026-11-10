//! The incident as every party reconstructs it from the alert and the roster, so that each builds
//! byte-identical transactions without trusting anyone else's copy.
use crate::node::{point_from, point_hex};
use crate::wire::{self, h32, Msg, Template};
use bitaid_core::hashes::tagged;
use bitaid_core::oracle::verify_bip340;
use bitaid_core::outputs;
use bitaid_core::payouts::{caller_refund_spk, Parties};
use bitaid_core::presign::{IncidentSet, IncidentTerms};
use bitaid_core::txbuild;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{OutPoint, ScriptBuf, Transaction, Txid};
use musig2::secp::Point;
use std::str::FromStr;

/// What the wallet key signs at registration: the scoped key, the template and the funding outpoint.
pub fn registration_digest(scoped: &str, t: &Template, funding: &str) -> [u8; 32] {
    let mut b = hex::decode(scoped).unwrap_or_default();
    b.extend_from_slice(&t.hash());
    b.extend_from_slice(funding.as_bytes());
    tagged("Bitaid/registration", &b)
}

#[derive(Clone, Debug)]
pub struct Alerted {
    pub case_hex: String,
    pub case_id: [u8; 32],
    pub caller: String,
    pub cell: String,
    pub template: Template,
    pub funding: OutPoint,
    pub funding_value: u64,
    pub wallet_key: String,
    pub scoped_key: String,
    pub oracle_key: String,
    pub attest_key: String,
    pub fallback_height: u32,
}

/// The bond a responder needs to accept this case: twice the most it could capture (the reward and
/// the bounty, all to one seat), and never below `floor` (§2.3, review finding D-12).
pub fn exposure_bond(a: &Alerted, floor: u64) -> u64 {
    floor.max(2 * (a.template.pots[1] + a.template.pots[2]))
}

/// How a registration names its pool: the co-signing key, then the attestation key.
pub fn pool_id(cosign: &str, attest: &str) -> String {
    format!("{cosign}{attest}")
}

impl Alerted {
    /// Checks an alert and the registration inside it. `chain_spk` is the funding output as the
    /// chain shows it (None if missing or spent).
    pub fn check(
        sender: &str,
        msg: &Msg,
        chain: impl Fn(&OutPoint) -> Option<(u64, ScriptBuf)>,
        oracle_expected: &str,
    ) -> Result<Alerted, String> {
        let Msg::Alert {
            case_id,
            cell,
            registration,
            template,
            ..
        } = msg
        else {
            return Err("not an alert".into());
        };
        let reg = wire::verify(&wire::unb64(registration).ok_or("registration encoding")?)?;
        if reg.sender != sender {
            return Err("registration is not the alerting caller's".into());
        }
        let Msg::Registration {
            funding,
            funding_value,
            wallet_key,
            scoped_key,
            oracle_key,
            attest_key,
            fallback_height,
            template: rt,
            wallet_sig,
        } = reg.msg
        else {
            return Err("not a registration".into());
        };
        if &rt != template {
            return Err("alert economics differ from the registered template".into());
        }
        rt.check()?;
        // `oracle_expected` is the pool's id: both its keys, which must be distinct (or, for a replay
        // of the log that relies on no attestation, the co-signing key alone)
        let named = pool_id(&oracle_key, &attest_key) == oracle_expected
            || (oracle_expected.len() == 64 && oracle_key == oracle_expected);
        if !named || oracle_key == attest_key {
            return Err("registration names another oracle".into());
        }
        let d = registration_digest(&scoped_key, &rt, &funding);
        let sig: [u8; 64] = hex::decode(&wallet_sig)
            .ok()
            .and_then(|v| v.try_into().ok())
            .ok_or("sig")?;
        if !verify_bip340(&h32(&wallet_key).ok_or("wallet key")?, &d, &sig) {
            return Err("wallet signature over the registration is invalid".into());
        }
        let op = OutPoint::from_str(&funding).map_err(|e| e.to_string())?;
        let secp = Secp256k1::verification_only();
        let x = |h: &str| wire::xonly(h).ok_or("bad key");
        let tree = outputs::funding(
            &secp,
            &x(&wallet_key)?,
            &x(&scoped_key)?,
            &x(&oracle_key)?,
            fallback_height,
        );
        let (v, spk) = chain(&op).ok_or("funding output missing or spent")?;
        if spk != tree.script_pubkey() {
            return Err("funding output's script is not the registered one".into());
        }
        if bitcoin::bip32::Xpub::from_str(&rt.refund_xpub).is_err() {
            return Err("template's refund xpub does not parse".into());
        }
        let total: u64 = rt.pots.iter().sum();
        if v != total || v != funding_value {
            return Err(format!(
                "funding holds {v} sats, the template's pots sum to {total}"
            ));
        }
        Ok(Alerted {
            case_hex: case_id.clone(),
            case_id: h32(case_id).ok_or("case id")?,
            caller: sender.into(),
            cell: cell.clone(),
            template: rt,
            funding: op,
            funding_value: v,
            wallet_key,
            scoped_key,
            oracle_key,
            attest_key,
            fallback_height,
        })
    }

    pub fn funding_tree(&self) -> bitaid_core::tree::ScriptTree {
        let secp = Secp256k1::verification_only();
        outputs::funding(
            &secp,
            &wire::xonly(&self.wallet_key).unwrap(),
            &wire::xonly(&self.scoped_key).unwrap(),
            &wire::xonly(&self.oracle_key).unwrap(),
            self.fallback_height,
        )
    }

    /// The caller's MuSig key: its scoped key, lifted with even y (callers pick an even key).
    pub fn caller_point(&self) -> Point {
        point_from(&format!("02{}", self.scoped_key)).unwrap()
    }
}

#[derive(Clone, Debug)]
pub struct Rostered {
    pub set_version: u32,
    pub seats: Vec<String>,
    pub musig_keys: Vec<Point>,
    pub payout_spks: Vec<ScriptBuf>,
    pub oracle_nonces: [Point; 3],
    pub refund_height: u32,
    pub incident_txid: Txid,
    pub sealed_keys: Vec<String>,
    pub archivists: Vec<String>,
    /// the caller's fresh pot key for this case (None: an older roster, the scoped key)
    pub caller_musig: Option<Point>,
}

impl Rostered {
    pub fn from_msg(m: &Msg) -> Option<Rostered> {
        let Msg::Roster {
            set_version,
            seats,
            musig_keys,
            payout_spks,
            oracle_nonces,
            refund_height,
            incident_txid,
            sealed_keys,
            archivists,
            caller_musig,
            ..
        } = m
        else {
            return None;
        };
        let n: Vec<Point> = oracle_nonces.iter().filter_map(|s| point_from(s)).collect();
        Some(Rostered {
            set_version: *set_version,
            seats: seats.clone(),
            musig_keys: musig_keys.iter().filter_map(|s| point_from(s)).collect(),
            payout_spks: payout_spks
                .iter()
                .filter_map(|s| ScriptBuf::from_hex(s).ok())
                .collect(),
            oracle_nonces: [*n.first()?, *n.get(1)?, *n.get(2)?],
            refund_height: *refund_height,
            incident_txid: Txid::from_str(incident_txid).ok()?,
            sealed_keys: sealed_keys.clone(),
            archivists: archivists.clone(),
            caller_musig: point_from(caller_musig),
        })
    }
}

/// What a responder's signed Accept committed to, as the pool reads it from the log.
#[derive(Clone, Debug)]
pub struct AcceptInfo {
    pub musig_key: String,
    pub payout_spk: String,
    pub bond: String,
    pub bond_scoped: String,
    pub bond_cold: String,
    pub bond_fallback: u32,
}

/// A pool member's check of a roster before it confirms it, co-signs its incident or attests under it
/// (Specification §3.2): every seat accepted this case with exactly these keys and payout scripts, each
/// seat's bond is on chain with the bond script, at least `min_bond` and at least `fallback_margin`
/// blocks of its fallback left, the refund height is a full refund delay away, and the incident
/// transaction is the template's. `utxo` reads an unspent output.
#[allow(clippy::too_many_arguments)]
pub fn check_roster(
    a: &Alerted,
    r: &Rostered,
    accepts: &std::collections::HashMap<String, AcceptInfo>,
    utxo: impl Fn(&OutPoint) -> Option<bitcoin::TxOut>,
    tip: u32,
    min_bond: u64,
    fallback_margin: u32,
) -> Result<(), String> {
    use std::collections::HashSet;
    if r.seats.is_empty() || r.seats.len() > a.template.max_signers as usize {
        return Err(format!("{} seats", r.seats.len()));
    }
    if r.seats.iter().collect::<HashSet<_>>().len() != r.seats.len() {
        return Err("a seat listed twice".into());
    }
    if r.musig_keys.len() != r.seats.len() || r.payout_spks.len() != r.seats.len() {
        return Err("keys or payout scripts do not match the seats".into());
    }
    // a little slack: the caller set it a few blocks ago
    if r.refund_height + 12 < tip + a.template.refund_delay {
        return Err(format!(
            "refund height {} is less than the refund delay ({}) away from block {tip}",
            r.refund_height, a.template.refund_delay
        ));
    }
    let secp = Secp256k1::verification_only();
    let oracle = wire::xonly(&a.oracle_key).ok_or("oracle key")?;
    for (i, who) in r.seats.iter().enumerate() {
        let acc = accepts
            .get(who)
            .ok_or_else(|| format!("seat {} never accepted this case", &who[..8.min(who.len())]))?;
        if point_hex(&r.musig_keys[i]) != acc.musig_key {
            return Err(format!("seat {i}: not the signing key it accepted with"));
        }
        if r.payout_spks[i].to_hex_string() != acc.payout_spk {
            return Err(format!("seat {i}: not the payout script it accepted with"));
        }
        if acc.bond_fallback < tip + fallback_margin {
            return Err(format!("seat {i}: its bond's fallback (block {}) is too near", acc.bond_fallback));
        }
        let op: OutPoint = acc.bond.parse().map_err(|_| format!("seat {i}: bond outpoint"))?;
        let out = utxo(&op).ok_or_else(|| format!("seat {i}: its bond is not an unspent output"))?;
        let t = bitaid_core::outputs::bond(
            &secp,
            &wire::xonly(&acc.bond_scoped).ok_or("bond key")?,
            &wire::xonly(&acc.bond_cold).ok_or("bond key")?,
            &oracle,
            acc.bond_fallback,
        );
        if out.script_pubkey != t.script_pubkey() || out.value.to_sat() < min_bond {
            return Err(format!("seat {i}: not a bond of at least {min_bond} sats"));
        }
    }
    if incident_tx(a, r).compute_txid() != r.incident_txid {
        return Err("not the template's incident transaction".into());
    }
    Ok(())
}

/// The set-bound case id of this roster's outcome messages (Specification B.2).
pub fn bound_id(a: &Alerted, r: &Rostered) -> [u8; 32] {
    bitaid_core::presign::set_bound_id(&terms(a, r), &r.incident_txid)
}

/// The signers in order: the caller's scoped key, then the seats.
pub fn signers(a: &Alerted, r: &Rostered) -> Vec<Point> {
    let mut v = vec![r.caller_musig.unwrap_or_else(|| a.caller_point())];
    v.extend(r.musig_keys.iter().copied());
    v
}

/// The parties' aggregate key (the caller's pot key and every seat's, MuSig2, untweaked): the
/// seizure output's fallback after a year pays them together, not an archivist (review finding 12).
pub fn parties_key(a: &Alerted, r: &Rostered) -> bitcoin::XOnlyPublicKey {
    let ctx = musig2::KeyAggContext::new(signers(a, r)).expect("valid key set");
    let p: Point = ctx.aggregated_pubkey();
    bitcoin::XOnlyPublicKey::from_slice(&p.serialize_xonly()).expect("x-only")
}

pub fn pot_spk(a: &Alerted, r: &Rostered) -> ScriptBuf {
    bitaid_core::musig::pot_script_pubkey(&bitaid_core::musig::taproot_ctx(&signers(a, r)))
}

/// The incident transaction the funding output's accept leaf will spend into.
pub fn incident_tx(a: &Alerted, r: &Rostered) -> Transaction {
    txbuild::incident(a.funding, &a.template.pots, &pot_spk(a, r))
}

pub fn terms(a: &Alerted, r: &Rostered) -> IncidentTerms {
    let xpub = bitcoin::bip32::Xpub::from_str(&a.template.refund_xpub).expect("refund xpub");
    IncidentTerms {
        case_id: a.case_id,
        set_version: r.set_version,
        pots: a.template.pots,
        parties: Parties {
            caller: caller_refund_spk(&xpub, &a.case_id),
            responders: r.payout_spks.clone(),
            merit: vec![1; r.seats.len()],
            good_faith_pct: a.template.good_faith_pct as u64,
        },
        signers: signers(a, r),
        oracle: point_from(&format!("02{}", a.attest_key)).unwrap(),
        oracle_nonces: r.oracle_nonces,
        refund_height: r.refund_height,
    }
}

pub fn build_set(a: &Alerted, r: &Rostered) -> IncidentSet {
    IncidentSet::build(terms(a, r), r.incident_txid)
}
