//! The incident as every party reconstructs it from the alert and the roster, so that each builds
//! byte-identical transactions without trusting anyone else's copy.
use crate::node::point_from;
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
    pub fallback_height: u32,
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
        if oracle_key != oracle_expected {
            return Err("funding output names another oracle".into());
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
        })
    }
}

/// The signers in order: the caller's scoped key, then the seats.
pub fn signers(a: &Alerted, r: &Rostered) -> Vec<Point> {
    let mut v = vec![a.caller_point()];
    v.extend(r.musig_keys.iter().copied());
    v
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
        oracle: point_from(&format!("02{}", a.oracle_key)).unwrap(),
        oracle_nonces: r.oracle_nonces,
        refund_height: r.refund_height,
    }
}

pub fn build_set(a: &Alerted, r: &Rostered) -> IncidentSet {
    IncidentSet::build(terms(a, r), r.incident_txid)
}
