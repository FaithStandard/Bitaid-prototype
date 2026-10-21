//! The pre-signed incident set (Specification §3.2): at acceptance the caller's scoped key and the
//! signing responders sign every payout each pot can end in, each as an adaptor signature encrypted to
//! the attestation point of that ending, plus one refund per pot valid after the refund height.
//! Settlement then needs only the oracle's attestation for the ending the case reached.
use crate::endings::{endings, Ending, Pot};
use crate::hashes::outcome_msg;
use crate::musig::{self, Signed};
use crate::oracle::attestation_point;
use crate::payouts::{outputs, Parties};
use crate::txbuild::{self, keyspend_digest};
use bitcoin::{OutPoint, ScriptBuf, Transaction, TxOut, Txid, Witness};
use musig2::adaptor::AdaptorSignature;
use musig2::secp::{Point, Scalar};
use musig2::KeyAggContext;

/// Everything fixed at acceptance.
#[derive(Clone, Debug)]
pub struct IncidentTerms {
    pub case: String,
    /// Values of the deposit, reward and bounty pots in sats.
    pub pots: [u64; 3],
    pub parties: Parties,
    /// Caller's scoped key first, then the signing responders.
    pub signers: Vec<Point>,
    pub oracle: Point,
    /// The oracle's committed nonce point for each pot.
    pub oracle_nonces: [Point; 3],
    pub refund_height: u32,
}

#[derive(Clone, Debug)]
pub struct Payout {
    pub ending: Ending,
    pub tx: Transaction,
    pub digest: [u8; 32],
    pub point: Point,
    pub presig: Option<AdaptorSignature>,
}

#[derive(Clone, Debug)]
pub struct Refund {
    pub pot: Pot,
    pub tx: Transaction,
    pub digest: [u8; 32],
    pub sig: Option<[u8; 64]>,
}

pub struct IncidentSet {
    pub terms: IncidentTerms,
    pub ctx: KeyAggContext,
    pub pot_spk: ScriptBuf,
    pub incident_txid: Txid,
    pub pot_outpoints: [Option<OutPoint>; 3],
    pub payouts: Vec<Payout>,
    pub refunds: Vec<Refund>,
}

pub fn event_id(case: &str, pot: Pot) -> String {
    format!("{case}|{}", pot.name())
}

impl IncidentSet {
    /// Builds every transaction of the set from the terms and the incident transaction's id.
    /// Every signer runs this and must arrive at byte-identical transactions.
    pub fn build(terms: IncidentTerms, incident_txid: Txid) -> Self {
        let ctx = musig::taproot_ctx(&terms.signers);
        let pot_spk = musig::pot_script_pubkey(&ctx);
        // outputs of the incident transaction are the non-empty pots in order
        let mut pot_outpoints = [None; 3];
        let mut vout = 0u32;
        for p in Pot::ALL {
            if terms.pots[p.index()] > 0 {
                pot_outpoints[p.index()] = Some(OutPoint {
                    txid: incident_txid,
                    vout,
                });
                vout += 1;
            }
        }
        let k = terms.signers.len() - 1;
        let mut payouts = Vec::new();
        for e in endings(k) {
            let i = e.pot.index();
            let (Some(op), v) = (pot_outpoints[i], terms.pots[i]) else {
                continue;
            };
            let tx = txbuild::payout(op, &outputs(&e, v, &terms.parties));
            let digest = keyspend_digest(
                &tx,
                0,
                &[TxOut {
                    value: bitcoin::Amount::from_sat(v),
                    script_pubkey: pot_spk.clone(),
                }],
            );
            let m = outcome_msg(&terms.case, e.pot.name(), &e.label);
            let point = attestation_point(&terms.oracle_nonces[i], &terms.oracle, &m);
            payouts.push(Payout {
                ending: e,
                tx,
                digest,
                point,
                presig: None,
            });
        }
        let mut refunds = Vec::new();
        for p in Pot::ALL {
            let i = p.index();
            if let Some(op) = pot_outpoints[i] {
                let tx = txbuild::refund(
                    op,
                    terms.pots[i],
                    &terms.parties.caller,
                    terms.refund_height,
                );
                let digest =
                    keyspend_digest(&tx, 0, &[txbuild::txout(terms.pots[i], pot_spk.clone())]);
                refunds.push(Refund {
                    pot: p,
                    tx,
                    digest,
                    sig: None,
                });
            }
        }
        IncidentSet {
            terms,
            ctx,
            pot_spk,
            incident_txid,
            pot_outpoints,
            payouts,
            refunds,
        }
    }

    pub fn len(&self) -> usize {
        self.payouts.len()
    }
    pub fn is_empty(&self) -> bool {
        self.payouts.is_empty()
    }

    /// Signs the whole set in one process with all signers' secrets (tests, single-machine tools).
    pub fn sign_locally(&mut self, secrets: &[Scalar]) {
        for p in &mut self.payouts {
            if let Signed::Adaptor(a) =
                musig::sign_locally(&self.ctx, secrets, Some(p.point), &p.digest)
            {
                p.presig = Some(a);
            }
        }
        for r in &mut self.refunds {
            if let Signed::Complete(s) = musig::sign_locally(&self.ctx, secrets, None, &r.digest) {
                r.sig = Some(s);
            }
        }
    }

    /// Verifies every pre-signature against its digest and attestation point.
    pub fn verify_all(&self) -> bool {
        self.payouts.iter().all(|p| {
            p.presig
                .map(|a| musig::verify_presig(&self.ctx, &a, &p.digest, p.point))
                .unwrap_or(false)
        })
    }

    pub fn find(&self, pot: Pot, label: &str) -> Option<&Payout> {
        self.payouts
            .iter()
            .find(|p| p.ending.pot == pot && p.ending.label == label)
    }

    /// Completes the payout for `label` with the oracle's attestation; returns a broadcastable
    /// transaction, or None if the attestation does not complete it (a different outcome's).
    pub fn complete(&self, pot: Pot, label: &str, attestation: Scalar) -> Option<Transaction> {
        let p = self.find(pot, label)?;
        let sig = musig::complete(p.presig.as_ref()?, attestation)?;
        let x: Point = self.ctx.aggregated_pubkey();
        if !crate::oracle::verify_bip340(&x.serialize_xonly(), &p.digest, &sig) {
            return None;
        }
        let mut tx = p.tx.clone();
        tx.input[0].witness = Witness::from_slice(&[sig.to_vec()]);
        Some(tx)
    }

    pub fn refund(&self, pot: Pot) -> Option<Transaction> {
        let r = self.refunds.iter().find(|r| r.pot == pot)?;
        let mut tx = r.tx.clone();
        tx.input[0].witness = Witness::from_slice(&[r.sig?.to_vec()]);
        Some(tx)
    }
}
