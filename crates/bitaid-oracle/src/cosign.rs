//! Threshold co-signatures (Specification B.3 "Liveness"): FROST's two rounds among any t online
//! members, for messages not known in advance — the incident transaction at acceptance, withdrawals and
//! forfeitures. A ROAST-style coordinator starts a session with the first t members whose commitments
//! arrive; a member that does not return its share is dropped and a new session starts with others, so
//! one staller delays a signature but never blocks it.
use crate::conv;
use crate::keygen::MemberKey;
use frost_secp256k1_tr as frost;
use std::collections::{BTreeMap, BTreeSet};

/// How a simulated member behaves in a session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Behaviour {
    Honest,
    Offline,
    /// Sends a commitment, then never a share.
    Stalls,
}

pub struct Outcome {
    pub signature: [u8; 64],
    pub sessions: usize,
    pub signers: Vec<u16>,
}

/// Runs the coordinator against members in one process. Returns the BIP340 signature on `msg` under
/// the pool key, valid for the pool's x-only key in a tapscript leaf.
pub fn sign_local(
    keys: &[MemberKey],
    behaviour: &BTreeMap<u16, Behaviour>,
    t: usize,
    msg: &[u8; 32],
) -> Result<Outcome, String> {
    let mut rng = rand::thread_rng();
    let public = keys[0].public.clone();
    let mut excluded: BTreeSet<u16> = keys
        .iter()
        .filter(|k| behaviour.get(&k.id) == Some(&Behaviour::Offline))
        .map(|k| k.id)
        .collect();
    let mut sessions = 0;
    loop {
        sessions += 1;
        let responsive: Vec<&MemberKey> =
            keys.iter().filter(|k| !excluded.contains(&k.id)).collect();
        if responsive.len() < t {
            return Err(format!(
                "only {} responsive members, need {t}",
                responsive.len()
            ));
        }
        let chosen: Vec<&MemberKey> = responsive.into_iter().take(t).collect();
        let mut nonces = BTreeMap::new();
        let mut commitments = BTreeMap::new();
        for k in &chosen {
            let (n, c) = frost::round1::commit(k.key_package.signing_share(), &mut rng);
            nonces.insert(k.id, n);
            commitments.insert(conv::id(k.id), c);
        }
        let package = frost::SigningPackage::new(commitments, msg);
        let mut shares = BTreeMap::new();
        for k in &chosen {
            if behaviour.get(&k.id) == Some(&Behaviour::Stalls) {
                excluded.insert(k.id); // timed out: replaced in the next session
                continue;
            }
            let sh = frost::round2::sign(&package, &nonces[&k.id], &k.key_package)
                .map_err(|e| e.to_string())?;
            shares.insert(conv::id(k.id), sh);
        }
        if shares.len() < t {
            continue;
        }
        let sig = frost::aggregate(&package, &shares, &public).map_err(|e| e.to_string())?;
        let bytes = sig.serialize().map_err(|e| e.to_string())?;
        let mut out = [0u8; 64];
        out.copy_from_slice(&bytes);
        return Ok(Outcome {
            signature: out,
            sessions,
            signers: chosen.iter().map(|k| k.id).collect(),
        });
    }
}
