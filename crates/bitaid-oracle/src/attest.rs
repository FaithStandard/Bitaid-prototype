//! Attestation (Specification B.3 "Attestation"). After replaying the log, member i releases in public,
//! for the pot's nonce index j and outcome m, `s_i = k_{j,i} + e·x_i` with `e = H_BIP340(R_j, Q, m)`.
//! Anyone checks it against the member's public shares: `s_i·G = R_{j,i} + e·X_i`; a share for an outcome
//! the log does not support is therefore signed evidence against the member who released it. Any t
//! valid shares interpolate to `s`, and `(R_j, s)` is a BIP340 signature on m under Q: the scalar that
//! completes the pre-signed payout for m and no other.
use crate::keygen::MemberKey;
use crate::nonces::Batch;
use bitaid_core::oracle::challenge;
use musig2::secp::{MaybePoint, MaybeScalar, Point, Scalar, G};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Share {
    pub member: u16,
    pub batch: u64,
    pub index: usize,
    pub message: [u8; 32],
    pub s: Scalar,
}

/// This member's attestation share. Refuses a second, different message for the same nonce index.
pub fn share(
    key: &MemberKey,
    batch: &mut Batch,
    index: usize,
    m: &[u8; 32],
) -> Result<Share, &'static str> {
    if let Some(prev) = batch.spent.get(&index) {
        if prev != m {
            return Err("nonce index already spent on another outcome");
        }
    }
    let q = key.pool_key();
    let q = if q.has_even_y() { q } else { -q };
    let e = challenge(&batch.r[index], &q, m);
    let s = (MaybeScalar::from(batch.mine[index]) + e * key.attest_share())
        .not_zero()
        .map_err(|_| "zero")?;
    batch.spent.insert(index, *m);
    Ok(Share {
        member: key.id,
        batch: batch.batch,
        index,
        message: *m,
        s,
    })
}

/// Checks a published share against the member's public key share and public nonce share.
pub fn verify(key: &MemberKey, batch: &Batch, sh: &Share) -> bool {
    let q = key.pool_key();
    let q = if q.has_even_y() { q } else { -q };
    let e = challenge(&batch.r[sh.index], &q, &sh.message);
    let Some(rji) = batch.public[sh.index].get(&sh.member) else {
        return false;
    };
    MaybePoint::from(sh.s * G) == MaybePoint::from(*rji) + e * key.attest_public(sh.member)
}

/// Combines t valid shares into the attestation scalar s, checked against `S_m = R_j + e·Q`.
pub fn combine(
    key: &MemberKey,
    batch: &Batch,
    shares: &[Share],
    t: usize,
) -> Result<Scalar, &'static str> {
    let valid: Vec<&Share> = shares
        .iter()
        .filter(|s| verify(key, batch, s))
        .take(t)
        .collect();
    if valid.len() < t {
        return Err("fewer than t valid shares");
    }
    let ids: Vec<u16> = valid.iter().map(|s| s.member).collect();
    let mut s = MaybeScalar::Zero;
    for sh in &valid {
        s += crate::lagrange(sh.member, &ids) * sh.s;
    }
    let s = s.not_zero().map_err(|_| "zero")?;
    let q = key.pool_key();
    let q = if q.has_even_y() { q } else { -q };
    let m = &valid[0].message;
    let point: Point = bitaid_core::oracle::attestation_point(&batch.r[valid[0].index], &q, m);
    if s * G != point {
        return Err("combined scalar does not match the attestation point");
    }
    Ok(s)
}
