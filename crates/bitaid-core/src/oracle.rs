//! The oracle (Specification §3.3, Appendix B.3), single-key form.
//!
//! For each pot of each case the oracle commits a one-time nonce point R. For an outcome message m
//! the attestation point is `S_m = R + e·X`, with `e = H_BIP340(R, X, m)`, and the attestation is the
//! BIP340 scalar `s = k + e·x`, so `(R, s)` is a valid BIP340 signature on m and `s·G = S_m`.
//! The payouts are adaptor signatures encrypted to the `S_m`, so the attestation completes exactly
//! one of them. Attesting two messages under one R reveals the key.
//!
//! Milestone M1 uses one key; M2 replaces it with the pool's FROST threshold key, whose
//! attestation has the same form.
use crate::hashes::tagged;
use musig2::secp::{MaybeScalar, Point, Scalar, G};
use std::collections::HashMap;

pub fn random_scalar() -> Scalar {
    loop {
        let b: [u8; 32] = rand::random();
        if let Ok(s) = Scalar::from_slice(&b) {
            return s;
        }
    }
}

/// Negates `s` if needed so that `s·G` has an even y-coordinate (BIP340 convention).
pub fn even(s: Scalar) -> Scalar {
    if (s * G).has_even_y() {
        s
    } else {
        -s
    }
}

/// BIP340 challenge `H(R.x || X.x || m) mod n`.
pub fn challenge(r: &Point, x: &Point, m: &[u8; 32]) -> MaybeScalar {
    let mut buf = Vec::with_capacity(96);
    buf.extend_from_slice(&r.serialize_xonly());
    buf.extend_from_slice(&x.serialize_xonly());
    buf.extend_from_slice(m);
    MaybeScalar::reduce_from(&tagged("BIP0340/challenge", &buf))
}

/// `S_m = R + e·X`: the point a payout for outcome m is encrypted to.
pub fn attestation_point(r: &Point, x: &Point, m: &[u8; 32]) -> Point {
    (*r + challenge(r, x, m) * *x)
        .not_inf()
        .expect("attestation point is not infinity")
}

pub struct Oracle {
    key: Scalar,
    nonces: HashMap<String, Scalar>,
    spent: HashMap<String, [u8; 32]>,
}

impl Oracle {
    pub fn new() -> Self {
        Self::from_secret(random_scalar())
    }
    pub fn from_secret(x: Scalar) -> Self {
        Oracle {
            key: even(x),
            nonces: HashMap::new(),
            spent: HashMap::new(),
        }
    }
    pub fn pubkey(&self) -> Point {
        self.key * G
    }
    pub fn secret_for_tests(&self) -> Scalar {
        self.key
    }
    /// Commits a fresh nonce for `event` (one pot of one case) and returns R.
    pub fn announce(&mut self, event: &str) -> Point {
        self.announce_with(event, random_scalar())
    }
    pub fn announce_with(&mut self, event: &str, k: Scalar) -> Point {
        let k = even(k);
        self.nonces.insert(event.to_string(), k);
        k * G
    }
    /// Attests outcome `m` for `event`. Refuses a second, different message for the same nonce.
    pub fn attest(&mut self, event: &str, m: &[u8; 32]) -> Result<Scalar, &'static str> {
        if let Some(prev) = self.spent.get(event) {
            if prev != m {
                return Err("nonce already spent on another outcome");
            }
        }
        let k = *self.nonces.get(event).ok_or("unknown event")?;
        let r = k * G;
        let s = MaybeScalar::from(k) + challenge(&r, &self.pubkey(), m) * self.key;
        self.spent.insert(event.to_string(), *m);
        s.not_zero().map_err(|_| "zero attestation")
    }
    /// The oracle's co-signature on a transaction digest (BIP340, fresh nonce).
    pub fn cosign(&self, digest: &[u8; 32]) -> [u8; 64] {
        sign_bip340(&self.key, digest)
    }
}

impl Default for Oracle {
    fn default() -> Self {
        Self::new()
    }
}

/// Plain BIP340 signature with libsecp256k1 (via the `bitcoin` crate).
pub fn sign_bip340(secret: &Scalar, digest: &[u8; 32]) -> [u8; 64] {
    use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey};
    let secp = Secp256k1::new();
    let kp = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&secret.serialize()).unwrap());
    secp.sign_schnorr(&Message::from_digest(*digest), &kp)
        .serialize()
}

pub fn verify_bip340(xonly: &[u8; 32], digest: &[u8; 32], sig: &[u8; 64]) -> bool {
    use bitcoin::secp256k1::{schnorr::Signature, Message, Secp256k1, XOnlyPublicKey};
    let secp = Secp256k1::verification_only();
    match (
        XOnlyPublicKey::from_slice(xonly),
        Signature::from_slice(sig),
    ) {
        (Ok(x), Ok(s)) => secp
            .verify_schnorr(&s, &Message::from_digest(*digest), &x)
            .is_ok(),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn attestation_is_bip340_signature_and_matches_point() {
        let mut o = Oracle::new();
        let r = o.announce("c|deposit");
        let m = crate::hashes::outcome_msg("c", "deposit", "returned");
        let s = o.attest("c|deposit", &m).unwrap();
        assert_eq!(s * G, attestation_point(&r, &o.pubkey(), &m));
        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&r.serialize_xonly());
        sig[32..].copy_from_slice(&s.serialize());
        assert!(verify_bip340(&o.pubkey().serialize_xonly(), &m, &sig));
        let m2 = crate::hashes::outcome_msg("c", "deposit", "seized by merit weight");
        assert!(
            o.attest("c|deposit", &m2).is_err(),
            "second outcome under one nonce must be refused"
        );
    }
}
