//! Bitaid oracle pool (prototype, milestone M2). Specification §3.3 and Appendix B.3.
//!
//! * `keygen` — the pool key by distributed key generation (the Zcash Foundation's FROST DKG,
//!   verifiable shares, proofs of knowledge), tweaked as BIP86 prescribes.
//! * `nonces` — batches of one-time nonces generated jointly in advance (Feldman-verified sharing),
//!   each later spent on exactly one attestation.
//! * `attest` — publicly verifiable attestation shares `s_i = k_{j,i} + e·x_i`, released in public;
//!   any t valid shares combine to the BIP340 signature that completes a pre-signed payout.
//! * `cosign` — FROST two-round co-signatures for the acceptance, withdrawal and forfeiture leaves,
//!   with a ROAST-style coordinator that replaces members who stall.
//!
//! Prototype for testing and review: never hold real funds with it.
pub mod attest;
pub mod conv;
pub mod cosign;
pub mod keygen;
pub mod net;
pub mod nonces;

/// Lagrange coefficient at zero for member `i` within the set `ids` (identifiers are 1-based).
pub fn lagrange(i: u16, ids: &[u16]) -> musig2::secp::Scalar {
    use musig2::secp::{MaybeScalar, Scalar};
    let s = |x: u16| Scalar::try_from(x as u128).expect("nonzero id");
    let mut num = MaybeScalar::one();
    let mut den = MaybeScalar::one();
    for &j in ids {
        if j == i {
            continue;
        }
        num *= s(j);
        den *= MaybeScalar::from(s(j)) - MaybeScalar::from(s(i));
    }
    let den = den.not_zero().expect("distinct ids");
    (num * den.invert()).not_zero().expect("nonzero")
}
