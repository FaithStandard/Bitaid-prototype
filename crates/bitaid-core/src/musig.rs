//! MuSig2 (BIP327) for the incident outputs, with adaptor signatures.
//!
//! Each pot is a key-path-only taproot output whose internal key aggregates the caller's scoped
//! key and the signing responders' keys (in that order), tweaked as BIP86 prescribes. Signing runs in
//! two rounds per message: every signer publishes a nonce pair, then a partial signature over the
//! aggregate nonce. For a pre-signed payout the session is bound to the outcome's attestation point
//! T, so the aggregate is an adaptor signature that becomes valid only with the oracle's scalar for T.
use musig2::adaptor::{self, AdaptorSignature};
use musig2::secp::{MaybeScalar, Point, Scalar};
use musig2::{AggNonce, KeyAggContext, PartialSignature, PubNonce, SecNonce};

pub fn taproot_ctx(pubkeys: &[Point]) -> KeyAggContext {
    KeyAggContext::new(pubkeys.iter().copied())
        .expect("valid key set")
        .with_unspendable_taproot_tweak()
        .expect("tweak")
}

/// The x-only output key of the pots, as a `bitcoin` key.
pub fn output_key(ctx: &KeyAggContext) -> bitcoin::key::TweakedPublicKey {
    let p: Point = ctx.aggregated_pubkey();
    let x = bitcoin::XOnlyPublicKey::from_slice(&p.serialize_xonly()).unwrap();
    bitcoin::key::TweakedPublicKey::dangerous_assume_tweaked(x)
}

pub fn pot_script_pubkey(ctx: &KeyAggContext) -> bitcoin::ScriptBuf {
    bitcoin::ScriptBuf::new_p2tr_tweaked(output_key(ctx))
}

/// Round 1 for one signer and one message: a fresh nonce.
pub fn nonce(seckey: &Scalar, msg: &[u8; 32]) -> SecNonce {
    let seed: [u8; 32] = rand::random();
    SecNonce::build_with_seckey(seed, *seckey)
        .with_message(msg)
        .build()
}

pub fn agg_nonce(pubs: &[PubNonce]) -> AggNonce {
    pubs.iter().sum()
}

/// Round 2: this signer's partial signature, bound to adaptor point `t` if given.
pub fn partial(
    ctx: &KeyAggContext,
    seckey: &Scalar,
    secnonce: SecNonce,
    agg: &AggNonce,
    t: Option<Point>,
    msg: &[u8; 32],
) -> PartialSignature {
    match t {
        Some(t) => {
            adaptor::sign_partial(ctx, *seckey, secnonce, agg, t, msg).expect("partial adaptor")
        }
        None => musig2::sign_partial(ctx, *seckey, secnonce, agg, msg).expect("partial"),
    }
}

/// Checks another signer's partial signature before relying on the set.
pub fn verify(
    ctx: &KeyAggContext,
    ps: PartialSignature,
    agg: &AggNonce,
    t: Option<Point>,
    pubkey: Point,
    pubnonce: &PubNonce,
    msg: &[u8; 32],
) -> bool {
    match t {
        Some(t) => adaptor::verify_partial(ctx, ps, agg, t, pubkey, pubnonce, msg).is_ok(),
        None => musig2::verify_partial(ctx, ps, agg, pubkey, pubnonce, msg).is_ok(),
    }
}

/// Runs a whole session in one process (tests and single-machine tools). Every partial signature is
/// verified, as each party does before trusting the set.
pub fn sign_locally(
    ctx: &KeyAggContext,
    secrets: &[Scalar],
    t: Option<Point>,
    msg: &[u8; 32],
) -> Signed {
    let secs: Vec<SecNonce> = secrets.iter().map(|s| nonce(s, msg)).collect();
    let pubs: Vec<PubNonce> = secs.iter().map(|s| s.public_nonce()).collect();
    let agg = agg_nonce(&pubs);
    let parts: Vec<PartialSignature> = secrets
        .iter()
        .zip(secs)
        .map(|(sk, sn)| partial(ctx, sk, sn, &agg, t, msg))
        .collect();
    for ((ps, sk), pn) in parts.iter().zip(secrets).zip(&pubs) {
        let pk: Point = sk.base_point_mul();
        assert!(
            verify(ctx, *ps, &agg, t, pk, pn, msg),
            "partial signature failed verification"
        );
    }
    match t {
        Some(t) => Signed::Adaptor(
            adaptor::aggregate_partial_signatures(ctx, &agg, t, parts, msg).expect("aggregate"),
        ),
        None => {
            let sig: [u8; 64] =
                musig2::aggregate_partial_signatures(ctx, &agg, parts, msg).expect("aggregate");
            Signed::Complete(sig)
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum Signed {
    Adaptor(AdaptorSignature),
    Complete([u8; 64]),
}

/// Completes an adaptor pre-signature with the oracle's attestation scalar.
pub fn complete(pre: &AdaptorSignature, attestation: Scalar) -> Option<[u8; 64]> {
    pre.adapt(MaybeScalar::from(attestation))
}

/// Checks a pre-signature against the aggregate key, message and adaptor point without the secret.
pub fn verify_presig(
    ctx: &KeyAggContext,
    pre: &AdaptorSignature,
    msg: &[u8; 32],
    t: Point,
) -> bool {
    let p: Point = ctx.aggregated_pubkey();
    adaptor::verify_single(p, pre, msg, t).is_ok()
}
