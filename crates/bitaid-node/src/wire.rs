//! The messages of Specification Appendix B.2.
//!
//! A message is CBOR, signed with the sender's identity key (BIP340) over
//! `tagged_hash("Bitaid/msg", body)`, and carries a version, the Bitcoin height at sending and the
//! sender's identity key. The signature travels with the bytes it signs, so any transport will do:
//! here it is carried in a Nostr event signed by the same key. Messages of a case after acceptance
//! are encrypted with the case key, which the caller hands each signer sealed to its identity
//! (ECDH + ChaCha20-Poly1305), so relays see only case tags and ciphertext.
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use bitaid_core::hashes::tagged;
use bitcoin::secp256k1::{
    ecdh::SharedSecret, schnorr, Keypair, Message, Parity, PublicKey, Secp256k1, SecretKey,
    XOnlyPublicKey,
};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use serde::{Deserialize, Serialize};

pub const VERSION: u8 = 1;

pub type Hex32 = String;

/// What a caller commits to at registration (the template of §3): the pots, the split rule and the
/// bounds of the case. Its hash is committed in the registration and checked by every signer.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Template {
    /// deposit, reward, bounty in sats
    pub pots: [u64; 3],
    /// intervener share of the bounty in percent (the rest to documenters); default 70
    pub intervener_pct: u8,
    pub good_faith_pct: u8,
    pub max_signers: u8,
    /// seconds from the alert during which responders may accept
    pub joining_window: u32,
    /// seconds after the last ballot reveal before deemed consent (§9; 48 h in production), and
    /// after each arbitration tier's verdict before it is final (§10.5; 48 h in production)
    pub dispute_window: u32,
    /// first-instance arbitration fee per seat in sats; +25% per tier above (§10.5)
    pub arb_fee: u64,
    /// blocks after acceptance before the per-pot refunds are valid
    pub refund_delay: u32,
    /// account xpub from which the per-case refund address is derived (§3, no address reuse)
    pub refund_xpub: String,
}

impl Template {
    pub fn hash(&self) -> [u8; 32] {
        let mut b = Vec::new();
        ciborium::into_writer(self, &mut b).unwrap();
        tagged("Bitaid/template", &b)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum Class {
    Intervention,
    Documentation,
    None,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Act {
    /// seat index of the responder (order of the roster)
    pub seat: u8,
    pub class: Class,
    /// pointer to the footage: blob hash and second
    pub footage: Option<(Hex32, u32)>,
}

/// An itemised ballot (§9): every act its author saw, and whether the outcome was achieved.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Ballot {
    pub acts: Vec<Act>,
    pub outcome_achieved: bool,
    /// the alert was a misuse (troll, fabricated): asks for the deposit to be seized
    pub misuse: bool,
}

impl Ballot {
    pub fn commitment(&self, salt: &[u8; 32]) -> [u8; 32] {
        let mut b = Vec::new();
        ciborium::into_writer(self, &mut b).unwrap();
        b.extend_from_slice(salt);
        tagged("Bitaid/ballot", &b)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum Msg {
    /// A service announcing itself: the oracle its attestation key, an archivist its Blossom URL.
    Announce {
        role: String,
        key: Hex32,
        url: String,
    },
    /// Caller, at registration.
    Registration {
        funding: String,
        funding_value: u64,
        wallet_key: Hex32,
        scoped_key: Hex32,
        oracle_key: Hex32,
        fallback_height: u32,
        template: Template,
        /// wallet key's BIP340 signature over (scoped key, template hash, funding outpoint)
        wallet_sig: String,
    },
    /// Caller app, at panic.
    Alert {
        case_id: Hex32,
        /// H3 cell of the alert (resolution 8)
        cell: String,
        /// the signed registration the alert draws on (B.2), carried whole so a responder who was
        /// offline at registration can still check it
        registration: String,
        template: Template,
        pre_trigger: Hex32,
    },
    /// Responder app, at acceptance.
    Accept {
        case_id: Hex32,
        /// MuSig2 key for the incident set (33-byte compressed, hex)
        musig_key: String,
        bond: String,
        /// the bond's scoped and cold keys and fallback height, so anyone can rebuild its script
        bond_scoped: Hex32,
        bond_cold: Hex32,
        bond_fallback: u32,
        /// where this responder's shares are paid
        payout_spk: String,
    },
    /// Caller proposes one unused index of the pool's nonce batch per pot; each member that reserves
    /// them for this case answers with the nonce points (B.2 "Nonce assignment").
    NonceRequest {
        case_id: Hex32,
        indices: Vec<u32>,
    },
    NonceAssignment {
        case_id: Hex32,
        member: u16,
        indices: Vec<u32>,
        nonces: Vec<String>,
    },
    /// Caller, at the end of the joining window: the signing set, sealed case keys, the incident txid.
    Roster {
        case_id: Hex32,
        set_version: u32,
        /// identity keys of the signing responders, in seat order
        seats: Vec<Hex32>,
        musig_keys: Vec<String>,
        payout_spks: Vec<String>,
        oracle_nonces: Vec<String>,
        refund_height: u32,
        incident_txid: String,
        /// the case key sealed to each seat (hex), then to each pool member in member order, then to
        /// each archivist of the case
        sealed_keys: Vec<String>,
        /// identity keys of the case's archivists: they co-sign the seizure output's distribution (§12)
        archivists: Vec<Hex32>,
    },
    /// Every signer, round 1: nonces for every message of the set (encrypted with the case key).
    SigNonces {
        case_id: Hex32,
        set_version: u32,
        signer: u8,
        nonces: Vec<String>,
    },
    /// Every signer, round 2: partial signatures for every message of the set.
    SigPartials {
        case_id: Hex32,
        set_version: u32,
        signer: u8,
        partials: Vec<String>,
    },
    /// Caller asks the pool to co-sign the incident transaction once the set is complete: a FROST
    /// session per request; a member that commits but does not sign is replaced in the next session.
    /// Also used, after a case is final, for the oracle's half of a bond forfeiture or of the seizure
    /// output's distribution, which every member co-signs only if its own replay of the case calls for it.
    CosignRequest {
        case_id: Hex32,
        session: u32,
        tx: String,
        /// the input to co-sign
        input: u32,
    },
    PoolCommit {
        case_id: Hex32,
        session: u32,
        member: u16,
        commitment: String,
    },
    PoolPackage {
        case_id: Hex32,
        session: u32,
        package: String,
    },
    PoolSigShare {
        case_id: Hex32,
        session: u32,
        member: u16,
        share: String,
    },
    /// Pool setup over the relays: key generation (FROST DKG) and one nonce batch (B.3).
    PoolHello {
        pool: String,
        member: u16,
        n: u16,
        t: u16,
    },
    PoolDkg1 {
        pool: String,
        member: u16,
        package: String,
    },
    /// One message per sender: the share for each other member, sealed to it.
    PoolDkg2 {
        pool: String,
        from: u16,
        sealed: Vec<(u16, String)>,
    },
    PoolNonceCommit {
        pool: String,
        commitments: String,
    },
    /// One message per sender: the share for each other member, sealed to it.
    PoolNonceShare {
        pool: String,
        from: u16,
        sealed: Vec<(u16, String)>,
    },
    PoolNonceStatus {
        pool: String,
        member: u16,
        bad: Vec<u16>,
    },
    PoolReady {
        pool: String,
        member: u16,
        key: Hex32,
        public: String,
        members: Vec<u16>,
        qualified: Vec<u16>,
    },
    /// Caller, once the set is complete and the incident transaction confirmed.
    Incident {
        case_id: Hex32,
        txid: String,
    },
    /// Recorder, after upload: what was pinned and where (hash-before-upload, §8).
    Evidence {
        case_id: Hex32,
        blobs: Vec<(Hex32, u64)>,
        slice_roots: Vec<Hex32>,
        archivists: Vec<String>,
    },
    /// Attendee, blind ballot commitment, then the reveal.
    BallotCommit {
        case_id: Hex32,
        commitment: Hex32,
    },
    BallotReveal {
        case_id: Hex32,
        ballot: Ballot,
        salt: Hex32,
    },
    /// A bonded party sends the case to arbitration (tier 1) or appeals to the next tier (§10.1, §10.5).
    Escalate {
        case_id: Hex32,
        tier: u32,
        reason: String,
    },
    /// An eligible arbitrator offers to take a seat, knowing only the fee, tier and case value (§10.2).
    SeatOffer {
        case_id: Hex32,
        tier: u32,
        bond: String,
        bond_scoped: Hex32,
        bond_cold: Hex32,
        bond_fallback: u32,
        bond_value: u64,
        payout_spk: String,
    },
    /// The escalating party, after a block mined once offers closed: the offers considered, the block,
    /// the seats it draws, and the case key sealed to each seated arbitrator.
    Seated {
        case_id: Hex32,
        tier: u32,
        height: u32,
        block_hash: Hex32,
        offers: Vec<Hex32>,
        seats: Vec<Hex32>,
        sealed_keys: Vec<String>,
    },
    /// The escalating party paid each seated arbitrator its fee directly.
    FeePaid {
        case_id: Hex32,
        tier: u32,
        txid: String,
    },
    /// Seated arbitrator: blind vote commitment, then the reveal (§10.4).
    VerdictCommit {
        case_id: Hex32,
        tier: u32,
        commitment: Hex32,
    },
    VerdictReveal {
        case_id: Hex32,
        tier: u32,
        verdict: Ballot,
        salt: Hex32,
    },
    /// Seated arbitrator, on taking the seat: the forfeitures of its seat stake pre-signed with its bond's
    /// scoped key, one per penalty step (2×, 2.5×, 3×, 3.5×, 4× the seat fee), each paying the case's
    /// seizure output (§10.4, §12).
    Forfeits {
        case_id: Hex32,
        tier: u32,
        /// the seat's stake: an output under the arbitrator's bond script set aside for this seat, so
        /// that seats held at once never pre-sign forfeitures of the same output
        stake: String,
        value: u64,
        sigs: Vec<String>,
    },
    /// Whoever collects a case's seizure output asks its archivists to co-sign the distribution (§12).
    SeizureRequest {
        case_id: Hex32,
        tx: String,
    },
    /// An archivist's signatures on that distribution, one per input, after its own replay of the case.
    SeizureSig {
        case_id: Hex32,
        txid: String,
        sigs: Vec<String>,
    },
    /// The tier's commitment (roster and answers) is in this transaction's OP_RETURN (B.2).
    TierCommitted {
        case_id: Hex32,
        tier: u32,
        txid: String,
    },
    /// Pool member, once per pot after replaying the case: its public attestation share for the outcome
    /// it reads from the log. Any t valid shares for one outcome combine to the scalar that completes it.
    AttestShare {
        case_id: Hex32,
        pot: u8,
        share: String,
    },
}

impl Msg {
    pub fn name(&self) -> &'static str {
        match self {
            Msg::Announce { .. } => "announce",
            Msg::Registration { .. } => "registration",
            Msg::Alert { .. } => "alert",
            Msg::Accept { .. } => "accept",
            Msg::NonceRequest { .. } => "nonce-request",
            Msg::NonceAssignment { .. } => "nonce-assignment",
            Msg::Roster { .. } => "roster",
            Msg::SigNonces { .. } => "sig-nonces",
            Msg::SigPartials { .. } => "sig-partials",
            Msg::CosignRequest { .. } => "cosign-request",
            Msg::PoolCommit { .. } => "pool-commit",
            Msg::PoolPackage { .. } => "pool-package",
            Msg::PoolSigShare { .. } => "pool-sig-share",
            Msg::PoolHello { .. } => "pool-hello",
            Msg::PoolDkg1 { .. } => "pool-dkg1",
            Msg::PoolDkg2 { .. } => "pool-dkg2",
            Msg::PoolNonceCommit { .. } => "pool-nonce-commit",
            Msg::PoolNonceShare { .. } => "pool-nonce-share",
            Msg::PoolNonceStatus { .. } => "pool-nonce-status",
            Msg::PoolReady { .. } => "pool-ready",
            Msg::Incident { .. } => "incident",
            Msg::Evidence { .. } => "evidence",
            Msg::BallotCommit { .. } => "ballot-commit",
            Msg::BallotReveal { .. } => "ballot-reveal",
            Msg::AttestShare { .. } => "attest-share",
            Msg::Escalate { .. } => "escalate",
            Msg::SeatOffer { .. } => "seat-offer",
            Msg::Seated { .. } => "seated",
            Msg::FeePaid { .. } => "fee-paid",
            Msg::VerdictCommit { .. } => "verdict-commit",
            Msg::VerdictReveal { .. } => "verdict-reveal",
            Msg::TierCommitted { .. } => "tier-committed",
            Msg::Forfeits { .. } => "forfeits",
            Msg::SeizureRequest { .. } => "seizure-request",
            Msg::SeizureSig { .. } => "seizure-sig",
        }
    }
    pub fn case_id(&self) -> Option<&str> {
        match self {
            Msg::Registration { .. }
            | Msg::Announce { .. }
            | Msg::PoolHello { .. }
            | Msg::PoolDkg1 { .. }
            | Msg::PoolDkg2 { .. }
            | Msg::PoolNonceCommit { .. }
            | Msg::PoolNonceShare { .. }
            | Msg::PoolNonceStatus { .. }
            | Msg::PoolReady { .. } => None,
            Msg::Alert { case_id, .. }
            | Msg::Accept { case_id, .. }
            | Msg::NonceRequest { case_id, .. }
            | Msg::NonceAssignment { case_id, .. }
            | Msg::Roster { case_id, .. }
            | Msg::SigNonces { case_id, .. }
            | Msg::SigPartials { case_id, .. }
            | Msg::CosignRequest { case_id, .. }
            | Msg::PoolCommit { case_id, .. }
            | Msg::PoolPackage { case_id, .. }
            | Msg::PoolSigShare { case_id, .. }
            | Msg::Incident { case_id, .. }
            | Msg::Evidence { case_id, .. }
            | Msg::BallotCommit { case_id, .. }
            | Msg::BallotReveal { case_id, .. }
            | Msg::AttestShare { case_id, .. }
            | Msg::Escalate { case_id, .. }
            | Msg::SeatOffer { case_id, .. }
            | Msg::Seated { case_id, .. }
            | Msg::FeePaid { case_id, .. }
            | Msg::VerdictCommit { case_id, .. }
            | Msg::VerdictReveal { case_id, .. }
            | Msg::TierCommitted { case_id, .. }
            | Msg::Forfeits { case_id, .. }
            | Msg::SeizureRequest { case_id, .. }
            | Msg::SeizureSig { case_id, .. } => Some(case_id),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Envelope {
    pub v: u8,
    pub height: u32,
    pub sender: Hex32,
    pub msg: Msg,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct SignedBytes {
    body: Vec<u8>,
    sig: Vec<u8>,
}

fn msg_digest(body: &[u8]) -> [u8; 32] {
    tagged("Bitaid/msg", body)
}

/// Encodes and signs; returns CBOR bytes of (body, signature).
pub fn sign(keys: &Keypair, height: u32, msg: Msg) -> Vec<u8> {
    let env = Envelope {
        v: VERSION,
        height,
        sender: hex::encode(keys.x_only_public_key().0.serialize()),
        msg,
    };
    let mut body = Vec::new();
    ciborium::into_writer(&env, &mut body).unwrap();
    let sig = Secp256k1::new().sign_schnorr(&Message::from_digest(msg_digest(&body)), keys);
    let mut out = Vec::new();
    ciborium::into_writer(
        &SignedBytes {
            body,
            sig: sig.as_ref().to_vec(),
        },
        &mut out,
    )
    .unwrap();
    out
}

/// Decodes and checks the signature against the sender named inside.
pub fn verify(bytes: &[u8]) -> Result<Envelope, String> {
    let sb: SignedBytes = ciborium::from_reader(bytes).map_err(|e| format!("cbor: {e}"))?;
    let env: Envelope =
        ciborium::from_reader(&sb.body[..]).map_err(|e| format!("cbor body: {e}"))?;
    if env.v != VERSION {
        return Err(format!("unknown version {}", env.v));
    }
    let pk = XOnlyPublicKey::from_slice(&hex::decode(&env.sender).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    let sig = schnorr::Signature::from_slice(&sb.sig).map_err(|e| e.to_string())?;
    Secp256k1::verification_only()
        .verify_schnorr(&sig, &Message::from_digest(msg_digest(&sb.body)), &pk)
        .map_err(|_| "bad signature".to_string())?;
    Ok(env)
}

pub fn b64(b: &[u8]) -> String {
    B64.encode(b)
}
pub fn unb64(s: &str) -> Option<Vec<u8>> {
    B64.decode(s).ok()
}

// ------------------------------------------------------------------ encryption

/// ECDH between x-only identity keys: both sides use the even-y lift, so either computes the same.
fn shared(my: &Keypair, their: &XOnlyPublicKey) -> [u8; 32] {
    let (_, parity) = my.x_only_public_key();
    let mut sk = SecretKey::from_keypair(my);
    if parity == Parity::Odd {
        sk = sk.negate();
    }
    let pk = PublicKey::from_x_only_public_key(*their, Parity::Even);
    SharedSecret::new(&pk, &sk).secret_bytes()
}

fn aead(key: &[u8; 32]) -> ChaCha20Poly1305 {
    ChaCha20Poly1305::new(key.into())
}

pub fn encrypt(key: &[u8; 32], aad: &[u8], pt: &[u8]) -> Vec<u8> {
    let n: [u8; 12] = rand::random();
    let ct = aead(key)
        .encrypt(Nonce::from_slice(&n), Payload { msg: pt, aad })
        .expect("encrypt");
    [n.to_vec(), ct].concat()
}

pub fn decrypt(key: &[u8; 32], aad: &[u8], ct: &[u8]) -> Option<Vec<u8>> {
    if ct.len() < 12 {
        return None;
    }
    aead(key)
        .decrypt(
            Nonce::from_slice(&ct[..12]),
            Payload {
                msg: &ct[12..],
                aad,
            },
        )
        .ok()
}

/// Seals `pt` from `my` to `their`, bound to `aad`.
pub fn seal(my: &Keypair, their: &XOnlyPublicKey, aad: &[u8], pt: &[u8]) -> Vec<u8> {
    encrypt(&tagged("Bitaid/seal", &shared(my, their)), aad, pt)
}

pub fn unseal(my: &Keypair, their: &XOnlyPublicKey, aad: &[u8], ct: &[u8]) -> Option<Vec<u8>> {
    decrypt(&tagged("Bitaid/seal", &shared(my, their)), aad, ct)
}

pub fn xonly(hex32: &str) -> Option<XOnlyPublicKey> {
    XOnlyPublicKey::from_slice(&hex::decode(hex32).ok()?).ok()
}

pub fn h32(s: &str) -> Option<[u8; 32]> {
    hex::decode(s).ok()?.try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kp() -> Keypair {
        Keypair::new(&Secp256k1::new(), &mut rand::thread_rng())
    }

    #[test]
    fn sign_verify_tamper() {
        let k = kp();
        let b = sign(
            &k,
            100,
            Msg::NonceRequest {
                case_id: "ab".into(),
                indices: vec![1, 2, 3],
            },
        );
        let env = verify(&b).unwrap();
        assert_eq!(env.height, 100);
        let mut t = b.clone();
        let n = t.len();
        t[n / 2] ^= 1;
        assert!(verify(&t).is_err());
    }

    #[test]
    fn seal_between_parities() {
        for _ in 0..8 {
            let (a, b) = (kp(), kp());
            let ct = seal(&a, &b.x_only_public_key().0, b"aad", b"secret");
            assert_eq!(
                unseal(&b, &a.x_only_public_key().0, b"aad", &ct).unwrap(),
                b"secret"
            );
            assert!(unseal(&b, &a.x_only_public_key().0, b"other", &ct).is_none());
        }
    }
}
