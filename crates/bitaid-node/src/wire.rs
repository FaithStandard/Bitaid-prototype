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
    /// blocks after the last ballot reveal before deemed consent (§9), and after each arbitration
    /// tier's commitment confirms before its verdict is final (§10.5); 288 (about 48 h) in production
    pub dispute_blocks: u32,
    /// first-instance arbitration fee per seat in sats; +25% per tier above (§10.5)
    pub arb_fee: u64,
    /// blocks after acceptance before the per-pot refunds are valid
    pub refund_delay: u32,
    /// account xpub from which the per-case refund address is derived (§3, no address reuse)
    pub refund_xpub: String,
    /// blocks from the confirmation of a seat's fee in which the seat must commit its vote, or its
    /// seat is forfeit (§10.4: 1,008 in production); a review seat counts from its draw
    pub commit_blocks: u32,
    /// blocks from the last commit in which the seats reveal; a missing reveal is charged as an
    /// incoherent vote (§10.4: 144 in production)
    pub reveal_blocks: u32,
    /// blocks after the final tier's commitment whose hash seeds the review draw (§10.3; in
    /// production the first block after the escalation window closes)
    #[serde(default)]
    pub review_delay: u32,
    /// review rate in percent for this case's draw, in place of the protocol's rates by value
    /// (§10.3). A test setting: production cases carry none
    #[serde(default)]
    pub review_pct: Option<u8>,
}

impl Template {
    /// The protocol's bounds on a caller's template (review finding D-9): a template outside them is
    /// refused by every checker, so no caller can set a parameter that empties a mechanism. Production
    /// floors (BITAID_PRODUCTION=1) add the spec's windows and forbid a set review rate.
    pub fn check(&self) -> Result<(), String> {
        let dust = bitaid_core::payouts::DUST;
        if self.pots.iter().any(|p| *p != 0 && *p < dust) {
            return Err(format!("a non-empty pot below {dust} sats"));
        }
        if self.pots.iter().all(|p| *p == 0) {
            return Err("no pot".into());
        }
        if self.intervener_pct > 100 || self.good_faith_pct > 100 {
            return Err("a share above 100%".into());
        }
        if !(1..=12).contains(&self.max_signers) {
            return Err(format!("{} signers (1 to 12)", self.max_signers));
        }
        if self.arb_fee < dust {
            return Err(format!("arbitration fee below {dust} sats"));
        }
        if self.dispute_blocks == 0 || self.commit_blocks == 0 || self.reveal_blocks == 0 {
            return Err("a window of zero blocks".into());
        }
        if self.review_pct.is_some_and(|p| p > 100) {
            return Err("review rate above 100%".into());
        }
        if (self.refund_delay as u64)
            <= 4 * (self.dispute_blocks as u64 + self.commit_blocks as u64 + self.reveal_blocks as u64)
        {
            return Err("refund delay too short for a dispute to finish before it".into());
        }
        if crate::production() {
            if self.dispute_blocks < 288 || self.commit_blocks < 1_008 || self.reveal_blocks < 144 {
                return Err("windows below the protocol's (288 / 1,008 / 144 blocks)".into());
            }
            if self.review_pct.is_some() {
                return Err("a review rate set by the caller".into());
            }
        }
        Ok(())
    }

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

/// How grave a responder's fault is, as the tables of §11.6–11.8 read it: what its bond forfeits.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    /// 25% of the bond (more if recurring, §11.8)
    Lapse,
    /// the whole bond and layer 0
    Misconduct,
    /// the whole bond and layer 0, and exclusion
    Bannable,
}

/// A finding that the responder at `seat` was at fault (use of force §11.6, harm to fellow responders
/// §11.7). `harmed`: the seat of a fellow responder it harmed, if any (repaid its loss first, §12).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Fault {
    pub seat: u8,
    pub severity: Severity,
    #[serde(default)]
    pub harmed: Option<u8>,
}

/// An itemised ballot (§9): every act its author saw, and whether the outcome was achieved.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Ballot {
    pub acts: Vec<Act>,
    pub outcome_achieved: bool,
    /// the alert was a misuse (troll, fabricated): asks for the deposit to be seized
    pub misuse: bool,
    /// responders this ballot finds at fault; an attendee's finding never seizes, it starts a ruling
    #[serde(default)]
    pub faults: Vec<Fault>,
}

impl Ballot {
    /// hash(ballot, salt, voter key) (§10.4): bound to the voter, so a seat cannot copy another's
    /// commitment and then its reveal.
    pub fn commitment(&self, salt: &[u8; 32], voter: &str) -> [u8; 32] {
        let mut b = Vec::new();
        ciborium::into_writer(self, &mut b).unwrap();
        b.extend_from_slice(salt);
        b.extend_from_slice(&h32(voter).unwrap_or_default());
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
        /// the pool's co-signing key (in the funding script)
        oracle_key: Hex32,
        /// the pool's attestation key (outcomes are attested under it, never co-signed)
        #[serde(default)]
        attest_key: Hex32,
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
        /// the commitment to the exact location (`case::place_commitment`), revealed only to
        /// responders who accepted (Specification §13): the cell alone is broadcast
        #[serde(default)]
        place: String,
    },
    /// Caller to one responder whose acceptance it checked: the exact location the alert committed
    /// to, sealed to that responder (latitude, longitude and the commitment's salt, as JSON)
    Place {
        case_id: Hex32,
        sealed: String,
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
        /// the caller's pot key for this case (MuSig2), fresh per case: not its scoped key, which
        /// signs only the incident transaction (review finding 16)
        #[serde(default)]
        caller_musig: String,
    },
    /// A pool member's confirmation that it checked a roster (every seat accepted with these keys and
    /// payout scripts, bonds on chain, refund height, its own reserved nonces) and will attest under it:
    /// `bound` is the set-bound case id the outcome messages are built on. A responder signs only once
    /// a threshold of members has confirmed the exact set it is asked to sign.
    RosterAck {
        case_id: Hex32,
        set_version: u32,
        bound: Hex32,
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
        /// a hash of the nonces this signer signed with, every signer's in order: views that differ
        /// mean a signer sent different nonces to different parties, and the log shows which
        #[serde(default)]
        seen: String,
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
        /// which of the pool's two keys ("" attestation, "cosign" co-signing)
        #[serde(default)]
        purpose: String,
    },
    /// One message per sender: the share for each other member, sealed to it.
    PoolDkg2 {
        pool: String,
        from: u16,
        sealed: Vec<(u16, String)>,
        #[serde(default)]
        purpose: String,
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
    /// A dealer's answer to complaints against it: the disputed shares, in the clear, one per member
    /// that complained (JSON `Shares`). Everyone checks them against the dealer's commitments; a dealer
    /// is disqualified only if it does not answer or its answer fails. Revealing a complainer's shares
    /// leaks nothing beyond what that complainer could already reveal itself.
    PoolNonceReveal {
        pool: String,
        dealer: u16,
        shares: Vec<String>,
    },
    PoolReady {
        pool: String,
        member: u16,
        key: Hex32,
        public: String,
        members: Vec<u16>,
        qualified: Vec<u16>,
        /// every member's identity, in the order of `members`, as this member ran the setup with
        /// them: a ready counts only from the identity it names for its own member
        #[serde(default)]
        ids: Vec<String>,
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
        /// tier 1: the transaction that posts the case on the fee market (§10.6). A pointer only:
        /// the posting, its fee and its height are read from the chain.
        #[serde(default)]
        post: String,
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
        /// where a forfeited seat's fee is refunded to the payer
        refund_spk: String,
    },
    /// The escalating party, after a seat missed its commit deadline and its seat forfeiture refunded the
    /// fee: the replacement drawn from the remaining offers by a block mined after the forfeiture, and
    /// the case key sealed to it (§10.4).
    Reseated {
        case_id: Hex32,
        tier: u32,
        height: u32,
        block_hash: Hex32,
        replaced: Hex32,
        seat: Hex32,
        sealed_key: String,
        /// a review seat's self-replacement (§10.3): the offers the replacement was drawn from;
        /// empty for a seat redrawn from the panel's own list
        #[serde(default)]
        from: Vec<Hex32>,
    },
    /// Drawn reviewer (§10.3): accepts the review seat, or posts the fee it pays a replacement (re-posted
    /// as it rises until someone offers); or an eligible arbitrator offering to take a leaver's seat.
    ReviewAnswer {
        case_id: Hex32,
        tier: u32,
        accept: bool,
        fee: u64,
        /// an eligible arbitrator offering to take `seat`, a leaver's, at its posted `fee`; empty for a
        /// drawn reviewer's own answer
        #[serde(default)]
        seat: Hex32,
    },
    /// A bonded arbitrator flags a closed case the review draw passed over, sending it to the staged
    /// review at its own expense (§10.3): it pays each panel before it sits.
    Flag {
        case_id: Hex32,
    },
    /// Review convener, on a flagged case: a stage's seats are final; the flagger pays them now.
    ReviewSeats {
        case_id: Hex32,
        tier: u32,
        seats: Vec<Hex32>,
    },
    /// Review convener: the case key, sealed to a reviewer that accepted or took a seat by replacement.
    ReviewKey {
        case_id: Hex32,
        tier: u32,
        seat: Hex32,
        sealed_key: String,
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
    /// seizure output (§10.4, §12), then its seat forfeiture, refunding the fee to the payer if it misses
    /// its commit deadline.
    Forfeits {
        case_id: Hex32,
        tier: u32,
        /// the seat's stake: an output under the arbitrator's bond script set aside for this seat, so
        /// that seats held at once never pre-sign forfeitures of the same output
        stake: String,
        value: u64,
        sigs: Vec<String>,
        /// an entry bond's seizure only (registry case): the archivist committee whose majority, with
        /// the oracle pool, must co-sign moving the seized bond out of the holding output (B.1)
        #[serde(default)]
        holders: Vec<Hex32>,
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
        /// the seats whose reveals the commitment counts: a reveal published after it is not counted,
        /// so a seat cannot un-commit a tier by revealing late (review finding)
        #[serde(default)]
        revealed: Vec<Hex32>,
        /// the seats whose commitments the poster counted as made by the deadline, as it saw them
        /// arrive; on chain with the rest, so whether a commitment was on time is read from the chain,
        /// never from the height its sender stated (empty: judged by the stated heights, as before)
        #[serde(default)]
        committed: Vec<Hex32>,
    },
    /// Pool member: the case's last tier hung with no verdict below it and no party re-rolled it within
    /// the window, so the deadlock stands and the incident output closes by its refund locktime (§10.5).
    Deadlock {
        case_id: Hex32,
    },
    /// Anyone: the ids of the messages anchored on chain under one root (§7). The chain holds the
    /// root; this list lets a node find which messages it timestamps.
    Checkpoint {
        leaves: Vec<Hex32>,
    },
    /// Pool member, once per pot after replaying the case: its public attestation share for the outcome
    /// it reads from the log. Any t valid shares for one outcome combine to the scalar that completes it.
    AttestShare {
        case_id: Hex32,
        pot: u8,
        share: String,
    },
    /// Light client (§7.2, `design/phone_light.md`) asking its Core (or a sampled bonded worker)
    /// for new headers, proven transactions, output spend status, and a case's on-chain records
    /// in one exchange. Carried link-locally (never flooded or stored in gossip replay logs).
    LightAsk {
        id: Hex32,
        /// Block locator (newest-first block hashes known to the requester: tip, last 10, then
        /// exponentially sparser). Empty means no headers requested.
        locator: Vec<Hex32>,
        txids: Vec<Hex32>,
        outpoints: Vec<String>,
        case_id: Option<Hex32>,
        from_height: u32,
    },
    /// Signed answer to `LightAsk` (§7.2): carries new 80-byte headers, Merkle-proven transactions,
    /// output status, and case records. `ask_hash` binds the answer to the exact question, and
    /// `covers` lists the typed IDs of everything the answer claims is the complete set (empty
    /// included), so a later proof of omission convicts the sender.
    LightAnswer {
        id: Hex32,
        ask_hash: Hex32,
        tip_height: u32,
        tip_hash: Hex32,
        /// Height of `headers[0]` (or `tip_height` when `headers` is empty), so the requester can
        /// apply the batch across a reorg via `HeaderChain::apply_fork_at`.
        headers_from: u32,
        headers: Vec<Vec<u8>>,
        txs: Vec<LightTxProof>,
        outputs: Vec<LightOutput>,
        records: Vec<LightRecord>,
        /// Highest block height for which `records` is the complete set (signed by the Core).
        /// When the response hits `LIGHT_MAX_RECORDS`, `records_through < tip_height` so the
        /// client continues pagination from `records_through + 1` without losing records.
        #[serde(default)]
        records_through: u32,
        covers: Vec<LightCover>,
    },
}

/// Hard bounds on `LightAsk` / `LightAnswer` payloads so a hostile peer cannot exhaust memory or
/// bandwidth (all answers also fit comfortably inside `gossip::MAX_LINE`).
pub const LIGHT_MAX_LOCATOR: usize = 64;
pub const LIGHT_MAX_HEADERS: usize = 2_016;
pub const LIGHT_MAX_TXS: usize = 64;
pub const LIGHT_MAX_OUTPUTS: usize = 64;
pub const LIGHT_MAX_RECORDS: usize = 64;
pub const LIGHT_MAX_ANSWER_BYTES: usize = 1 << 20;

/// One item listed in `LightAnswer.covers` (§7.2 omission accountability): typed so a transaction
/// id, an outpoint, and a record transaction id cannot collide.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LightCover {
    Tx(Hex32),
    Output(String),
    Record(Hex32),
}

/// One transaction proven to be in a block (`LightAnswer.txs`).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct LightTxProof {
    /// Raw consensus-encoded Bitcoin transaction bytes.
    pub raw: Vec<u8>,
    pub height: u32,
    pub block_hash: Hex32,
    /// Consensus-encoded `PartialMerkleTree` proving `raw` is in `block_hash`.
    pub merkle_path: Vec<u8>,
}

/// One output's unspent/spent status (`LightAnswer.outputs`). Value and script are never taken on
/// the server's word: the creating transaction's `LightTxProof` is returned in `LightAnswer.txs`
/// (and listed in `covers`) so the client derives value and scriptPubKey from the proven tx.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct LightOutput {
    pub outpoint: String,
    pub unspent: bool,
    pub spent_by: Option<Hex32>,
    pub height: u32,
}

/// One on-chain Bitaid record of a case (`LightAnswer.records`).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct LightRecord {
    pub txid: Hex32,
    pub height: u32,
    pub block_hash: Hex32,
    /// Consensus-encoded `PartialMerkleTree` proving `txid` is in `block_hash`.
    pub merkle_path: Vec<u8>,
    /// Raw consensus-encoded transaction carrying the record's OP_RETURN.
    pub record: Vec<u8>,
}

/// Tagged hash of a `LightAsk` message, echoed in `LightAnswer.ask_hash` so the sender's signature
/// binds the answer to the exact question (§7.2).
pub fn light_ask_hash(ask: &Msg) -> Hex32 {
    let mut b = Vec::new();
    ciborium::into_writer(ask, &mut b).unwrap();
    hex::encode(tagged("Bitaid/light-ask", &b))
}

/// True if `content` (base64-encoded signed `Envelope` or raw `Envelope`) carries a `LightAsk`
/// or `LightAnswer`. Used by gossip admission to drop any light message that a hostile peer
/// attempts to flood inside a normal gossip event.
pub fn is_light_b64(content: &str) -> bool {
    let Some(raw) = unb64(content) else {
        return false;
    };
    let env: Envelope = if let Ok(sb) = ciborium::from_reader::<SignedBytes, _>(raw.as_slice()) {
        match ciborium::from_reader::<Envelope, _>(sb.body.as_slice()) {
            Ok(e) => e,
            Err(_) => return false,
        }
    } else if let Ok(e) = ciborium::from_reader::<Envelope, _>(raw.as_slice()) {
        e
    } else {
        return false;
    };
    matches!(env.msg, Msg::LightAsk { .. } | Msg::LightAnswer { .. })
}

impl Msg {
    /// Checks hard size/count bounds on `LightAsk` and `LightAnswer` messages.
    pub fn check_light_bounds(&self, raw_len: usize) -> Result<(), String> {
        if raw_len > LIGHT_MAX_ANSWER_BYTES {
            return Err(format!(
                "light message too large: {raw_len} > {LIGHT_MAX_ANSWER_BYTES}"
            ));
        }
        match self {
            Msg::LightAsk {
                locator,
                txids,
                outpoints,
                ..
            } => {
                if locator.len() > LIGHT_MAX_LOCATOR {
                    return Err(format!(
                        "locator too long: {} > {LIGHT_MAX_LOCATOR}",
                        locator.len()
                    ));
                }
                if txids.len() > LIGHT_MAX_TXS {
                    return Err(format!("too many txids: {} > {LIGHT_MAX_TXS}", txids.len()));
                }
                if outpoints.len() > LIGHT_MAX_OUTPUTS {
                    return Err(format!(
                        "too many outpoints: {} > {LIGHT_MAX_OUTPUTS}",
                        outpoints.len()
                    ));
                }
                Ok(())
            }
            Msg::LightAnswer {
                headers,
                txs,
                outputs,
                records,
                covers,
                ..
            } => {
                if headers.len() > LIGHT_MAX_HEADERS {
                    return Err(format!(
                        "too many headers: {} > {LIGHT_MAX_HEADERS}",
                        headers.len()
                    ));
                }
                if let Some((i, h)) = headers.iter().enumerate().find(|(_, h)| h.len() != 80) {
                    return Err(format!("header {i} has {} bytes, expected 80", h.len()));
                }
                if txs.len() > LIGHT_MAX_TXS {
                    return Err(format!("too many txs: {} > {LIGHT_MAX_TXS}", txs.len()));
                }
                if outputs.len() > LIGHT_MAX_OUTPUTS {
                    return Err(format!(
                        "too many outputs: {} > {LIGHT_MAX_OUTPUTS}",
                        outputs.len()
                    ));
                }
                if records.len() > LIGHT_MAX_RECORDS {
                    return Err(format!(
                        "too many records: {} > {LIGHT_MAX_RECORDS}",
                        records.len()
                    ));
                }
                let max_covers = LIGHT_MAX_TXS + LIGHT_MAX_OUTPUTS + LIGHT_MAX_RECORDS;
                if covers.len() > max_covers {
                    return Err(format!("too many covers: {} > {max_covers}", covers.len()));
                }
                Ok(())
            }
            _ => Err("not a light message".into()),
        }
    }
}

impl Msg {
    /// Whether the time of this message decides anything: such a message counts from the block that
    /// anchors it on chain (§7), never from the height its sender states. A tier-1 escalation is only
    /// a pointer to its posting, which the chain already times.
    pub fn timed(&self) -> bool {
        match self {
            Msg::SeatOffer { .. } | Msg::VerdictCommit { .. } | Msg::ReviewAnswer { .. } | Msg::Flag { .. } => true,
            // the attending vote (§9): a ballot's commitment and its reveal each count within a
            // window the chain measures from the incident's block
            Msg::BallotCommit { .. } | Msg::BallotReveal { .. } => true,
            // (an appeal; a review stage's opening is only an announcement: the chain fixes its
            // draw block, and review tiers are numbered from 100)
            Msg::Escalate { tier, .. } => *tier >= 2 && *tier < 100,
            // a seat's stake (§10.4): put up by its stake deadline, counted from the block that
            // anchors it (a responder's and an entry bond's forfeitures, tier 0, are not timed)
            Msg::Forfeits { tier, .. } => *tier >= 1 && *tier < 100,
            // an appeal's draw (§10.4): any party or dissenter who appealed may publish it, and the
            // first anchored counts, so a party that opens an appeal and stalls is overtaken
            // and a seat's stake deadline runs from the block anchoring its draw, for every tier: the
            // seats cannot stake before they know, so a draw published late delays only its publisher
            // (public signet run, 2026-11-24: counted from the draw block, every tier-1 seat was late
            // before it was told)
            Msg::Seated { tier, .. } => *tier >= 1 && *tier < 100,
            Msg::Reseated { tier, from, .. } => *tier >= 1 && *tier < 100 && from.is_empty(),
            _ => false,
        }
    }
    pub fn name(&self) -> &'static str {
        match self {
            Msg::Announce { .. } => "announce",
            Msg::Registration { .. } => "registration",
            Msg::Alert { .. } => "alert",
            Msg::Place { .. } => "place",
            Msg::Accept { .. } => "accept",
            Msg::NonceRequest { .. } => "nonce-request",
            Msg::NonceAssignment { .. } => "nonce-assignment",
            Msg::Roster { .. } => "roster",
            Msg::RosterAck { .. } => "roster-ack",
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
            Msg::PoolNonceReveal { .. } => "pool-nonce-reveal",
            Msg::PoolReady { .. } => "pool-ready",
            Msg::Incident { .. } => "incident",
            Msg::Evidence { .. } => "evidence",
            Msg::BallotCommit { .. } => "ballot-commit",
            Msg::BallotReveal { .. } => "ballot-reveal",
            Msg::AttestShare { .. } => "attest-share",
            Msg::Escalate { .. } => "escalate",
            Msg::SeatOffer { .. } => "seat-offer",
            Msg::Seated { .. } => "seated",
            Msg::Reseated { .. } => "reseated",
            Msg::ReviewAnswer { .. } => "review-answer",
            Msg::ReviewKey { .. } => "review-key",
            Msg::Flag { .. } => "flag",
            Msg::ReviewSeats { .. } => "review-seats",
            Msg::FeePaid { .. } => "fee-paid",
            Msg::VerdictCommit { .. } => "verdict-commit",
            Msg::VerdictReveal { .. } => "verdict-reveal",
            Msg::TierCommitted { .. } => "tier-committed",
            Msg::Forfeits { .. } => "forfeits",
            Msg::Deadlock { .. } => "deadlock",
            Msg::Checkpoint { .. } => "checkpoint",
            Msg::SeizureRequest { .. } => "seizure-request",
            Msg::SeizureSig { .. } => "seizure-sig",
            Msg::LightAsk { .. } => "light-ask",
            Msg::LightAnswer { .. } => "light-answer",
        }
    }
    pub fn case_id(&self) -> Option<&str> {
        match self {
            Msg::Registration { .. }
            | Msg::Checkpoint { .. }
            | Msg::Announce { .. }
            | Msg::PoolHello { .. }
            | Msg::PoolDkg1 { .. }
            | Msg::PoolDkg2 { .. }
            | Msg::PoolNonceCommit { .. }
            | Msg::PoolNonceShare { .. }
            | Msg::PoolNonceStatus { .. }
            | Msg::PoolNonceReveal { .. }
            | Msg::PoolReady { .. }
            | Msg::LightAsk { .. }
            | Msg::LightAnswer { .. } => None,
            Msg::Alert { case_id, .. }
            | Msg::Accept { case_id, .. }
            | Msg::Place { case_id, .. }
            | Msg::NonceRequest { case_id, .. }
            | Msg::NonceAssignment { case_id, .. }
            | Msg::Roster { case_id, .. }
            | Msg::RosterAck { case_id, .. }
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
            | Msg::Reseated { case_id, .. }
            | Msg::FeePaid { case_id, .. }
            | Msg::VerdictCommit { case_id, .. }
            | Msg::VerdictReveal { case_id, .. }
            | Msg::TierCommitted { case_id, .. }
            | Msg::Forfeits { case_id, .. }
            | Msg::Deadlock { case_id, .. }
            | Msg::ReviewAnswer { case_id, .. }
            | Msg::ReviewKey { case_id, .. }
            | Msg::Flag { case_id, .. }
            | Msg::ReviewSeats { case_id, .. }
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

/// Whether a message of this name may be timed (see `Msg::timed`), told from its tag before it is read.
pub fn timed_name(t: &str) -> bool {
    ["seat-offer", "verdict-commit", "review-answer", "flag", "escalate", "ballot-commit", "ballot-reveal", "forfeits", "seated", "reseated"].contains(&t)
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

    #[test]
    fn light_ask_and_answer_sign_verify_and_tamper() {
        let phone = kp();
        let core = kp();
        let ask = Msg::LightAsk {
            id: "01".repeat(16),
            locator: vec!["10".repeat(32), "00".repeat(32)],
            txids: vec!["aa".repeat(32)],
            outpoints: vec![format!("{}:0", "bb".repeat(32))],
            case_id: Some("cc".repeat(32)),
            from_height: 90,
        };
        let ask_hash = light_ask_hash(&ask);
        let ask_bytes = sign(&phone, 100, ask.clone());
        let ask_env = verify(&ask_bytes).unwrap();
        assert_eq!(ask_env.msg, ask);
        assert_eq!(ask_env.msg.name(), "light-ask");
        assert_eq!(ask_env.msg.case_id(), None);
        assert!(!ask_env.msg.timed());
        assert!(ask_env.msg.check_light_bounds(ask_bytes.len()).is_ok());
        assert!(is_light_b64(&b64(&ask_bytes)));

        // Non-empty answer covering tx, output, and record.
        let ans = Msg::LightAnswer {
            id: "01".repeat(16),
            ask_hash: ask_hash.clone(),
            tip_height: 102,
            tip_hash: "dd".repeat(32),
            headers_from: 101,
            headers: vec![vec![0x11; 80], vec![0x22; 80]],
            txs: vec![LightTxProof {
                raw: vec![1, 2, 3, 4],
                height: 101,
                block_hash: "ee".repeat(32),
                merkle_path: vec![5, 6, 7],
            }],
            outputs: vec![LightOutput {
                outpoint: format!("{}:0", "bb".repeat(32)),
                unspent: true,
                spent_by: None,
                height: 101,
            }],
            records: vec![LightRecord {
                txid: "ff".repeat(32),
                height: 102,
                block_hash: "dd".repeat(32),
                merkle_path: vec![8, 9],
                record: vec![10, 11, 12],
            }],
            records_through: 102,
            covers: vec![
                LightCover::Tx("aa".repeat(32)),
                LightCover::Output(format!("{}:0", "bb".repeat(32))),
                LightCover::Record("ff".repeat(32)),
            ],
        };
        let ans_bytes = sign(&core, 102, ans.clone());
        let ans_env = verify(&ans_bytes).unwrap();
        assert_eq!(ans_env.msg, ans);
        assert_eq!(ans_env.msg.name(), "light-answer");
        assert_eq!(ans_env.msg.case_id(), None);
        assert!(ans_env.msg.check_light_bounds(ans_bytes.len()).is_ok());
        assert!(is_light_b64(&b64(&ans_bytes)));

        // Bounds checks reject oversized header counts, malformed header lengths, and byte caps.
        assert!(ans_env
            .msg
            .check_light_bounds(LIGHT_MAX_ANSWER_BYTES + 1)
            .is_err());
        let bad_hdr_len = Msg::LightAnswer {
            id: "01".repeat(16),
            ask_hash: ask_hash.clone(),
            tip_height: 102,
            tip_hash: "dd".repeat(32),
            headers_from: 101,
            headers: vec![vec![0x11; 79]],
            txs: vec![],
            outputs: vec![],
            records: vec![],
            records_through: 102,
            covers: vec![],
        };
        assert!(bad_hdr_len.check_light_bounds(100).is_err());

        let too_many_hdrs = Msg::LightAnswer {
            id: "01".repeat(16),
            ask_hash: ask_hash.clone(),
            tip_height: 3000,
            tip_hash: "dd".repeat(32),
            headers_from: 1,
            headers: vec![vec![0u8; 80]; LIGHT_MAX_HEADERS + 1],
            txs: vec![],
            outputs: vec![],
            records: vec![],
            records_through: 3000,
            covers: vec![],
        };
        assert!(too_many_hdrs.check_light_bounds(200_000).is_err());

        // Tampering with any byte (e.g. covers or outputs) breaks signature verification.
        let mut tampered = ans_bytes.clone();
        let mid = tampered.len() / 2;
        tampered[mid] ^= 0xff;
        assert!(verify(&tampered).is_err());

        // Empty-set answer still signs and verifies cleanly (§7.2 omission accountability).
        let empty = Msg::LightAnswer {
            id: "01".repeat(16),
            ask_hash,
            tip_height: 102,
            tip_hash: "dd".repeat(32),
            headers_from: 102,
            headers: vec![],
            txs: vec![],
            outputs: vec![],
            records: vec![],
            records_through: 102,
            covers: vec![],
        };
        let empty_bytes = sign(&core, 102, empty.clone());
        assert_eq!(verify(&empty_bytes).unwrap().msg, empty);
    }
}
