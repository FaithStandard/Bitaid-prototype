//! The full incident set for six signers (caller + five responders): 387 payouts and three refunds,
//! every partial signature verified, every pre-signature checked against its attestation point, the
//! right attestation completing its payout and every other outcome's attestation failing.
use bitaid_core::endings::Pot;
use bitaid_core::hashes::outcome_msg;
use bitaid_core::oracle::{random_scalar, Oracle};
use bitaid_core::payouts::Parties;
use bitaid_core::presign::{event_id, IncidentSet, IncidentTerms};
use bitcoin::hashes::Hash;
use bitcoin::{ScriptBuf, Txid};
use musig2::secp::{Point, G};
use std::time::Instant;

fn spk(b: u8) -> ScriptBuf {
    ScriptBuf::from_bytes([0x51, 0x20].into_iter().chain([b; 32]).collect())
}

#[test]
fn full_set_six_signers() {
    let secrets: Vec<_> = (0..6).map(|_| random_scalar()).collect();
    let signers: Vec<Point> = secrets.iter().map(|s| *s * G).collect();
    let mut oracle = Oracle::new();
    let case = "case-rust-1";
    let nonces = Pot::ALL.map(|p| oracle.announce(&event_id(case, p)));
    let terms = IncidentTerms {
        case: case.into(),
        pots: [100_000, 600_000, 300_000],
        parties: Parties {
            caller: spk(0),
            responders: (1..=5).map(spk).collect(),
            merit: vec![3, 1, 2, 1, 1],
            good_faith_pct: 50,
        },
        signers,
        oracle: oracle.pubkey(),
        oracle_nonces: nonces,
        refund_height: 1_000,
    };
    let mut set = IncidentSet::build(terms, Txid::all_zeros());
    assert_eq!(set.len(), 387);
    let t0 = Instant::now();
    set.sign_locally(&secrets);
    eprintln!(
        "signed 387 payouts + 3 refunds for six signers in {:.2} s",
        t0.elapsed().as_secs_f64()
    );
    assert!(set.verify_all());
    // settle the reward on one ending: only its attestation completes it
    let label = "paid (2, 1, 1, 1, 0)";
    let m = outcome_msg(case, "reward", label);
    let s = oracle.attest(&event_id(case, Pot::Reward), &m).unwrap();
    assert!(set.complete(Pot::Reward, label, s).is_some());
    let wrong = set
        .payouts
        .iter()
        .filter(|p| p.ending.pot == Pot::Reward && p.ending.label != label);
    assert!(wrong.clone().count() == 252);
    for p in wrong {
        assert!(
            set.complete(Pot::Reward, &p.ending.label, s).is_none(),
            "{} completed with another outcome's attestation",
            p.ending.label
        );
    }
    // a second, different attestation under the same nonce is refused by the oracle
    assert!(oracle
        .attest(
            &event_id(case, Pot::Reward),
            &outcome_msg(case, "reward", "withheld")
        )
        .is_err());
    assert!(set.refund(Pot::Deposit).is_some());
}
