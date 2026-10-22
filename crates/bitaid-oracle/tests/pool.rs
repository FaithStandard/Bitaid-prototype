//! The oracle pool end to end, in one process: DKG, a nonce batch with a cheating dealer, publicly
//! verifiable attestation shares completing a real pre-signed payout from bitaid-core, a member caught
//! attesting a wrong outcome, and FROST co-signatures that survive offline and stalling members.
use bitaid_core::endings::Pot;
use bitaid_core::hashes::case_id;
use bitaid_core::oracle::{random_scalar, verify_bip340};
use bitaid_core::payouts::Parties;
use bitaid_core::presign::{IncidentSet, IncidentTerms};
use bitaid_oracle::cosign::{sign_local, Behaviour};
use bitaid_oracle::{attest, keygen, nonces};
use bitcoin::hashes::Hash;
use bitcoin::{ScriptBuf, Txid};
use musig2::secp::{Point, G};
use std::collections::BTreeMap;

fn spk(b: u8) -> ScriptBuf {
    ScriptBuf::from_bytes([0x51, 0x20].into_iter().chain([b; 32]).collect())
}

#[test]
fn pool_end_to_end() {
    let (n, t) = (7u16, 4usize);
    let members: Vec<u16> = (1..=n).collect();
    // ---------------------------------------------------------------- key
    let keys = keygen::run_local(n, t as u16);
    let q = keys[0].pool_key();
    assert!(
        keys.iter().all(|k| k.pool_key() == q),
        "every member derives the same pool key"
    );
    let q_even = if q.has_even_y() { q } else { -q };

    // ---------------------------------------------------------------- nonce batch, member 5 deals a bad share
    let (views, qualified) = nonces::run_local(&members, t as u16, 6, 1, Some(5));
    assert!(
        !qualified.contains(&5) && qualified.len() == 6,
        "the cheating dealer is disqualified"
    );
    assert!(
        views.iter().all(|v| v.r == views[0].r),
        "every member derives the same nonce points"
    );
    assert!(views[0].r.iter().all(|r| r.has_even_y()));
    let mut views: BTreeMap<u16, nonces::Batch> = views.into_iter().map(|v| (v.me, v)).collect();

    // ---------------------------------------------------------------- a case pre-signed against the pool
    let case = case_id("pool-case");
    let secrets: Vec<_> = (0..4).map(|_| random_scalar()).collect();
    let terms = IncidentTerms {
        case_id: case,
        set_version: 0,
        pots: [100_000, 600_000, 300_000],
        parties: Parties {
            caller: spk(0),
            responders: (1..=3).map(spk).collect(),
            merit: vec![1, 1, 1],
            good_faith_pct: 50,
        },
        signers: secrets.iter().map(|s| *s * G).collect::<Vec<Point>>(),
        oracle: q_even,
        oracle_nonces: [views[&1].r[0], views[&1].r[1], views[&1].r[2]],
        refund_height: 1000,
    };
    let mut set = IncidentSet::build(terms, Txid::all_zeros());
    set.sign_locally(&secrets);
    assert!(set.verify_all());
    let label = "paid (5, 3, 2)";
    let m = set.message(Pot::Reward, label).unwrap();
    let wrong = set.message(Pot::Reward, "withheld").unwrap();

    // ---------------------------------------------------------------- attestation, members 1-3 offline
    let mut shares = Vec::new();
    for id in [4u16, 6, 7] {
        let k = &keys[id as usize - 1];
        shares.push(attest::share(k, views.get_mut(&id).unwrap(), 1, &m).unwrap());
    }
    // member 2 attests a different outcome under the same nonce: a valid share, but for the wrong message
    let liar = attest::share(&keys[1], views.get_mut(&2).unwrap(), 1, &wrong).unwrap();
    assert!(
        attest::verify(&keys[0].pool(), &views[&1].public(), &liar),
        "the share verifies against member 2's public shares"
    );
    assert_ne!(
        liar.message, m,
        "so it is signed evidence that member 2 attested an outcome the log does not support"
    );
    assert!(
        attest::combine(&keys[0].pool(), &views[&1].public(), &shares, &m, t).is_err(),
        "three shares are not enough"
    );
    shares.push(attest::share(&keys[2], views.get_mut(&3).unwrap(), 1, &m).unwrap());
    // a corrupted share is rejected by anyone
    let mut forged = shares[0].clone();
    forged.s = (forged.s + musig2::secp::Scalar::one()).not_zero().unwrap();
    assert!(!attest::verify(
        &keys[0].pool(),
        &views[&1].public(),
        &forged
    ));
    let s = attest::combine(&keys[0].pool(), &views[&1].public(), &shares, &m, t)
        .expect("four valid shares combine");
    assert!(
        set.complete(Pot::Reward, label, s).is_some(),
        "the pool's attestation completes the pre-signed payout"
    );
    assert!(
        set.complete(Pot::Reward, "withheld", s).is_none(),
        "and no other"
    );
    assert!(
        attest::share(&keys[3], views.get_mut(&4).unwrap(), 1, &wrong).is_err(),
        "a member refuses a second outcome on a spent nonce"
    );

    // ---------------------------------------------------------------- co-signature: 2 offline, 1 stalls
    let digest = bitaid_core::hashes::tagged("test/acceptance", b"incident transaction digest");
    let mut beh = BTreeMap::new();
    beh.insert(1, Behaviour::Offline);
    beh.insert(2, Behaviour::Offline);
    beh.insert(3, Behaviour::Stalls);
    let out = sign_local(&keys, &beh, t, &digest).expect("co-signature");
    assert!(
        verify_bip340(&keys[0].xonly(), &digest, &out.signature),
        "valid BIP340 signature under the pool's x-only key"
    );
    assert_eq!(
        out.sessions, 2,
        "the staller is replaced in a second session"
    );
    assert!(!out.signers.contains(&3));
    beh.insert(4, Behaviour::Offline);
    assert!(
        sign_local(&keys, &beh, t, &digest).is_err(),
        "below t responsive members, nothing is signed"
    );
}
