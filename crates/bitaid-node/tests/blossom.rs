use bitaid_core::hashes::sha256;
use bitaid_node::blossom::{self, Policy};
use bitcoin::secp256k1::{Keypair, Secp256k1};

fn kp() -> Keypair {
    Keypair::new(&Secp256k1::new(), &mut rand::thread_rng())
}

#[test]
fn archivist_stores_only_live_case_evidence_from_parties() {
    let dir = std::env::temp_dir().join(format!("bitaid-blossom-{}", rand::random::<u32>()));
    let policy = Policy::default();
    let srv = blossom::spawn("127.0.0.1:0", dir, policy.clone()).unwrap();
    let (party, stranger) = (kp(), kp());
    let case = hex::encode([7u8; 32]);
    policy.allow(&case, &hex::encode(party.x_only_public_key().0.serialize()));

    let key: [u8; 32] = rand::random();
    let footage: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
    let blobs = blossom::seal_footage(&key, &case, &footage, 128 * 1024);
    assert_eq!(blobs.len(), 3);
    for b in &blobs {
        let h = blossom::upload(&srv.url, &party, &case, b).expect("party uploads");
        assert_eq!(h, hex::encode(sha256(b)));
    }
    // a stranger, and a party naming another case, are refused
    let e = blossom::upload(&srv.url, &stranger, &case, &blobs[0]).unwrap_err();
    assert!(e.starts_with("401"), "{e}");
    let other = hex::encode([8u8; 32]);
    assert!(blossom::upload(&srv.url, &party, &other, &blobs[0]).is_err());
    assert_eq!(*srv.refused.lock().unwrap(), 2);

    // anyone can fetch ciphertext by hash; only the key holder reads it
    let got: Vec<Vec<u8>> = blobs
        .iter()
        .map(|b| blossom::fetch(&srv.url, &hex::encode(sha256(b))).unwrap())
        .collect();
    assert_eq!(blossom::open_footage(&key, &case, &got).unwrap(), footage);
    assert!(blossom::open_footage(&[0u8; 32], &case, &got).is_none());

    // a single 4 KiB slice by range request matches the blob's slice
    let h0 = hex::encode(sha256(&blobs[0]));
    let s = blossom::fetch_slice(&srv.url, &h0, 5).unwrap();
    assert_eq!(&s[..], &blobs[0][5 * 4096..6 * 4096]);
    assert_ne!(
        blossom::slice_root(&blobs[0]),
        blossom::slice_root(&blobs[1])
    );
}

#[test]
fn concurrent_fetches_never_stall() {
    let dir = std::env::temp_dir().join(format!("bitaid-blossom-{}", rand::random::<u32>()));
    let policy = Policy::default();
    let srv = blossom::spawn("127.0.0.1:0", dir, policy.clone()).unwrap();
    let party = kp();
    let case = hex::encode([9u8; 32]);
    policy.allow(&case, &hex::encode(party.x_only_public_key().0.serialize()));
    let mut hashes = vec![];
    for i in 0..6u8 {
        let b: Vec<u8> = (0..262_144u32).map(|j| (j as u8) ^ i).collect();
        hashes.push(blossom::upload(&srv.url, &party, &case, &b).unwrap());
    }
    let t0 = std::time::Instant::now();
    let hs: Vec<_> = (0..8)
        .map(|_| {
            let (u, h) = (srv.url.clone(), hashes.clone());
            std::thread::spawn(move || {
                for _ in 0..5 {
                    for x in &h {
                        blossom::fetch(&u, x).unwrap();
                    }
                }
            })
        })
        .collect();
    for h in hs {
        h.join().unwrap();
    }
    assert!(
        t0.elapsed() < std::time::Duration::from_secs(20),
        "{:?}",
        t0.elapsed()
    );
}
