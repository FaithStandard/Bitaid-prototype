//! One member of the oracle pool, as its own process.
//! Usage: bitaid-oracle-node --hub HOST:PORT --id I --n N --t T [--batch B] [--stall] [--liar]
//! Joins the pool's key generation and nonce batch with the other members over the relay, then serves
//! attestation and co-signing requests until stopped. `--stall` sends co-signing commitments but never
//! the share (to test replacement); `--liar` attests a different outcome than requested (to test that the
//! share is caught as evidence).
use bitaid_oracle::net::{open, seal, Conn, Msg};
use bitaid_oracle::{attest, conv, keygen::MemberKey, nonces};
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use frost_secp256k1_tr as frost;
use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

fn arg(name: &str) -> Option<String> {
    let a: Vec<String> = std::env::args().collect();
    a.iter()
        .position(|x| x == name)
        .and_then(|i| a.get(i + 1).cloned())
}
fn flag(name: &str) -> bool {
    std::env::args().any(|x| x == name)
}

fn main() {
    let hub = arg("--hub").unwrap_or("127.0.0.1:7400".into());
    let me: u16 = arg("--id").expect("--id").parse().unwrap();
    let n: u16 = arg("--n").expect("--n").parse().unwrap();
    let t: u16 = arg("--t").expect("--t").parse().unwrap();
    let batch_size: usize = arg("--batch").unwrap_or("8".into()).parse().unwrap();
    let (stall, liar) = (flag("--stall"), flag("--liar"));
    let wait = Duration::from_secs(
        arg("--setup-wait")
            .map(|s| s.parse().unwrap())
            .unwrap_or(900),
    );
    let secp = Secp256k1::new();
    let sk = SecretKey::new(&mut rand::thread_rng());
    let mut c = Conn::connect(&hub).expect("connect to hub");
    let t0 = Instant::now();
    let log = |s: &str| eprintln!("[member {me} {:>6.2}s] {s}", t0.elapsed().as_secs_f64());

    // ---------------------------------------------------------------- introductions
    c.send(&Msg::Hello {
        id: me,
        enc: hex::encode(PublicKey::from_secret_key(&secp, &sk).serialize()),
    });
    let mut peers: BTreeMap<u16, PublicKey> = BTreeMap::new();
    for m in c.collect(
        |m| matches!(m, Msg::Hello { id, .. } if *id != me),
        (n - 1) as usize,
        wait,
    ) {
        if let Msg::Hello { id, enc } = m {
            peers.insert(
                id,
                PublicKey::from_slice(&hex::decode(enc).unwrap()).unwrap(),
            );
        }
    }
    assert_eq!(peers.len(), (n - 1) as usize, "not every member joined");
    let members: Vec<u16> = (1..=n).collect();
    log("all members present");

    // ---------------------------------------------------------------- key generation (FROST DKG)
    let mut rng = rand::thread_rng();
    let (s1, p1) = frost::keys::dkg::part1(conv::id(me), n, t, &mut rng).unwrap();
    c.send(&Msg::Dkg1 {
        id: me,
        pkg: hex::encode(p1.serialize().unwrap()),
    });
    let mut r1 = BTreeMap::new();
    for m in c.collect(
        |m| matches!(m, Msg::Dkg1 { id, .. } if *id != me),
        (n - 1) as usize,
        wait,
    ) {
        if let Msg::Dkg1 { id, pkg } = m {
            r1.insert(
                conv::id(id),
                frost::keys::dkg::round1::Package::deserialize(&hex::decode(pkg).unwrap()).unwrap(),
            );
        }
    }
    let (s2, out) = frost::keys::dkg::part2(s1, &r1).expect("part2");
    for (to, pkg) in out {
        let to_n = members
            .iter()
            .copied()
            .find(|&i| conv::id(i) == to)
            .unwrap();
        let aad = [b"dkg2".as_slice(), &me.to_le_bytes(), &to_n.to_le_bytes()].concat();
        c.send(&Msg::Dkg2 {
            from: me,
            to: to_n,
            ct: seal(&sk, &peers[&to_n], &aad, &pkg.serialize().unwrap()),
        });
    }
    let mut r2 = BTreeMap::new();
    for m in c.collect(
        |m| matches!(m, Msg::Dkg2 { to, .. } if *to == me),
        (n - 1) as usize,
        wait,
    ) {
        if let Msg::Dkg2 { from, ct, .. } = m {
            let aad = [b"dkg2".as_slice(), &from.to_le_bytes(), &me.to_le_bytes()].concat();
            let pt = open(&sk, &peers[&from], &aad, &ct).expect("decrypt");
            r2.insert(
                conv::id(from),
                frost::keys::dkg::round2::Package::deserialize(&pt).unwrap(),
            );
        }
    }
    let (kp, pp) = frost::keys::dkg::part3(&s2, &r1, &r2)
        .expect("part3: a dealer's share failed verification");
    let key = MemberKey {
        id: me,
        key_package: kp,
        public: pp,
    };
    log(&format!("pool key {}", hex::encode(key.xonly())));

    // ---------------------------------------------------------------- nonce batch
    let dealer = nonces::Dealer::new(me, batch_size, t);
    c.send(&Msg::NonceCommit {
        c: dealer.commitments(1),
    });
    for &to in &members {
        if to == me {
            continue;
        }
        let sh = serde_json::to_vec(&dealer.shares_for(to, 1)).unwrap();
        let aad = [b"nonce".as_slice(), &me.to_le_bytes(), &to.to_le_bytes()].concat();
        c.send(&Msg::NonceShare {
            from: me,
            to,
            ct: seal(&sk, &peers[&to], &aad, &sh),
        });
    }
    let mut commits = BTreeMap::new();
    commits.insert(me, dealer.commitments(1));
    for m in c.collect(
        |m| matches!(m, Msg::NonceCommit { c } if c.dealer != me),
        (n - 1) as usize,
        wait,
    ) {
        if let Msg::NonceCommit { c: cm } = m {
            commits.insert(cm.dealer, cm);
        }
    }
    let mut received = BTreeMap::new();
    received.insert(me, dealer.shares_for(me, 1));
    let mut bad = Vec::new();
    for m in c.collect(
        |m| matches!(m, Msg::NonceShare { to, .. } if *to == me),
        (n - 1) as usize,
        wait,
    ) {
        if let Msg::NonceShare { from, ct, .. } = m {
            let aad = [b"nonce".as_slice(), &from.to_le_bytes(), &me.to_le_bytes()].concat();
            let ok = open(&sk, &peers[&from], &aad, &ct)
                .and_then(|pt| serde_json::from_slice::<nonces::Shares>(&pt).ok())
                .filter(|s| nonces::verify_share(&commits[&from], s));
            match ok {
                Some(s) => {
                    received.insert(from, s);
                }
                None => bad.push(from),
            }
        }
    }
    c.send(&Msg::NonceStatus {
        id: me,
        bad: bad.clone(),
    });
    let mut qualified: BTreeSet<u16> = members.iter().copied().collect();
    for b in &bad {
        qualified.remove(b);
    }
    for m in c.collect(
        |m| matches!(m, Msg::NonceStatus { id, .. } if *id != me),
        (n - 1) as usize,
        wait,
    ) {
        if let Msg::NonceStatus { bad, .. } = m {
            for b in bad {
                qualified.remove(&b);
            }
        }
    }
    let mut batch = nonces::finish(me, &members, &commits, &received, &qualified);
    c.send(&Msg::Ready {
        id: me,
        q: hex::encode(key.xonly()),
        public: hex::encode(key.public.serialize().unwrap()),
        qualified: qualified.iter().copied().collect(),
        members: members.clone(),
    });
    log(&format!(
        "ready: {} nonces, qualified dealers {:?}",
        batch_size, qualified
    ));

    // ---------------------------------------------------------------- serving
    let mut sessions: BTreeMap<u64, frost::round1::SigningNonces> = BTreeMap::new();
    while let Some(m) = c.wait(
        |m| {
            matches!(
                m,
                Msg::AttestReq { .. } | Msg::CosignReq { .. } | Msg::Package { .. }
            )
        },
        Duration::from_secs(3600),
    ) {
        match m {
            Msg::AttestReq {
                req,
                index,
                message,
            } => {
                let mut msg: [u8; 32] = hex::decode(message).unwrap().try_into().unwrap();
                if liar {
                    msg[31] ^= 1;
                }
                match attest::share(&key, &mut batch, index, &msg) {
                    Ok(share) => {
                        c.send(&Msg::AttestShare { req, share });
                        log(&format!(
                            "attested request {req} (nonce {index}){}",
                            if liar { " — a different outcome" } else { "" }
                        ));
                    }
                    Err(e) => log(&format!("refused request {req}: {e}")),
                }
            }
            Msg::CosignReq { session, .. } => {
                let (nonces, comm) =
                    frost::round1::commit(key.key_package.signing_share(), &mut rng);
                sessions.insert(session, nonces);
                c.send(&Msg::Commit {
                    session,
                    id: me,
                    c: hex::encode(comm.serialize().unwrap()),
                });
            }
            Msg::Package { session, pkg } => {
                let package =
                    frost::SigningPackage::deserialize(&hex::decode(pkg).unwrap()).unwrap();
                if !package.signing_commitments().contains_key(&conv::id(me)) {
                    continue;
                }
                let Some(nonces) = sessions.remove(&session) else {
                    continue;
                };
                if stall {
                    log(&format!("stalling on session {session}"));
                    continue;
                }
                let sh = frost::round2::sign(&package, &nonces, &key.key_package).unwrap();
                c.send(&Msg::SigShare {
                    session,
                    id: me,
                    s: hex::encode(sh.serialize()),
                });
                log(&format!("co-signed session {session}"));
            }
            _ => {}
        }
    }
}
