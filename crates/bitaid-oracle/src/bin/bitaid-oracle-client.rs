//! Drives a networked oracle pool: reads the members' public data from the relay, coordinates FROST
//! co-signing (ROAST-style: a member that does not return its share is replaced in a new session), and
//! requests and combines attestation shares, checking every share in public.
//! Usage: bitaid-oracle-client --hub HOST:PORT --n N --t T
//! With BITAID_CLI set to a regtest bitcoin-cli command line, it runs a whole incident on chain with the
//! networked pool as its oracle; otherwise it attests and co-signs test messages.
#[path = "../../../bitaid-core/examples/common/mod.rs"]
#[allow(dead_code)]
mod common;
use bitaid_core::endings::Pot;
use bitaid_core::hashes::{case_id, tagged};
use bitaid_core::oracle::{random_scalar, sign_bip340, verify_bip340};
use bitaid_core::outputs::{self, funding_leaf};
use bitaid_core::payouts::Parties;
use bitaid_core::presign::{IncidentSet, IncidentTerms};
use bitaid_core::txbuild;
use bitaid_oracle::keygen::PoolPublic;
use bitaid_oracle::net::{Conn, Msg};
use bitaid_oracle::{attest, conv, nonces};
use bitcoin::Witness;
use frost_secp256k1_tr as frost;
use musig2::secp::{Point, G};
use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

fn arg(name: &str) -> Option<String> {
    let a: Vec<String> = std::env::args().collect();
    a.iter()
        .position(|x| x == name)
        .and_then(|i| a.get(i + 1).cloned())
}

struct Pool {
    conn: Conn,
    t: usize,
    pool: PoolPublic,
    batch: nonces::BatchPublic,
    next: u64,
    excluded: BTreeSet<u16>,
}

impl Pool {
    fn cosign(&mut self, digest: &[u8; 32]) -> Result<([u8; 64], usize, Vec<u16>), String> {
        let mut sessions = 0;
        loop {
            sessions += 1;
            self.next += 1;
            let session = self.next;
            self.conn.send(&Msg::CosignReq {
                session,
                digest: hex::encode(digest),
            });
            let excl = self.excluded.clone();
            let commits = self.conn.collect(
                |m| matches!(m, Msg::Commit { session: s, id, .. } if *s == session && !excl.contains(id)),
                self.t,
                Duration::from_secs(5),
            );
            if commits.len() < self.t {
                return Err(format!("only {} members committed", commits.len()));
            }
            let mut cm = BTreeMap::new();
            for m in &commits {
                if let Msg::Commit { id, c, .. } = m {
                    cm.insert(
                        conv::id(*id),
                        frost::round1::SigningCommitments::deserialize(&hex::decode(c).unwrap())
                            .unwrap(),
                    );
                }
            }
            let chosen: Vec<u16> = commits
                .iter()
                .filter_map(|m| {
                    if let Msg::Commit { id, .. } = m {
                        Some(*id)
                    } else {
                        None
                    }
                })
                .collect();
            let package = frost::SigningPackage::new(cm, digest);
            self.conn.send(&Msg::Package {
                session,
                pkg: hex::encode(package.serialize().unwrap()),
            });
            let got = self.conn.collect(
                |m| matches!(m, Msg::SigShare { session: s, .. } if *s == session),
                self.t,
                Duration::from_secs(3),
            );
            let mut shares = BTreeMap::new();
            for m in &got {
                if let Msg::SigShare { id, s, .. } = m {
                    shares.insert(
                        conv::id(*id),
                        frost::round2::SignatureShare::deserialize(&hex::decode(s).unwrap())
                            .unwrap(),
                    );
                }
            }
            if shares.len() < self.t {
                for id in &chosen {
                    if !shares.contains_key(&conv::id(*id)) {
                        self.excluded.insert(*id); // timed out: replaced in the next session
                    }
                }
                continue;
            }
            let sig = frost::aggregate(&package, &shares, &self.pool.public)
                .map_err(|e| e.to_string())?;
            let mut out = [0u8; 64];
            out.copy_from_slice(&sig.serialize().unwrap());
            return Ok((out, sessions, chosen));
        }
    }

    fn attest(
        &mut self,
        index: usize,
        m: &[u8; 32],
    ) -> Result<(musig2::secp::Scalar, Vec<String>), String> {
        self.next += 1;
        let req = self.next;
        self.conn.send(&Msg::AttestReq {
            req,
            index,
            message: hex::encode(m),
        });
        let mut shares = Vec::new();
        let mut notes = Vec::new();
        let end = Instant::now() + Duration::from_secs(10);
        while Instant::now() < end {
            let Some(Msg::AttestShare { share, .. }) = self.conn.wait(
                |x| matches!(x, Msg::AttestShare { req: r, .. } if *r == req),
                end - Instant::now(),
            ) else {
                break;
            };
            if !attest::verify(&self.pool, &self.batch, &share) {
                notes.push(format!("member {}: invalid share, rejected", share.member));
            } else if &share.message != m {
                notes.push(format!(
                    "member {}: valid share for a different outcome — signed evidence against it",
                    share.member
                ));
            } else {
                shares.push(share);
            }
            if let Ok(s) = attest::combine(&self.pool, &self.batch, &shares, m, self.t) {
                return Ok((s, notes));
            }
        }
        Err(format!("only {} valid shares; {:?}", shares.len(), notes))
    }
}

fn main() {
    let hub = arg("--hub").unwrap_or("127.0.0.1:7400".into());
    let n: u16 = arg("--n").expect("--n").parse().unwrap();
    let t: usize = arg("--t").expect("--t").parse().unwrap();
    let mut conn = Conn::connect(&hub).expect("connect");
    let mut rep = common::Report(0, 0);

    // the pool's public data, from the relay's history
    let readies = conn.collect(
        |m| matches!(m, Msg::Ready { .. }),
        n as usize,
        Duration::from_secs(60),
    );
    let Some(Msg::Ready {
        q,
        public,
        qualified,
        members,
        ..
    }) = readies.first().cloned()
    else {
        panic!("no member ready")
    };
    let agree = readies.iter().all(
        |m| matches!(m, Msg::Ready { q: q2, qualified: ql, .. } if *q2 == q && *ql == qualified),
    );
    rep.check(
        &format!(
            "{} members ready, all agreeing on the pool key and the qualified dealers",
            readies.len()
        ),
        agree,
        &q,
    );
    let pool = PoolPublic {
        public: frost::keys::PublicKeyPackage::deserialize(&hex::decode(public).unwrap()).unwrap(),
    };
    let commits: BTreeMap<u16, nonces::Commitments> = conn
        .collect(
            |m| matches!(m, Msg::NonceCommit { .. }),
            n as usize,
            Duration::from_secs(10),
        )
        .into_iter()
        .filter_map(|m| {
            if let Msg::NonceCommit { c } = m {
                Some((c.dealer, c))
            } else {
                None
            }
        })
        .collect();
    let batch = nonces::public_view(&members, &commits, &qualified.iter().copied().collect());
    let mut p = Pool {
        conn,
        t,
        pool,
        batch,
        next: 0,
        excluded: BTreeSet::new(),
    };

    match std::env::var("BITAID_CLI") {
        Err(_) => {
            let d = tagged("test/acceptance", b"digest");
            let t0 = Instant::now();
            match p.cosign(&d) {
                Ok((sig, sessions, signers)) => rep.check(
                    "Co-signature over the network",
                    verify_bip340(&p.pool.xonly(), &d, &sig),
                    &format!(
                        "{sessions} session(s), signers {signers:?}, {:.0} ms",
                        t0.elapsed().as_secs_f64() * 1e3
                    ),
                ),
                Err(e) => rep.check("Co-signature over the network", false, &e),
            }
            let m = tagged("test/outcome", b"m");
            let t0 = Instant::now();
            match p.attest(0, &m) {
                Ok((s, notes)) => rep.check(
                    "Attestation over the network",
                    s * G
                        == bitaid_core::oracle::attestation_point(
                            &p.batch.r[0],
                            &p.pool.even_key(),
                            &m,
                        ),
                    &format!(
                        "{:.0} ms; {}",
                        t0.elapsed().as_secs_f64() * 1e3,
                        notes.join("; ")
                    ),
                ),
                Err(e) => rep.check("Attestation over the network", false, &e),
            }
        }
        Ok(_) => {
            let rpc = common::rpc_from_env();
            let secp = bitcoin::secp256k1::Secp256k1::new();
            let qx = bitcoin::XOnlyPublicKey::from_slice(&p.pool.xonly()).unwrap();
            let (w, k) = (random_scalar(), random_scalar());
            let pots = [100_000u64, 600_000, 300_000];
            let total: u64 = pots.iter().sum();
            let ft = outputs::funding(
                &secp,
                &common::xo(&w),
                &common::xo(&k),
                &qx,
                rpc.height() + 52_560,
            );
            let fop = rpc.fund(&ft.script_pubkey(), total);
            let resp: Vec<_> = (0..3).map(|_| random_scalar()).collect();
            let mut secrets = vec![k];
            secrets.extend(resp.iter().copied());
            let signers: Vec<Point> = secrets.iter().map(|s| *s * G).collect();
            let pot_spk =
                bitaid_core::musig::pot_script_pubkey(&bitaid_core::musig::taproot_ctx(&signers));
            let mut inc = txbuild::incident(fop, &pots, &pot_spk);
            let leaf = &ft.scripts[funding_leaf::ACCEPT];
            let d = txbuild::scriptspend_digest(
                &inc,
                0,
                &[txbuild::txout(total, ft.script_pubkey())],
                leaf,
            );
            let t0 = Instant::now();
            match p.cosign(&d) {
                Ok((co, sessions, signers_used)) => {
                    let ms = t0.elapsed().as_secs_f64() * 1e3;
                    inc.input[0].witness = Witness::from_slice(&[
                        co.to_vec(),
                        sign_bip340(&k, &d).to_vec(),
                        leaf.to_bytes(),
                        ft.control(funding_leaf::ACCEPT).serialize(),
                    ]);
                    let r = rpc.package(&inc);
                    rep.check(
                        "Acceptance co-signed by the networked pool and confirmed",
                        r.is_ok(),
                        &format!(
                            "{sessions} session(s), signers {signers_used:?}, {ms:.0} ms; {}",
                            common::reasons(&r)
                        ),
                    );
                }
                Err(e) => rep.check("Acceptance co-signed by the networked pool", false, &e),
            }
            rpc.mine(1);
            let case = case_id(&format!("net-{}", rpc.height()));
            let terms = IncidentTerms {
                case_id: case,
                set_version: 0,
                pots,
                parties: Parties {
                    caller: rpc.new_spk(),
                    responders: (0..3).map(|_| rpc.new_spk()).collect(),
                    merit: vec![1, 1, 1],
                    good_faith_pct: 50,
                },
                signers,
                oracle: p.pool.even_key(),
                oracle_nonces: [p.batch.r[0], p.batch.r[1], p.batch.r[2]],
                refund_height: rpc.height() + 12_960,
            };
            let mut set = IncidentSet::build(terms, inc.compute_txid());
            set.sign_locally(&secrets);
            for (pot, label) in [
                (Pot::Deposit, "returned"),
                (Pot::Reward, "paid (6, 4, 0)"),
                (Pot::Bounty, "split (4, 3, 3)"),
            ] {
                let m = set.message(pot, label).unwrap();
                let t0 = Instant::now();
                match p.attest(pot.index(), &m) {
                    Ok((s, notes)) => {
                        let ms = t0.elapsed().as_secs_f64() * 1e3;
                        let tx = set.complete(pot, label, s).expect("completes");
                        let r = rpc.package(&tx);
                        rep.check(
                            &format!(
                                "{}: \"{label}\" attested over the network and accepted",
                                pot.name()
                            ),
                            r.is_ok(),
                            &format!(
                                "{ms:.0} ms; {}{}",
                                common::reasons(&r),
                                if notes.is_empty() {
                                    String::new()
                                } else {
                                    format!("; {}", notes.join("; "))
                                }
                            ),
                        );
                    }
                    Err(e) => rep.check(&format!("{}: attestation", pot.name()), false, &e),
                }
            }
            rpc.mine(1);
            rep.check(
                "All three pots paid on chain",
                set.pot_outpoints.iter().flatten().all(|op| rpc.spent(op)),
                "",
            );
        }
    }
    println!("{} passed, {} failed", rep.0, rep.1);
    std::process::exit(if rep.1 == 0 { 0 } else { 1 });
}
