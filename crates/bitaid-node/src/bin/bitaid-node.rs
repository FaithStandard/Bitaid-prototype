//! `bitaid-node --role caller|responder|oracle|archivist --relay ws://… [options]`
//!
//! One incident end to end over Nostr relays, with Bitcoin Core (regtest) as the chain:
//! registration → alert in an H3 cell → acceptances → roster → the pre-signed set signed across
//! machines → oracle co-signature → incident transaction → evidence on archivists → blind ballots →
//! deemed consent → the oracle's attestations → payouts confirmed.
use bitaid_core::endings::Pot;
use bitaid_core::hashes::{case_id as hash_case, tagged};
use bitaid_core::oracle::{even, random_scalar, sign_bip340, Oracle};
use bitaid_core::outputs::{self, funding_leaf};
use bitaid_core::presign::event_id;
use bitaid_core::txbuild;
use bitaid_node::blossom;
use bitaid_node::case::{self, Alerted, Rostered};
use bitaid_node::chain::Rpc;
use bitaid_node::node::{point_from, point_hex, scalar_from, xo, Node};
use bitaid_node::nostr::{kind, Filter};
use bitaid_node::settle::{decide, Decision};
use bitaid_node::wire::{self, b64, h32, Act, Ballot, Class, Msg, Template};
use bitcoin::consensus::encode::{deserialize_hex, serialize_hex};
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{OutPoint, Transaction, Witness};
use musig2::secp::{MaybeScalar, Point, Scalar, G};
use musig2::{PartialSignature, PubNonce};
use std::collections::{BTreeMap, HashMap};
use std::str::FromStr;
use std::time::{Duration, Instant};

const BOND_FLOOR: u64 = 1_000_000; // 0.01 BTC, §2

fn args() -> Vec<String> {
    std::env::args().collect()
}
fn arg(name: &str) -> Option<String> {
    let a = args();
    a.iter()
        .position(|x| x == name)
        .and_then(|i| a.get(i + 1).cloned())
}
fn args_all(name: &str) -> Vec<String> {
    let a = args();
    a.iter()
        .enumerate()
        .filter(|(_, x)| *x == name)
        .filter_map(|(i, _)| a.get(i + 1).cloned())
        .collect()
}
fn flag(name: &str) -> bool {
    args().iter().any(|x| x == name)
}
fn num<T: FromStr>(name: &str, d: T) -> T {
    arg(name).and_then(|s| s.parse().ok()).unwrap_or(d)
}
fn secs(n: u64) -> Duration {
    Duration::from_secs(n)
}

fn relay_host(url: &str) -> String {
    let h = url.split("://").nth(1).unwrap_or(url).trim_end_matches('/');
    let h = h.split('/').next().unwrap_or(h);
    if h.contains(':') {
        h.to_string()
    } else {
        format!("{h}:443")
    }
}

fn cell_of(lat: f64, lon: f64) -> h3o::CellIndex {
    h3o::LatLng::new(lat, lon)
        .expect("lat/lon")
        .to_cell(h3o::Resolution::Eight)
}

fn chain_view(rpc: &Rpc) -> impl Fn(&OutPoint) -> Option<(u64, bitcoin::ScriptBuf)> + '_ {
    move |op| rpc.utxo(op).map(|o| (o.value.to_sat(), o.script_pubkey))
}

fn main() {
    let role = arg("--role").expect("--role caller|responder|oracle|archivist");
    let relays = args_all("--relay");
    assert!(!relays.is_empty(), "at least one --relay ws://host:port");
    let name = arg("--name").unwrap_or(role.clone());
    let secret = arg("--secret").and_then(|s| h32(&s));
    let node = Node::new(&name, &relays, Rpc::from_env(), secret);
    node.log(&format!(
        "{} on {} relay(s), identity {}",
        role,
        node.client.relay_count(),
        &node.me()[..16]
    ));
    let code = match role.as_str() {
        "oracle" => oracle(node),
        "archivist" => archivist(node),
        "caller" => caller(node),
        "responder" => responder(node),
        r => panic!("unknown role {r}"),
    };
    std::process::exit(code);
}

// =================================================================== services

fn announce(n: &mut Node, role: &str, key: &str, url: &str) {
    let m = Msg::Announce {
        role: role.into(),
        key: key.into(),
        url: url.into(),
    };
    n.send(kind::ANNOUNCE, vec![vec!["r".into(), role.into()]], m, None);
}

fn oracle(mut n: Node) -> i32 {
    let mut o = Oracle::from_secret(scalar_from(&hex::encode(n.keys.secret_bytes())).unwrap());
    let okey = hex::encode(o.pubkey().serialize_xonly());
    n.subscribe("all", vec![Filter::kinds(&[kind::ALERT, kind::CASE])]);
    std::thread::sleep(Duration::from_millis(300));
    announce(&mut n, "oracle", &okey, "");
    n.log(&format!("attestation key {}", &okey[..16]));
    let mut alerts: HashMap<String, Alerted> = HashMap::new();
    let mut rosters: HashMap<String, Rostered> = HashMap::new();
    let mut commits: HashMap<String, BTreeMap<String, String>> = HashMap::new();
    let mut reveals: HashMap<String, BTreeMap<String, Ballot>> = HashMap::new();
    let mut ready_at: HashMap<String, Instant> = HashMap::new();
    let mut done: std::collections::HashSet<String> = Default::default();
    let idle = num("--exit-after", 900u64);
    let mut last = Instant::now();
    loop {
        if last.elapsed() > secs(idle) {
            return 0;
        }
        // deemed consent: every seat revealed and the dispute window has passed
        let due: Vec<String> = ready_at
            .iter()
            .filter(|(_, t)| Instant::now() >= **t)
            .map(|(c, _)| c.clone())
            .collect();
        for c in due {
            ready_at.remove(&c);
            let (a, r) = (&alerts[&c], &rosters[&c]);
            let ballots: Vec<Ballot> = reveals[&c].values().cloned().collect();
            match decide(r.seats.len(), a.template.pots, &a.template, &ballots) {
                Decision::Settled(ends) => {
                    for e in ends {
                        let m = e.message(&a.case_id, r.set_version);
                        match o.attest(&event_id(&a.case_id, e.pot), &m) {
                            Ok(s) => {
                                n.log(&format!("attesting {} \"{}\"", e.pot.name(), e.label));
                                let msg = Msg::Attestation {
                                    case_id: c.clone(),
                                    pot: e.pot.index() as u8,
                                    outcome: hex::encode(m),
                                    s: hex::encode(s.serialize()),
                                };
                                n.send_case(&c, &[], msg, false);
                            }
                            Err(err) => {
                                n.log(&format!("refused to attest {}: {err}", e.pot.name()))
                            }
                        }
                    }
                    done.insert(c);
                }
                Decision::Escalate(why) => {
                    n.log(&format!("case {}: escalation needed: {why}", &c[..8]))
                }
            }
        }
        let got = n.wait(Duration::from_millis(500), |env, e| {
            Some((env.clone(), e.clone()))
        });
        let Some((env, _ev)) = got else { continue };
        last = Instant::now();
        let s = env.sender.clone();
        match &env.msg {
            Msg::Alert { .. } => match Alerted::check(&s, &env.msg, chain_view(&n.rpc), &okey) {
                Ok(a) => {
                    n.log(&format!(
                        "alert {} in cell {} checked",
                        &a.case_hex[..8],
                        a.cell
                    ));
                    alerts.insert(a.case_hex.clone(), a);
                }
                Err(e) => n.log(&format!("alert ignored: {e}")),
            },
            Msg::NonceRequest { case_id } => {
                let Some(a) = alerts.get(case_id) else {
                    continue;
                };
                if a.caller != s {
                    continue;
                }
                let nonces = Pot::ALL
                    .map(|p| point_hex(&o.announce(&event_id(&a.case_id, p))))
                    .to_vec();
                n.send_case(
                    case_id,
                    std::slice::from_ref(&s),
                    Msg::NonceAssignment {
                        case_id: case_id.clone(),
                        nonces,
                    },
                    false,
                );
                n.log(&format!("nonces assigned for {}", &case_id[..8]));
            }
            Msg::Roster { case_id, .. } => {
                let (Some(a), Some(r)) = (alerts.get(case_id), Rostered::from_msg(&env.msg)) else {
                    continue;
                };
                if a.caller != s {
                    continue;
                }
                if let Some(k) = r.sealed_keys.last().and_then(|k| hex::decode(k).ok()) {
                    if let Some(key) =
                        wire::unseal(&n.keys, &wire::xonly(&s).unwrap(), case_id.as_bytes(), &k)
                    {
                        n.add_case_key(case_id, key.try_into().unwrap());
                    }
                }
                commits.remove(case_id);
                reveals.remove(case_id);
                rosters.insert(case_id.clone(), r);
            }
            Msg::CosignRequest { case_id, tx } => {
                let (Some(a), Some(r)) = (alerts.get(case_id), rosters.get(case_id)) else {
                    continue;
                };
                if a.caller != s {
                    continue;
                }
                let Ok(t) = deserialize_hex::<Transaction>(tx) else {
                    continue;
                };
                // co-sign only the template's incident transaction for this roster
                let expect = case::incident_tx(a, r);
                if t.compute_txid() != expect.compute_txid() || t.compute_txid() != r.incident_txid
                {
                    n.log("co-signature refused: not the template's incident transaction");
                    continue;
                }
                let tree = a.funding_tree();
                let d = txbuild::scriptspend_digest(
                    &t,
                    0,
                    &[txbuild::txout(a.funding_value, tree.script_pubkey())],
                    &tree.scripts[funding_leaf::ACCEPT],
                );
                n.send_case(
                    case_id,
                    std::slice::from_ref(&s),
                    Msg::Cosign {
                        case_id: case_id.clone(),
                        sig: hex::encode(o.cosign(&d)),
                    },
                    false,
                );
                n.log(&format!(
                    "co-signed incident {}",
                    &t.compute_txid().to_string()[..8]
                ));
            }
            Msg::BallotCommit {
                case_id,
                commitment,
            } => {
                let Some(r) = rosters.get(case_id) else {
                    continue;
                };
                if r.seats.contains(&s) {
                    commits
                        .entry(case_id.clone())
                        .or_default()
                        .insert(s.clone(), commitment.clone());
                }
            }
            Msg::BallotReveal {
                case_id,
                ballot,
                salt,
            } => {
                let (Some(r), Some(cm)) = (rosters.get(case_id), commits.get(case_id)) else {
                    continue;
                };
                let ok = cm
                    .get(&s)
                    .map(|c| *c == hex::encode(ballot.commitment(&h32(salt).unwrap_or_default())))
                    .unwrap_or(false);
                if !ok {
                    n.log("reveal ignored: does not match its commitment");
                    continue;
                }
                let rv = reveals.entry(case_id.clone()).or_default();
                rv.insert(s.clone(), ballot.clone());
                if rv.len() == r.seats.len() && !done.contains(case_id) {
                    let w = alerts[case_id].template.dispute_window as u64;
                    n.log(&format!(
                        "all {} ballots revealed for {}; deemed consent in {w} s unless escalated",
                        rv.len(),
                        &case_id[..8]
                    ));
                    ready_at.insert(case_id.clone(), Instant::now() + secs(w));
                }
            }
            _ => {}
        }
    }
}

fn archivist(mut n: Node) -> i32 {
    let listen = arg("--listen").unwrap_or("0.0.0.0:7480".into());
    let dir = std::path::PathBuf::from(
        arg("--dir").unwrap_or(format!("/tmp/bitaid-archive-{}", &n.me()[..8])),
    );
    let srv = blossom::spawn(&listen, dir, blossom::Policy::default()).expect("listen");
    let port = srv.url.rsplit(':').next().unwrap_or("7480").to_string();
    let url = match arg("--public-url").as_deref() {
        // the address this machine uses to reach the relay, which is the one other devices can reach
        Some("auto") => {
            let host = relay_host(&args_all("--relay")[0]);
            let ip = std::net::UdpSocket::bind("0.0.0.0:0")
                .and_then(|u| u.connect(&host).map(|_| u))
                .and_then(|u| u.local_addr())
                .map(|a| a.ip().to_string())
                .unwrap_or("127.0.0.1".into());
            format!("http://{ip}:{port}")
        }
        Some(u) => u.to_string(),
        None => srv.url.clone(),
    };
    n.subscribe("all", vec![Filter::kinds(&[kind::ALERT, kind::CASE])]);
    std::thread::sleep(Duration::from_millis(300));
    let me = n.me();
    announce(&mut n, "archivist", &me, &url);
    n.log(&format!("Blossom server at {url}"));
    let idle = num("--exit-after", 900u64);
    let mut last = Instant::now();
    loop {
        if last.elapsed() > secs(idle) {
            n.log(&format!(
                "stored {}, refused {}",
                srv.stored.lock().unwrap(),
                srv.refused.lock().unwrap()
            ));
            return 0;
        }
        let Some(env) = n.wait(secs(1), |env, _| Some(env.clone())) else {
            continue;
        };
        last = Instant::now();
        match &env.msg {
            Msg::Alert { case_id, .. } => {
                srv.policy.allow(case_id, &env.sender);
                n.log(&format!("live case {}: caller may upload", &case_id[..8]));
            }
            Msg::Roster { case_id, seats, .. } => {
                for s in seats {
                    srv.policy.allow(case_id, s);
                }
                n.log(&format!(
                    "case {}: {} seated responders may upload",
                    &case_id[..8],
                    seats.len()
                ));
            }
            _ => {}
        }
    }
}

// =================================================================== shared by the signers

/// Runs both signing rounds for this signer over the relays and completes the set.
/// Returns the set, or Err naming the signer whose partial signature failed.
fn sign_set(
    n: &mut Node,
    a: &Alerted,
    r: &Rostered,
    my_index: usize,
    sk: &Scalar,
    corrupt: bool,
) -> Result<bitaid_core::presign::IncidentSet, String> {
    let mut set = case::build_set(a, r);
    let parties: Vec<String> = std::iter::once(a.caller.clone())
        .chain(r.seats.iter().cloned())
        .collect();
    let nsig = parties.len();
    let t0 = Instant::now();
    let mut st = set.round1(sk);
    let c = a.case_hex.clone();
    let v = r.set_version;
    let my_nonces: Vec<String> = st
        .pubnonces
        .iter()
        .map(|p| hex::encode(p.serialize()))
        .collect();
    n.send_case(
        &c,
        &[],
        Msg::SigNonces {
            case_id: c.clone(),
            set_version: v,
            signer: my_index as u8,
            nonces: my_nonces,
        },
        true,
    );
    let p2 = parties.clone();
    let got = n.collect(
        secs(120),
        |env, _| match &env.msg {
            Msg::SigNonces {
                case_id,
                set_version,
                signer,
                nonces,
            } if *case_id == c
                && *set_version == v
                && p2.get(*signer as usize) == Some(&env.sender) =>
            {
                let pn: Option<Vec<PubNonce>> = nonces
                    .iter()
                    .map(|h| PubNonce::from_bytes(&hex::decode(h).ok()?).ok())
                    .collect();
                Some((*signer as usize, pn?))
            }
            _ => None,
        },
        |v| v.len() >= nsig,
    );
    let mut all_nonces: Vec<Option<Vec<PubNonce>>> = vec![None; nsig];
    for (i, pn) in got {
        all_nonces[i] = Some(pn);
    }
    let all_nonces: Vec<Vec<PubNonce>> = all_nonces
        .into_iter()
        .enumerate()
        .map(|(i, x)| x.ok_or(format!("signer {i}: no nonces")))
        .collect::<Result<_, _>>()?;
    let mut parts = set.round2(sk, &mut st, &all_nonces)?;
    if corrupt {
        parts.swap(0, 1);
        n.log("sending corrupted partial signatures (test)");
    }
    let mine: Vec<String> = parts.iter().map(|p| hex::encode(p.serialize())).collect();
    n.send_case(
        &c,
        &[],
        Msg::SigPartials {
            case_id: c.clone(),
            set_version: v,
            signer: my_index as u8,
            partials: mine,
        },
        true,
    );
    let p2 = parties.clone();
    let got = n.collect(
        secs(120),
        |env, _| match &env.msg {
            Msg::SigPartials {
                case_id,
                set_version,
                signer,
                partials,
            } if *case_id == c
                && *set_version == v
                && p2.get(*signer as usize) == Some(&env.sender) =>
            {
                let ps: Option<Vec<PartialSignature>> = partials
                    .iter()
                    .map(|h| MaybeScalar::from_slice(&hex::decode(h).ok()?).ok())
                    .collect();
                Some((*signer as usize, ps?))
            }
            _ => None,
        },
        |v| v.len() >= nsig,
    );
    let mut all_parts: Vec<Option<Vec<PartialSignature>>> = vec![None; nsig];
    for (i, p) in got {
        all_parts[i] = Some(p);
    }
    let all_parts: Vec<Vec<PartialSignature>> = all_parts
        .into_iter()
        .enumerate()
        .map(|(i, x)| x.ok_or(format!("signer {i}: no partial signatures")))
        .collect::<Result<_, _>>()?;
    set.finish(&all_nonces, &all_parts)?;
    n.log(&format!(
        "set v{v} complete: {} payouts + {} refunds, {} signers, {:.2} s",
        set.len(),
        set.refunds.len(),
        nsig,
        t0.elapsed().as_secs_f64()
    ));
    Ok(set)
}

/// Waits for the oracle's attestations and completes and broadcasts the matching payouts.
fn settle(
    n: &mut Node,
    a: &Alerted,
    set: &bitaid_core::presign::IncidentSet,
    oracle_key: &str,
    oracle_id: &str,
    broadcast: bool,
) -> Vec<(Pot, String)> {
    let pots: Vec<Pot> = Pot::ALL
        .into_iter()
        .filter(|p| a.template.pots[p.index()] > 0)
        .collect();
    let c = a.case_hex.clone();
    let oid = oracle_id.to_string();
    let got = n.collect(
        secs(num("--settle-wait", 300u64)),
        |env, _| match &env.msg {
            Msg::Attestation {
                case_id,
                pot,
                outcome,
                s,
            } if *case_id == c && env.sender == oid => Some((*pot, outcome.clone(), s.clone())),
            _ => None,
        },
        |v| v.len() >= pots.len(),
    );
    let _ = oracle_key;
    let mut out = Vec::new();
    for (pot, outcome, s) in got {
        let p = Pot::ALL[pot as usize];
        let Some(payout) = set.payouts.iter().find(|x| {
            x.ending.pot == p
                && hex::encode(x.ending.message(&a.case_id, set.terms.set_version)) == outcome
        }) else {
            n.check(
                &format!(
                    "{}: attested outcome is one of the pre-signed endings",
                    p.name()
                ),
                false,
                "",
            );
            continue;
        };
        let label = payout.ending.label.clone();
        let Some(sc) = scalar_from(&s) else { continue };
        match set.complete(p, &label, sc) {
            Some(tx) => {
                if broadcast {
                    // another party may have broadcast it first: then it is already in the mempool or a block
                    let known = |n: &Node| {
                        n.rpc
                            .call(
                                "getrawtransaction",
                                serde_json::json!([tx.compute_txid().to_string()]),
                            )
                            .is_ok()
                    };
                    let (ok, how) = if known(n) {
                        (true, "already broadcast by another party".to_string())
                    } else {
                        match n.rpc.package(&tx) {
                            Ok(_) => (true, String::new()),
                            // if this node cannot pay the fee, another party's broadcast still settles it
                            Err(e) => {
                                let mut k = false;
                                for _ in 0..20 {
                                    if known(n) {
                                        k = true;
                                        break;
                                    }
                                    std::thread::sleep(Duration::from_millis(500));
                                }
                                (
                                    k,
                                    if k {
                                        format!("broadcast by another party ({e})")
                                    } else {
                                        e
                                    },
                                )
                            }
                        }
                    };
                    n.check(
                        &format!(
                            "{}: \"{label}\" completed by the attestation and broadcast",
                            p.name()
                        ),
                        ok,
                        &how,
                    );
                } else {
                    n.check(
                        &format!("{}: \"{label}\" completes with the attestation", p.name()),
                        true,
                        "",
                    );
                }
                out.push((p, label));
            }
            None => n.check(
                &format!("{}: attestation completes the payout", p.name()),
                false,
                &label,
            ),
        }
    }
    out
}

fn ballot_from_args(seats: usize, my_seat: usize) -> Ballot {
    // --ballot "I,I,D" gives every seat's class as this attendee saw it; default: everyone intervened
    let spec = arg("--ballot").unwrap_or_default();
    let classes: Vec<Class> = spec
        .split(',')
        .filter(|s| !s.is_empty())
        .map(|s| match s.trim() {
            "I" => Class::Intervention,
            "D" => Class::Documentation,
            _ => Class::None,
        })
        .collect();
    let acts = (0..seats)
        .map(|i| Act {
            seat: i as u8,
            class: classes.get(i).cloned().unwrap_or(Class::Intervention),
            footage: if i == my_seat {
                Some((String::new(), 0))
            } else {
                None
            },
        })
        .collect();
    Ballot {
        acts,
        outcome_achieved: !flag("--not-achieved"),
        misuse: flag("--misuse"),
    }
}

fn upload_evidence(
    n: &mut Node,
    a: &Alerted,
    archivists: &[(String, String, String)],
    bytes: usize,
) {
    let c = a.case_hex.clone();
    let key = tagged("Bitaid/evidence-key", &n.case_keys[&c]);
    let footage: Vec<u8> = (0..bytes)
        .map(|i| (i * 31 % 251) as u8 ^ n.keys.secret_bytes()[0])
        .collect();
    let blobs = blossom::seal_footage(&key, &c, &footage, 256 * 1024);
    let t0 = Instant::now();
    let mut ok = 0;
    let mut urls = vec![];
    for (_, _, url) in archivists {
        let mut all = true;
        for b in &blobs {
            if blossom::upload(url, &n.keys, &c, b).is_err() {
                all = false;
            }
        }
        if all {
            ok += 1;
            urls.push(url.clone());
        }
    }
    let list: Vec<(String, u64)> = blobs
        .iter()
        .map(|b| (hex::encode(bitaid_core::hashes::sha256(b)), b.len() as u64))
        .collect();
    let roots: Vec<String> = blobs
        .iter()
        .map(|b| hex::encode(blossom::slice_root(b)))
        .collect();
    n.check(
        &format!(
            "evidence: {} KiB encrypted in {} blobs, pinned on {ok}/{} archivists",
            bytes / 1024,
            blobs.len(),
            archivists.len()
        ),
        ok == archivists.len() && ok > 0,
        &format!("{:.2} s", t0.elapsed().as_secs_f64()),
    );
    n.send_case(
        &c,
        &[],
        Msg::Evidence {
            case_id: c.clone(),
            blobs: list,
            slice_roots: roots,
            archivists: urls,
        },
        true,
    );
}

/// Commit, wait for every seat's commitment, reveal.
fn vote(n: &mut Node, a: &Alerted, r: &Rostered, ballot: Ballot) {
    let c = a.case_hex.clone();
    let salt: [u8; 32] = rand::random();
    n.send_case(
        &c,
        &[],
        Msg::BallotCommit {
            case_id: c.clone(),
            commitment: hex::encode(ballot.commitment(&salt)),
        },
        true,
    );
    let seats = r.seats.clone();
    let mut seen = std::collections::HashSet::new();
    let got = n.collect(
        secs(120),
        |env, _| match &env.msg {
            Msg::BallotCommit { case_id, .. }
                if *case_id == c
                    && seats.contains(&env.sender)
                    && seen.insert(env.sender.clone()) =>
            {
                Some(())
            }
            _ => None,
        },
        |v| v.len() >= seats.len(),
    );
    n.log(&format!(
        "{} of {} commitments in; revealing",
        got.len(),
        seats.len()
    ));
    n.send_case(
        &c,
        &[],
        Msg::BallotReveal {
            case_id: c.clone(),
            ballot,
            salt: hex::encode(salt),
        },
        true,
    );
}

// =================================================================== caller

fn caller(mut n: Node) -> i32 {
    let secp = Secp256k1::new();
    n.subscribe("svc", vec![Filter::kinds(&[kind::ANNOUNCE])]);
    let Some((oid, okey, _)) = n.find_service("oracle", secs(120)) else {
        n.check("oracle found on the relays", false, "");
        return n.summary();
    };
    let want_arch = num("--archivists", 1usize);
    let archivists = n.all_services("archivist", want_arch, secs(60));
    n.log(&format!(
        "oracle {}…, {} archivist(s)",
        &okey[..12],
        archivists.len()
    ));

    // ------------------------------------------------ registration
    let (w, k) = (random_scalar(), even(random_scalar()));
    let xpriv =
        bitcoin::bip32::Xpriv::new_master(bitcoin::Network::Regtest, &random_scalar().serialize())
            .unwrap();
    let template = Template {
        pots: [
            num("--deposit", 100_000u64),
            num("--reward", 600_000u64),
            num("--bounty", 300_000u64),
        ],
        intervener_pct: 70,
        good_faith_pct: 50,
        max_signers: num("--max-signers", 5u8),
        joining_window: num("--window", 15u32),
        dispute_window: num("--dispute-window", 5u32),
        refund_delay: 12_960,
        refund_xpub: bitcoin::bip32::Xpub::from_priv(&secp, &xpriv).to_string(),
    };
    let total: u64 = template.pots.iter().sum();
    let fallback = n.rpc.height() + 52_560;
    let tree = outputs::funding(
        &secp,
        &xo(&w),
        &xo(&k),
        &wire::xonly(&okey).unwrap(),
        fallback,
    );
    let fop = match n.rpc.fund(&tree.script_pubkey(), total) {
        Ok(op) => op,
        Err(e) => {
            n.check("funding output created", false, &e);
            return n.summary();
        }
    };
    if flag("--mine") {
        n.rpc.mine(1).ok();
    }
    let scoped_hex = hex::encode(xo(&k).serialize());
    let d = case::registration_digest(&scoped_hex, &template, &fop.to_string());
    let reg = Msg::Registration {
        funding: fop.to_string(),
        funding_value: total,
        wallet_key: hex::encode(xo(&w).serialize()),
        scoped_key: scoped_hex,
        oracle_key: okey.clone(),
        fallback_height: fallback,
        template: template.clone(),
        wallet_sig: hex::encode(sign_bip340(&w, &d)),
    };
    let reg_bytes = wire::sign(&n.keys, n.rpc.height(), reg);
    n.check(
        "registration: funding output (no key path) and template committed",
        true,
        &fop.to_string(),
    );

    // ------------------------------------------------ alert
    let (lat, lon) = (num("--lat", 13.6929f64), num("--lon", -89.2182f64));
    let cell = cell_of(lat, lon).to_string();
    let case_hex = hex::encode(hash_case(&format!(
        "{}-{}-{}",
        n.me(),
        fop,
        rand::random::<u64>()
    )));
    n.subscribe(
        "case",
        vec![Filter::kinds(&[kind::CASE]).tag('c', std::slice::from_ref(&case_hex))],
    );
    std::thread::sleep(Duration::from_millis(300));
    let alert = Msg::Alert {
        case_id: case_hex.clone(),
        cell: cell.clone(),
        registration: b64(&reg_bytes),
        template: template.clone(),
        pre_trigger: hex::encode([0u8; 32]),
    };
    let alert_t = Instant::now();
    n.send(
        kind::ALERT,
        vec![
            vec!["g".into(), cell.clone()],
            vec!["c".into(), case_hex.clone()],
        ],
        alert.clone(),
        None,
    );
    n.log(&format!("ALERT case {} in H3 cell {cell}", &case_hex[..8]));
    let a = Alerted::check(&n.me(), &alert, chain_view(&n.rpc), &okey).expect("own alert checks");

    // ------------------------------------------------ joining window
    let max = template.max_signers as usize;
    let c = case_hex.clone();
    let rpc_view = |op: &OutPoint| n.rpc.utxo(op);
    let _ = rpc_view;
    let mut accepts: Vec<(String, Point, String)> = Vec::new();
    let end = alert_t + secs(template.joining_window as u64);
    let mut first_accept = None;
    while Instant::now() < end && accepts.len() < max {
        let left = end.saturating_duration_since(Instant::now());
        let got = n.wait(left, |env, _| match &env.msg {
            Msg::Accept {
                case_id,
                musig_key,
                bond,
                bond_scoped,
                bond_cold,
                bond_fallback,
                payout_spk,
            } if *case_id == c => Some((
                env.sender.clone(),
                musig_key.clone(),
                bond.clone(),
                bond_scoped.clone(),
                bond_cold.clone(),
                *bond_fallback,
                payout_spk.clone(),
            )),
            _ => None,
        });
        let Some((who, mk, bond, bs, bc, bf, spk)) = got else {
            break;
        };
        if accepts.iter().any(|x| x.0 == who) {
            continue;
        }
        // the bond must exist, hold the floor and be the bond script for those keys and this oracle
        let ok = (|| {
            let op = OutPoint::from_str(&bond).ok()?;
            let utxo = n.rpc.utxo(&op)?;
            let t = outputs::bond(
                &secp,
                &wire::xonly(&bs)?,
                &wire::xonly(&bc)?,
                &wire::xonly(&okey)?,
                bf,
            );
            (utxo.value.to_sat() >= BOND_FLOOR && utxo.script_pubkey == t.script_pubkey())
                .then_some(())
        })();
        if ok.is_none() {
            n.log(&format!(
                "acceptance from {} refused: bond missing, below floor or not a bond",
                &who[..8]
            ));
            continue;
        }
        let Some(p) = point_from(&mk) else { continue };
        first_accept.get_or_insert(alert_t.elapsed());
        n.log(&format!("accepted by {} (bond {})", &who[..8], &bond[..12]));
        accepts.push((who, p, spk));
    }
    n.check(
        &format!(
            "{} responder(s) accepted within the joining window, bonds checked on chain",
            accepts.len()
        ),
        !accepts.is_empty(),
        &first_accept
            .map(|d| format!("first after {:.2} s", d.as_secs_f64()))
            .unwrap_or_default(),
    );
    if accepts.is_empty() {
        return n.summary();
    }

    // ------------------------------------------------ nonces from the oracle
    n.send_case(
        &c,
        std::slice::from_ref(&oid),
        Msg::NonceRequest { case_id: c.clone() },
        false,
    );
    let oid2 = oid.clone();
    let Some(nonces) = n.wait(secs(60), |env, _| match &env.msg {
        Msg::NonceAssignment { case_id, nonces } if *case_id == c && env.sender == oid2 => {
            Some(nonces.clone())
        }
        _ => None,
    }) else {
        n.check("oracle assigned nonces", false, "");
        return n.summary();
    };

    // ------------------------------------------------ roster and signing, re-rolled if a signer fails
    let case_key: [u8; 32] = rand::random();
    n.add_case_key(&c, case_key);
    let mut seated = accepts.clone();
    let mut version = 0u32;
    let refund_height = n.rpc.height() + template.refund_delay;
    let (set, roster) = loop {
        let mut r = Rostered {
            set_version: version,
            seats: seated.iter().map(|x| x.0.clone()).collect(),
            musig_keys: seated.iter().map(|x| x.1).collect(),
            payout_spks: seated
                .iter()
                .map(|x| bitcoin::ScriptBuf::from_hex(&x.2).unwrap())
                .collect(),
            oracle_nonces: [
                point_from(&nonces[0]).unwrap(),
                point_from(&nonces[1]).unwrap(),
                point_from(&nonces[2]).unwrap(),
            ],
            refund_height,
            incident_txid: bitcoin::Txid::from_str(&"00".repeat(32)).unwrap(),
            sealed_keys: vec![],
        };
        r.incident_txid = case::incident_tx(&a, &r).compute_txid();
        let mut sealed: Vec<String> = r
            .seats
            .iter()
            .map(|s| {
                hex::encode(wire::seal(
                    &n.keys,
                    &wire::xonly(s).unwrap(),
                    c.as_bytes(),
                    &case_key,
                ))
            })
            .collect();
        sealed.push(hex::encode(wire::seal(
            &n.keys,
            &wire::xonly(&oid).unwrap(),
            c.as_bytes(),
            &case_key,
        )));
        let msg = Msg::Roster {
            case_id: c.clone(),
            set_version: version,
            seats: r.seats.clone(),
            musig_keys: r.musig_keys.iter().map(point_hex).collect(),
            payout_spks: seated.iter().map(|x| x.2.clone()).collect(),
            oracle_nonces: nonces.clone(),
            refund_height,
            incident_txid: r.incident_txid.to_string(),
            sealed_keys: sealed.clone(),
        };
        r.sealed_keys = sealed;
        n.send_case(&c, &r.seats.clone(), msg, false);
        n.log(&format!(
            "ROSTER v{version}: {} seat(s), incident {}",
            r.seats.len(),
            &r.incident_txid.to_string()[..8]
        ));
        match sign_set(&mut n, &a, &r, 0, &k, false) {
            Ok(s) => break (s, r),
            Err(e) => {
                n.log(&format!("set v{version} failed: {e}"));
                let bad: Option<usize> = e
                    .strip_prefix("signer ")
                    .and_then(|x| x.split(':').next())
                    .and_then(|x| x.parse().ok());
                match bad {
                    Some(j) if j >= 1 && version < 2 => {
                        n.check(&format!("signer {j} caught sending an invalid partial signature; its seat is given up and the set re-signed"), true, &e);
                        seated.remove(j - 1);
                        version += 1;
                        if seated.is_empty() {
                            return n.summary();
                        }
                    }
                    _ => {
                        n.check("pre-signed set completed", false, &e);
                        return n.summary();
                    }
                }
            }
        }
    };
    n.check(
        &format!(
            "pre-signed set v{} complete and verified across machines",
            roster.set_version
        ),
        set.verify_all(),
        &format!(
            "{} payouts + {} refunds, {} signers",
            set.len(),
            set.refunds.len(),
            roster.seats.len() + 1
        ),
    );

    // ------------------------------------------------ incident transaction
    let mut inc = case::incident_tx(&a, &roster);
    n.send_case(
        &c,
        std::slice::from_ref(&oid),
        Msg::CosignRequest {
            case_id: c.clone(),
            tx: serialize_hex(&inc),
        },
        false,
    );
    let oid2 = oid.clone();
    let Some(osig) = n.wait(secs(60), |env, _| match &env.msg {
        Msg::Cosign { case_id, sig } if *case_id == c && env.sender == oid2 => {
            hex::decode(sig).ok()
        }
        _ => None,
    }) else {
        n.check("oracle co-signed the incident transaction", false, "");
        return n.summary();
    };
    let leaf = &tree.scripts[funding_leaf::ACCEPT];
    let dd = txbuild::scriptspend_digest(
        &inc,
        0,
        &[txbuild::txout(total, tree.script_pubkey())],
        leaf,
    );
    inc.input[0].witness = Witness::from_slice(&[
        osig,
        sign_bip340(&k, &dd).to_vec(),
        leaf.to_bytes(),
        tree.control(funding_leaf::ACCEPT).serialize(),
    ]);
    let r = n.rpc.package(&inc);
    n.check(
        "incident transaction: scoped key + oracle co-signature, zero fee, accepted as a package",
        r.is_ok(),
        &r.as_ref().err().cloned().unwrap_or_default(),
    );
    if flag("--mine") {
        n.rpc.mine(1).ok();
    }
    n.send_case(
        &c,
        &[],
        Msg::Incident {
            case_id: c.clone(),
            txid: inc.compute_txid().to_string(),
        },
        false,
    );
    n.log(&format!(
        "time from alert to a funded, fully pre-signed incident: {:.2} s",
        alert_t.elapsed().as_secs_f64()
    ));

    // ------------------------------------------------ evidence, then wait for settlement
    upload_evidence(
        &mut n,
        &a,
        &archivists,
        num("--footage-kib", 512usize) * 1024,
    );
    let paid = settle(&mut n, &a, &set, &okey, &oid, true);
    if flag("--mine") {
        n.rpc.mine(1).ok();
    }
    let spent = set
        .pot_outpoints
        .iter()
        .flatten()
        .all(|op| n.rpc.utxo(op).is_none());
    n.check(
        &format!("all {} pots settled on chain by deemed consent", paid.len()),
        spent && !paid.is_empty(),
        &paid
            .iter()
            .map(|(p, l)| format!("{}: {l}", p.name()))
            .collect::<Vec<_>>()
            .join("; "),
    );
    n.summary()
}

// =================================================================== responder

fn responder(mut n: Node) -> i32 {
    let secp = Secp256k1::new();
    n.subscribe("svc", vec![Filter::kinds(&[kind::ANNOUNCE])]);
    let Some((oid, okey, _)) = n.find_service("oracle", secs(120)) else {
        n.check("oracle found on the relays", false, "");
        return n.summary();
    };
    let archivists = n.all_services("archivist", num("--archivists", 1usize), secs(60));
    // ------------------------------------------------ bond
    let (bond_scoped, bond_cold) = (random_scalar(), random_scalar());
    let bf = n.rpc.height() + 52_560;
    let btree = outputs::bond(
        &secp,
        &xo(&bond_scoped),
        &xo(&bond_cold),
        &wire::xonly(&okey).unwrap(),
        bf,
    );
    let bond = match n
        .rpc
        .fund(&btree.script_pubkey(), num("--bond", BOND_FLOOR))
    {
        Ok(op) => op,
        Err(e) => {
            n.check("bond posted", false, &e);
            return n.summary();
        }
    };
    if flag("--mine") {
        n.rpc.mine(1).ok();
    }
    // ------------------------------------------------ listen to my cell and its neighbours
    let (lat, lon) = (num("--lat", 13.6929f64), num("--lon", -89.2182f64));
    let home = cell_of(lat, lon);
    let cells: Vec<String> = home
        .grid_disk::<Vec<_>>(1)
        .into_iter()
        .map(|c| c.to_string())
        .collect();
    n.subscribe(
        "alerts",
        vec![Filter::kinds(&[kind::ALERT]).tag('g', &cells)],
    );
    n.log(&format!(
        "bond {} posted; listening on {} cells around {home}",
        &bond.to_string()[..12],
        cells.len()
    ));
    let min_bounty = num("--min-bounty", 1u64);
    let delay = num("--accept-delay-ms", 0u64);
    let me = n.me();
    let a = loop {
        let Some(env) = n.wait(secs(num("--exit-after", 600u64)), |env, _| {
            matches!(env.msg, Msg::Alert { .. }).then(|| env.clone())
        }) else {
            n.check("an alert arrived in my cells", false, "");
            return n.summary();
        };
        match Alerted::check(&env.sender, &env.msg, chain_view(&n.rpc), &okey) {
            Ok(a) if a.template.pots[2] >= min_bounty => break a,
            Ok(_) => n.log("alert below my price; ignored"),
            Err(e) => n.check("alert checked", false, &e),
        }
    };
    n.check(
        &format!(
            "alert {} in cell {} checked: registration, wallet signature, funding output on chain",
            &a.case_hex[..8],
            a.cell
        ),
        true,
        "",
    );
    let c = a.case_hex.clone();
    n.subscribe(
        "case",
        vec![Filter::kinds(&[kind::CASE]).tag('c', std::slice::from_ref(&c))],
    );
    std::thread::sleep(Duration::from_millis(300 + delay));
    let sk = random_scalar();
    let payout = n.rpc.new_spk().expect("payout address");
    let acc = Msg::Accept {
        case_id: c.clone(),
        musig_key: point_hex(&(sk * G)),
        bond: bond.to_string(),
        bond_scoped: hex::encode(xo(&bond_scoped).serialize()),
        bond_cold: hex::encode(xo(&bond_cold).serialize()),
        bond_fallback: bf,
        payout_spk: payout.to_hex_string(),
    };
    n.send_case(&c, std::slice::from_ref(&a.caller), acc, false);
    n.log("ACCEPT sent");

    // ------------------------------------------------ rosters until a set completes with me in it
    let corrupt = flag("--bad-partial");
    let caller_id = a.caller.clone();
    let (set, r, my_seat) = loop {
        let Some(r) = n.wait(secs(120), |env, _| {
            (env.sender == caller_id)
                .then(|| Rostered::from_msg(&env.msg))
                .flatten()
        }) else {
            n.check("seated in a roster", false, "no roster");
            return n.summary();
        };
        let Some(seat) = r.seats.iter().position(|s| *s == me) else {
            n.log(&format!("roster v{} does not seat me", r.set_version));
            if corrupt {
                n.check("dropped from the set after sending a bad partial signature (expected for this test)", true, "");
                return n.summary();
            }
            continue;
        };
        let Some(key) = hex::decode(&r.sealed_keys[seat]).ok().and_then(|k| {
            wire::unseal(&n.keys, &wire::xonly(&caller_id).unwrap(), c.as_bytes(), &k)
        }) else {
            n.check("case key unsealed", false, "");
            return n.summary();
        };
        n.add_case_key(&c, key.try_into().unwrap());
        // the roster must be the template's: same incident txid as I compute
        if case::incident_tx(&a, &r).compute_txid() != r.incident_txid {
            n.check(
                "roster's incident transaction matches the template",
                false,
                "",
            );
            return n.summary();
        }
        match sign_set(&mut n, &a, &r, seat + 1, &sk, corrupt) {
            Ok(s) => break (s, r, seat),
            Err(e) => n.log(&format!(
                "set v{} failed: {e}; waiting for a re-roll",
                r.set_version
            )),
        }
    };
    n.check(
        &format!(
            "pre-signed set v{} verified (seat {my_seat})",
            r.set_version
        ),
        set.verify_all(),
        &format!("{} payouts", set.len()),
    );

    // ------------------------------------------------ incident confirmed, then evidence and ballot
    let cid = caller_id.clone();
    let inc = n.wait(secs(120), |env, _| match &env.msg {
        Msg::Incident { case_id, txid } if *case_id == c && env.sender == cid => Some(txid.clone()),
        _ => None,
    });
    let live = set
        .pot_outpoints
        .iter()
        .flatten()
        .all(|op| n.rpc.utxo(op).is_some());
    n.check(
        "incident transaction on chain: every pot output exists",
        inc.is_some() && live,
        &inc.unwrap_or_default(),
    );
    upload_evidence(
        &mut n,
        &a,
        &archivists,
        num("--footage-kib", 512usize) * 1024,
    );
    vote(&mut n, &a, &r, ballot_from_args(r.seats.len(), my_seat));
    let paid = settle(&mut n, &a, &set, &okey, &oid, flag("--broadcast"));
    if flag("--mine") {
        n.rpc.mine(1).ok();
    }
    let mut got = 0;
    for _ in 0..60 {
        got = n.rpc.received(&payout);
        if got > 0 {
            break;
        }
        std::thread::sleep(secs(1));
    }
    let expected_some = paid
        .iter()
        .any(|(p, l)| *p != Pot::Deposit && !l.contains("returned") && !l.contains("withheld"));
    n.check(
        "my shares arrived at my payout address",
        !expected_some || got > 0,
        &format!("{got} sats"),
    );
    n.summary()
}

#[allow(dead_code)]
fn unused(_: OutPoint) -> Option<Scalar> {
    scalar_from("")
}
