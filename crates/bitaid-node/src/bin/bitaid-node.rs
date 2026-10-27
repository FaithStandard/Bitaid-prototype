//! `bitaid-node --role caller|responder|oracle|archivist --relay ws://… [options]`
//!
//! One incident end to end over Nostr relays, with Bitcoin Core (regtest) as the chain:
//! registration → alert in an H3 cell → acceptances → roster → the pre-signed set signed across
//! machines → oracle co-signature → incident transaction → evidence on archivists → blind ballots →
//! deemed consent → the oracle's attestations → payouts confirmed.
use bitaid_core::endings::Pot;
use bitaid_core::hashes::{case_id as hash_case, tagged};
use bitaid_core::oracle::{even, random_scalar, sign_bip340};
use bitaid_core::outputs::{self, funding_leaf};
use bitaid_core::txbuild;
use bitaid_node::arb;
use bitaid_node::blossom;
use bitaid_node::case::{self, Alerted, Rostered};
use bitaid_node::chain::Rpc;
use bitaid_node::node::{point_from, point_hex, scalar_from, xo, Node};
use bitaid_node::nostr::{kind, Filter};
use bitaid_node::pool::{self, PoolView};
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
    let peers = args_all("--peer");
    let listen = arg("--listen-gossip");
    let name = arg("--name").unwrap_or(role.clone());
    let secret = arg("--secret").and_then(|s| h32(&s));
    // the Specification's transport: gossip between Cores (over Tor when --socks is given);
    // --relay keeps the Nostr-relay stand-in of the earlier tests
    let node = if !peers.is_empty() || listen.is_some() {
        let socks = arg("--socks").or_else(|| std::env::var("BITAID_SOCKS").ok());
        Node::gossip(
            &name,
            listen.as_deref(),
            &peers,
            socks.as_deref(),
            Rpc::from_env(),
            secret,
            secs(num("--link-wait", 180u64)),
        )
    } else {
        assert!(
            !relays.is_empty(),
            "give --peer HOST:PORT (gossip) or --relay ws://HOST:PORT (relay stand-in)"
        );
        Node::new(&name, &relays, Rpc::from_env(), secret)
    };
    node.log(&format!(
        "{} on {} link(s), identity {}",
        role,
        node.client.relay_count(),
        &node.me()[..16]
    ));
    let code = match role.as_str() {
        // a Core that only carries gossip: the hub other Cores and apps dial
        "core" => {
            let mut n = node;
            n.subscribe("all", vec![bitaid_node::nostr::Filter::default()]);
            loop {
                let _ = n.wait(secs(60), |_, _| Some(()));
            }
        }
        "pool-member" | "oracle" => pool_member(node),
        "archivist" => archivist(node),
        "arbitrator" => arbitrator(node),
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

/// One member of the oracle pool: joins key generation and the nonce batch, then serves cases.
fn pool_member(mut n: Node) -> i32 {
    let cfg = pool::MemberCfg {
        name: arg("--pool").unwrap_or("bitaid".into()),
        id: num("--id", 1u16),
        n: num("--n", 4u16),
        t: num("--t", 3u16),
        batch: num("--batch", 60usize),
        stall: flag("--stall"),
        liar: flag("--liar"),
        wait: secs(num("--setup-wait", 900u64)),
    };
    let me = cfg.id;
    let mut m = match pool::setup(&mut n, cfg) {
        Ok(m) => m,
        Err(e) => {
            n.log(&format!("pool setup failed: {e}"));
            return 1;
        }
    };
    let okey = m.view.key_hex();
    n.subscribe("all", vec![Filter::kinds(&[kind::ALERT, kind::CASE])]);
    let mut alerts: HashMap<String, Alerted> = HashMap::new();
    let mut rosters: HashMap<String, Rostered> = HashMap::new();
    let mut assigned: HashMap<String, Vec<u32>> = HashMap::new();
    let mut taken: HashMap<u32, String> = HashMap::new();
    let mut digests: HashMap<(String, u32), [u8; 32]> = HashMap::new();
    let mut sessions: HashMap<(String, u32), frost_secp256k1_tr::round1::SigningNonces> =
        HashMap::new();
    let mut commits: HashMap<String, BTreeMap<String, String>> = HashMap::new();
    let mut reveals: HashMap<String, BTreeMap<String, Ballot>> = HashMap::new();
    let mut ready_at: HashMap<String, Instant> = HashMap::new();
    let mut done: std::collections::HashSet<String> = Default::default();
    // per final case, the forfeitures and distribution inputs its replay calls for (computed once)
    #[allow(clippy::type_complexity)]
    let mut due_arb: HashMap<String, Vec<(bitcoin::Txid, usize, [u8; 32], String)>> =
        HashMap::new();
    // arbitration, per case: the current tier, who escalated it and at what height
    let mut esc: HashMap<String, (u32, String, u32)> = HashMap::new();
    let mut offers: HashMap<(String, u32), HashMap<String, (bool, String)>> = HashMap::new(); // sender -> (bond ok, payout)
    let mut panels: HashMap<(String, u32), Vec<String>> = HashMap::new();
    let mut fees_ok: std::collections::HashSet<(String, u32)> = Default::default();
    let mut fee_at: HashMap<(String, u32, String), Instant> = HashMap::new();
    let mut vcommits: HashMap<(String, u32), HashMap<String, String>> = HashMap::new();
    let mut vreveals: HashMap<(String, u32), Vec<(String, Ballot)>> = HashMap::new();
    let mut verdicts: HashMap<String, Ballot> = HashMap::new();
    #[allow(clippy::type_complexity)]
    let mut lapse: HashMap<String, (Instant, Option<(u32, String, u32)>)> = HashMap::new();
    let idle = num("--exit-after", 900u64);
    let mut last = Instant::now();
    loop {
        if last.elapsed() > secs(idle) {
            return 0;
        }
        let lapsed: Vec<String> = lapse
            .iter()
            .filter(|(_, (t, _))| Instant::now() >= *t)
            .map(|(c, _)| c.clone())
            .collect();
        for c in lapsed {
            let (_, prev) = lapse.remove(&c).unwrap();
            match prev {
                Some(p) => esc.insert(c.clone(), p),
                None => esc.remove(&c),
            };
            if verdicts.contains_key(&c) {
                n.log(&format!(
                    "case {}: the escalation was never seated and lapses; the last verdict stands",
                    &c[..8]
                ));
                ready_at.insert(c.clone(), Instant::now());
            } else {
                n.log(&format!("case {}: the escalation was never seated and lapses; the deadlock stands (refund path)", &c[..8]));
            }
        }
        // deemed consent: every seat revealed and the dispute window has passed; each member reads
        // the outcome from the ballots itself and releases its own share
        let due: Vec<String> = ready_at
            .iter()
            .filter(|(_, t)| Instant::now() >= **t)
            .map(|(c, _)| c.clone())
            .collect();
        for c in due {
            ready_at.remove(&c);
            let (a, r) = (&alerts[&c], &rosters[&c]);
            // an arbitrated case settles on its last tier's verdict; otherwise on the ballots
            let ballots: Vec<Ballot> = match verdicts.get(&c) {
                Some(v) => vec![v.clone()],
                None => reveals[&c].values().cloned().collect(),
            };
            match decide(r.seats.len(), a.template.pots, &a.template, &ballots) {
                Decision::Settled(ends) => {
                    for e in ends {
                        let msg = e.message(&a.case_id, r.set_version);
                        let index = assigned[&c][e.pot.index()] as usize;
                        match m.attest(index, &msg) {
                            Ok(share) => {
                                n.log(&format!(
                                    "attestation share for {} \"{}\"{}",
                                    e.pot.name(),
                                    e.label,
                                    if m.cfg.liar {
                                        " (lying: a different outcome)"
                                    } else {
                                        ""
                                    }
                                ));
                                n.send_case(
                                    &c,
                                    &[],
                                    Msg::AttestShare {
                                        case_id: c.clone(),
                                        pot: e.pot.index() as u8,
                                        share,
                                    },
                                    false,
                                );
                            }
                            Err(err) => {
                                n.log(&format!("refused to attest {}: {err}", e.pot.name()))
                            }
                        }
                    }
                    // an arbitrated case: replay it now, so co-signing its penalties later is immediate
                    if verdicts.contains_key(&c) {
                        let list = arb_due(&n, a, r);
                        n.log(&format!("case {}: the final ruling calls for {} co-signature(s) on forfeitures and the seizure distribution", &c[..8], list.len()));
                        due_arb.insert(c.clone(), list);
                    }
                    done.insert(c);
                }
                Decision::Escalate(why) => {
                    n.log(&format!("case {}: escalation needed: {why}", &c[..8]))
                }
            }
        }
        let Some(env) = n.wait(Duration::from_millis(500), |env, _| Some(env.clone())) else {
            continue;
        };
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
            Msg::NonceRequest { case_id, indices } => {
                let Some(a) = alerts.get(case_id) else {
                    continue;
                };
                if a.caller != s || indices.len() != 3 || assigned.contains_key(case_id) {
                    continue;
                }
                // reserve only indices this member has not given to another case
                let free = indices.iter().all(|j| {
                    (*j as usize) < m.batch.r.len()
                        && taken.get(j).map(|c| c == case_id).unwrap_or(true)
                });
                if !free {
                    n.log(&format!(
                        "nonce indices {indices:?} already reserved; refused"
                    ));
                    continue;
                }
                for j in indices {
                    taken.insert(*j, case_id.clone());
                }
                assigned.insert(case_id.clone(), indices.clone());
                let nonces = indices
                    .iter()
                    .map(|j| point_hex(&m.batch.r[*j as usize]))
                    .collect();
                n.send_case(
                    case_id,
                    std::slice::from_ref(&s),
                    Msg::NonceAssignment {
                        case_id: case_id.clone(),
                        member: me,
                        indices: indices.clone(),
                        nonces,
                    },
                    false,
                );
                n.log(&format!(
                    "nonces {indices:?} reserved for {}",
                    &case_id[..8]
                ));
            }
            Msg::Roster { case_id, .. } => {
                let (Some(a), Some(r)) = (alerts.get(case_id), Rostered::from_msg(&env.msg)) else {
                    continue;
                };
                if a.caller != s {
                    continue;
                }
                // the roster must use the nonces this member reserved for the case
                let mine: Option<Vec<String>> = assigned.get(case_id).map(|v| {
                    v.iter()
                        .map(|j| point_hex(&m.batch.r[*j as usize]))
                        .collect()
                });
                let theirs: Vec<String> = r.oracle_nonces.iter().map(point_hex).collect();
                if mine.as_ref() != Some(&theirs) {
                    n.log("roster ignored: oracle nonces are not the ones reserved for this case");
                    continue;
                }
                let pos = r.seats.len() + m.view.members.iter().position(|x| *x == me).unwrap();
                if let Some(k) = r.sealed_keys.get(pos).and_then(|k| hex::decode(k).ok()) {
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
            Msg::CosignRequest {
                case_id,
                session,
                tx,
                input,
            } => {
                let (Some(a), Some(r)) = (alerts.get(case_id), rosters.get(case_id)) else {
                    continue;
                };
                let Ok(t) = deserialize_hex::<Transaction>(tx) else {
                    continue;
                };
                let d = if a.caller == s
                    && *input == 0
                    && t.compute_txid() == case::incident_tx(a, r).compute_txid()
                    && t.compute_txid() == r.incident_txid
                {
                    // the template's incident transaction for this roster
                    let tree = a.funding_tree();
                    txbuild::scriptspend_digest(
                        &t,
                        0,
                        &[txbuild::txout(a.funding_value, tree.script_pubkey())],
                        &tree.scripts[funding_leaf::ACCEPT],
                    )
                } else if let Some((d, what)) =
                    seat_forfeit_due(&n, a, r, &t, *input, &vcommits, &fee_at)
                {
                    // a seat that missed its commit deadline: its seat forfeiture refunds the fee
                    n.log(&format!("co-signing {what} for {}", &case_id[..8]));
                    d
                } else if done.contains(case_id) {
                    // after the case is final: a forfeiture or the seizure distribution, only if this
                    // member's own replay of the log calls for exactly that transaction
                    if !due_arb.contains_key(case_id) {
                        let list = arb_due(&n, a, r);
                        due_arb.insert(case_id.clone(), list);
                    }
                    let id = t.compute_txid();
                    match due_arb[case_id]
                        .iter()
                        .find(|x| x.0 == id && x.1 == *input as usize)
                        .cloned()
                    {
                        Some((_, _, d, what)) => {
                            n.log(&format!("co-signing {what} for {}", &case_id[..8]));
                            d
                        }
                        None => {
                            n.log("co-signature refused: not a forfeiture or distribution the case calls for");
                            continue;
                        }
                    }
                } else {
                    n.log("co-signature refused: not the template's incident transaction");
                    continue;
                };
                digests.insert((case_id.clone(), *session), d);
                let (nonces, commitment) = m.commit();
                sessions.insert((case_id.clone(), *session), nonces);
                n.send_case(
                    case_id,
                    std::slice::from_ref(&s),
                    Msg::PoolCommit {
                        case_id: case_id.clone(),
                        session: *session,
                        member: me,
                        commitment,
                    },
                    false,
                );
            }
            Msg::PoolPackage {
                case_id,
                session,
                package,
            } => {
                let (Some(_), Some(d)) = (
                    alerts.get(case_id),
                    digests.get(&(case_id.clone(), *session)),
                ) else {
                    continue;
                };
                let Some(nonces) = sessions.remove(&(case_id.clone(), *session)) else {
                    continue;
                };
                if m.cfg.stall {
                    n.log(&format!("stalling on co-signing session {session} (test)"));
                    continue;
                }
                match m.sign(package, &nonces, d) {
                    Ok(share) => {
                        n.send_case(
                            case_id,
                            std::slice::from_ref(&s),
                            Msg::PoolSigShare {
                                case_id: case_id.clone(),
                                session: *session,
                                member: me,
                                share,
                            },
                            false,
                        );
                        n.log(&format!(
                            "co-signed for {} (session {session})",
                            &case_id[..8]
                        ));
                    }
                    Err(why) => n.log(&format!("session {session}: {why}")),
                }
            }
            Msg::Escalate { case_id, tier, .. } => {
                let (Some(a), Some(r)) = (alerts.get(case_id), rosters.get(case_id)) else {
                    continue;
                };
                let cur = esc.get(case_id).map(|x| x.0).unwrap_or(0);
                // only the next tier, by a bonded party to the case or by a dissenting arbitrator of the
                // tier below buying the re-roll itself (§10.4), as this member's replay of the log finds
                let party = a.caller == s || r.seats.contains(&s);
                let challenger = !party
                    && arb::Replay::build(&n.history, a, r, &n.rpc)
                        .and_then(|rp| rp.tiers.get(tier).map(|t| t.escalator == s && t.challenger))
                        .unwrap_or(false);
                if *tier != cur + 1 || !(party || challenger) || done.contains(case_id) {
                    continue;
                }
                if challenger {
                    n.log(&format!(
                        "case {}: a dissenter of the tier below opens tier {tier}",
                        &case_id[..8]
                    ));
                }
                // an escalation whose panel is never seated lapses, and the verdict below stands
                lapse.insert(
                    case_id.clone(),
                    (
                        Instant::now() + secs(num("--seat-wait", 300u64)),
                        esc.get(case_id).cloned(),
                    ),
                );
                esc.insert(case_id.clone(), (*tier, s.clone(), n.rpc.height()));
                ready_at.remove(case_id);
                n.log(&format!(
                    "case {} escalated to tier {tier} by {}",
                    &case_id[..8],
                    &s[..8]
                ));
            }
            Msg::SeatOffer {
                case_id,
                tier,
                bond,
                bond_scoped,
                bond_cold,
                bond_fallback,
                bond_value,
                payout_spk,
            } => {
                let Some(a) = alerts.get(case_id) else {
                    continue;
                };
                let value: u64 = a.template.pots.iter().sum();
                let secp = Secp256k1::verification_only();
                let ok = (|| {
                    let op = OutPoint::from_str(bond).ok()?;
                    let u = n.rpc.utxo(&op)?;
                    let t = outputs::bond(
                        &secp,
                        &wire::xonly(bond_scoped)?,
                        &wire::xonly(bond_cold)?,
                        &wire::xonly(&okey)?,
                        *bond_fallback,
                    );
                    (u.script_pubkey == t.script_pubkey()
                        && u.value.to_sat() == *bond_value
                        && u.value.to_sat() >= ARB_BOND_FLOOR.max(2 * value))
                    .then_some(())
                })()
                .is_some();
                offers
                    .entry((case_id.clone(), *tier))
                    .or_default()
                    .insert(s.clone(), (ok, payout_spk.clone()));
            }
            Msg::Seated {
                case_id,
                tier,
                height,
                block_hash,
                offers: listed,
                seats,
                ..
            } => {
                let Some((t, by, h0)) = esc.get(case_id).cloned() else {
                    continue;
                };
                if *tier != t || by != s {
                    continue;
                }
                let seen = offers
                    .get(&(case_id.clone(), *tier))
                    .cloned()
                    .unwrap_or_default();
                let size = bitaid_node::arb::panel_size(*tier);
                // the draw must be reproducible: a block mined after escalation, offers this member
                // saw with valid bonds, and the seats the block's hash picks among them
                let block_ok = *height > h0
                    && n.rpc.block_hash(*height).as_deref() == Some(block_hash.as_str());
                let offers_ok = listed
                    .iter()
                    .all(|o| seen.get(o).map(|x| x.0).unwrap_or(false));
                let draw_ok =
                    bitaid_node::arb::draw(block_hash, case_id, *tier, listed, size) == *seats;
                if block_ok && offers_ok && draw_ok {
                    panels.insert((case_id.clone(), *tier), seats.clone());
                    lapse.remove(case_id);
                    n.log(&format!("tier {tier} panel of {} checked: block {height}, draw reproduced, bonds above twice the case value", seats.len()));
                } else {
                    n.log(&format!("tier {tier} panel rejected: block {block_ok}, offers {offers_ok}, draw {draw_ok}"));
                }
            }
            Msg::Reseated {
                case_id,
                tier,
                replaced,
                seat,
                ..
            } => {
                let (Some(a), Some(r)) = (alerts.get(case_id), rosters.get(case_id)) else {
                    continue;
                };
                // this member's replay checks the draw from the offers left and that the replaced
                // seat never committed
                let ok = arb::Replay::build(&n.history, a, r, &n.rpc)
                    .and_then(|rp| {
                        rp.tiers
                            .get(tier)
                            .map(|t| t.forfeited.contains(replaced) && t.seats.contains(seat))
                    })
                    .unwrap_or(false);
                let key = (case_id.clone(), *tier);
                match (ok, panels.get_mut(&key)) {
                    (true, Some(list)) => {
                        if let Some(p) = list.iter().position(|x| x == replaced) {
                            list[p] = seat.clone();
                        }
                        fees_ok.remove(&key);
                        n.log(&format!(
                            "tier {tier}: {} replaced by {} (seat forfeit; replacement drawn)",
                            &replaced[..8],
                            &seat[..8]
                        ));
                    }
                    _ => n.log("replacement seat rejected"),
                }
            }
            Msg::FeePaid {
                case_id,
                tier,
                txid,
            } => {
                let key = (case_id.clone(), *tier);
                let (Some(seats), Some(a)) = (panels.get(&key), alerts.get(case_id)) else {
                    continue;
                };
                let fee = bitaid_node::arb::seat_fee(a.template.arb_fee, *tier);
                let seen = offers.get(&key).cloned().unwrap_or_default();
                // fees may be paid in several transactions (a replacement seat is paid on its own)
                for sid in seats.clone() {
                    let ok = seen
                        .get(&sid)
                        .and_then(|x| bitcoin::ScriptBuf::from_hex(&x.1).ok())
                        .map(|spk| n.rpc.paid_to(txid, &spk) >= fee)
                        .unwrap_or(false);
                    if ok {
                        // the seat's commit deadline runs from when this member saw it paid
                        fee_at
                            .entry((case_id.clone(), *tier, sid))
                            .or_insert(Instant::now());
                    }
                }
                if seats
                    .iter()
                    .all(|sid| fee_at.contains_key(&(case_id.clone(), *tier, sid.clone())))
                {
                    fees_ok.insert(key);
                }
            }
            Msg::VerdictCommit {
                case_id,
                tier,
                commitment,
            } => {
                let key = (case_id.clone(), *tier);
                if panels.get(&key).map(|p| p.contains(&s)).unwrap_or(false) {
                    vcommits
                        .entry(key)
                        .or_default()
                        .insert(s.clone(), commitment.clone());
                }
            }
            Msg::VerdictReveal {
                case_id,
                tier,
                verdict,
                salt,
            } => {
                let key = (case_id.clone(), *tier);
                let ok = vcommits
                    .get(&key)
                    .and_then(|m| m.get(&s))
                    .map(|c| *c == hex::encode(verdict.commitment(&h32(salt).unwrap_or_default())))
                    .unwrap_or(false);
                if ok {
                    let l = vreveals.entry(key).or_default();
                    if !l.iter().any(|x| x.0 == s) {
                        l.push((s.clone(), verdict.clone()));
                    }
                }
            }
            Msg::TierCommitted {
                case_id,
                tier,
                txid,
            } => {
                let key = (case_id.clone(), *tier);
                let (Some(seats), Some(rv)) =
                    (panels.get(&key).cloned(), vreveals.get(&key).cloned())
                else {
                    continue;
                };
                if rv.len() < seats.len()
                    || !fees_ok.contains(&key)
                    || esc.get(case_id).map(|x| x.0) != Some(*tier)
                {
                    n.log(&format!(
                        "tier {tier}: not attestable yet (reveals {}/{}, fees {})",
                        rv.len(),
                        seats.len(),
                        fees_ok.contains(&key)
                    ));
                    continue;
                }
                let cm = bitaid_node::arb::tier_commitment(case_id, *tier, &seats, &rv);
                if !n.rpc.has_op_return(txid, &cm) {
                    n.log("tier commitment not on chain; not attesting");
                    continue;
                }
                let votes: Vec<Ballot> = rv.iter().map(|x| x.1.clone()).collect();
                match bitaid_node::arb::supermajority(seats.len(), &votes) {
                    Some(v) => {
                        let k = bitaid_node::arb::verdict_key(&v);
                        let dissenters: Vec<&String> = rv
                            .iter()
                            .filter(|x| bitaid_node::arb::verdict_key(&x.1) != k)
                            .map(|x| &x.0)
                            .collect();
                        for d in &dissenters {
                            n.log(&format!("tier {tier}: dissenter {} owes {:.1}× the fee (provisional until the final ruling)", &d[..8], bitaid_node::arb::penalty_factor(seats.len(), dissenters.len())));
                        }
                        verdicts.insert(case_id.clone(), v.clone());
                        let w = alerts[case_id].template.dispute_window as u64;
                        n.log(&format!("tier {tier} verdict {} committed on chain; final in {w} s unless appealed", verdict_classes(&v)));
                        ready_at.insert(case_id.clone(), Instant::now() + secs(w));
                    }
                    // a hung tier decides nothing: the last verdict stands and the window to re-roll
                    // it reopens; a hung first tier leaves the attending deadlock, which only a re-roll
                    // or the refund path closes
                    None => match verdicts.get(case_id) {
                        Some(prev) => {
                            let w = alerts[case_id].template.dispute_window as u64;
                            n.log(&format!("tier {tier}: no two-thirds verdict; the tier {} verdict {} stands, final in {w} s unless re-rolled", tier - 1, verdict_classes(prev)));
                            ready_at.insert(case_id.clone(), Instant::now() + secs(w));
                        }
                        None => n.log(&format!("tier {tier}: no two-thirds verdict; the deadlock stands until a party re-rolls it, else the refund path")),
                    },
                }
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
    let dir = arg("--dir")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            // the system temporary folder (TMPDIR), which on Android/Termux is not /tmp
            std::env::temp_dir().join(format!("bitaid-archive-{}", &n.me()[..8]))
        });
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
    // the pool's key, to check alerts: the archivists co-sign a case's seizure output with the pool
    n.subscribe("svc", vec![Filter::kinds(&[kind::ANNOUNCE]).recent(3600)]);
    let view = pool::discover(
        &mut n,
        &arg("--pool").unwrap_or("bitaid".into()),
        secs(num("--setup-wait", 3600u64)),
    );
    let okey = view.as_ref().map(|v| v.key_hex()).unwrap_or_default();
    let mut alerts: HashMap<String, Alerted> = HashMap::new();
    let mut rosters: HashMap<String, Rostered> = HashMap::new();
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
                if let Ok(a) = Alerted::check(&env.sender, &env.msg, chain_view(&n.rpc), &okey) {
                    alerts.insert(a.case_hex.clone(), a);
                }
            }
            Msg::Roster {
                case_id,
                seats,
                archivists,
                sealed_keys,
                ..
            } => {
                for s in seats {
                    srv.policy.allow(case_id, s);
                }
                n.log(&format!(
                    "case {}: {} seated responders may upload",
                    &case_id[..8],
                    seats.len()
                ));
                if alerts
                    .get(case_id)
                    .map(|a| a.caller == env.sender)
                    .unwrap_or(false)
                {
                    if let Some(i) = archivists.iter().position(|x| *x == me) {
                        let pos = sealed_keys.len() - archivists.len() + i;
                        if let Some(k) = hex::decode(&sealed_keys[pos]).ok().and_then(|k| {
                            wire::unseal(
                                &n.keys,
                                &wire::xonly(&env.sender).unwrap(),
                                case_id.as_bytes(),
                                &k,
                            )
                        }) {
                            n.add_case_key(case_id, k.try_into().unwrap());
                        }
                    }
                    if let Some(r) = Rostered::from_msg(&env.msg) {
                        rosters.insert(case_id.clone(), r);
                    }
                }
            }
            // §12: sign the seizure output's distribution only as this archivist's own replay computes it,
            // and only once the pool has attested the case's final outcome
            Msg::SeizureRequest { case_id, tx } => {
                let (Some(a), Some(r), Some(v)) =
                    (alerts.get(case_id), rosters.get(case_id), view.as_ref())
                else {
                    continue;
                };
                let attested: std::collections::HashSet<&String> = n
                    .history
                    .iter()
                    .filter(
                        |e| matches!(&e.msg, Msg::AttestShare { case_id: c, .. } if c == case_id),
                    )
                    .map(|e| &e.sender)
                    .collect();
                if attested.len() < v.t {
                    n.log("distribution not signed: the case's outcome is not attested yet");
                    continue;
                }
                let Ok(t) = deserialize_hex::<Transaction>(tx) else {
                    continue;
                };
                let Some(rp) = arb::Replay::build(&n.history, a, r, &n.rpc) else {
                    continue;
                };
                let pens = rp.penalties();
                let Some((dist, prev)) = rp.distribution(&pens) else {
                    n.log("distribution not signed: the case calls for none");
                    continue;
                };
                if dist.compute_txid() != t.compute_txid() {
                    n.log("distribution not signed: not the one the case's log calls for");
                    continue;
                }
                let secp = Secp256k1::new();
                let sigs: Vec<String> = (0..dist.input.len())
                    .filter_map(|i| rp.distribution_digest(&dist, &prev, i))
                    .map(|d| {
                        hex::encode(
                            secp.sign_schnorr(
                                &bitcoin::secp256k1::Message::from_digest(d),
                                &n.keys,
                            )
                            .serialize(),
                        )
                    })
                    .collect();
                n.log(&format!(
                    "signed the seizure distribution of {} ({} inputs, {} sats from {} forfeitures)",
                    &case_id[..8],
                    sigs.len(),
                    pens.iter().map(|p| p.amount).sum::<u64>(),
                    pens.len()
                ));
                n.send_case(
                    case_id,
                    std::slice::from_ref(&env.sender),
                    Msg::SeizureSig {
                        case_id: case_id.clone(),
                        txid: dist.compute_txid().to_string(),
                        sigs,
                    },
                    false,
                );
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
    view: &PoolView,
    broadcast: bool,
) -> Vec<(Pot, String)> {
    let pots: Vec<u8> = Pot::ALL
        .into_iter()
        .filter(|p| a.template.pots[p.index()] > 0)
        .map(|p| p.index() as u8)
        .collect();
    // the nonce index of each pot, from the points the set was signed against
    let indices: Vec<u32> = set
        .terms
        .oracle_nonces
        .iter()
        .map(|r| {
            view.batch
                .r
                .iter()
                .position(|x| x == r)
                .map(|j| j as u32)
                .unwrap_or(u32::MAX)
        })
        .collect();
    let (got, notes) = pool::attestations(
        n,
        view,
        &a.case_hex,
        &pots,
        &indices,
        secs(num("--settle-wait", 300u64)),
    );
    for note in &notes {
        n.log(note);
    }
    let liars: Vec<&String> = notes
        .iter()
        .filter(|x| x.contains("different outcome"))
        .collect();
    if !liars.is_empty() {
        n.check(
            &format!("{} attestation share(s) for a different outcome caught and kept as evidence; t honest shares still combined", liars.len()),
            got.len() == pots.len(),
            "",
        );
    }
    let mut out = Vec::new();
    for (pot, (m, sc)) in got {
        let p = Pot::ALL[pot as usize];
        let Some(payout) = set.payouts.iter().find(|x| {
            x.ending.pot == p && x.ending.message(&a.case_id, set.terms.set_version) == m
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
                    if !ok {
                        continue;
                    }
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

fn class_of(s: &str) -> Class {
    match s.trim() {
        "I" => Class::Intervention,
        "D" => Class::Documentation,
        _ => Class::None,
    }
}

fn ballot_from_args(seats: usize, my_seat: usize) -> Ballot {
    // --claim I|D: what this attendee says it did, every other seat --others (default D); this is
    // what a ballot asserts, which may differ from what the footage shows (--act)
    if let Some(me) = arg("--claim") {
        let others = class_of(&arg("--others").unwrap_or("D".into()));
        let acts = (0..seats)
            .map(|i| Act {
                seat: i as u8,
                class: if i == my_seat {
                    class_of(&me)
                } else {
                    others.clone()
                },
                footage: None,
            })
            .collect();
        return Ballot {
            acts,
            outcome_achieved: !flag("--not-achieved"),
            misuse: flag("--misuse"),
        };
    }
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
    // simulated footage: a header stating what this recorder actually did (what a camera would show,
    // --act, default I), then filler; arbitrators read it after decrypting
    let mut footage = format!(
        "BITAID-SIMULATED-FOOTAGE recorder={} act={}\n",
        n.me(),
        arg("--act").unwrap_or("I".into())
    )
    .into_bytes();
    footage.extend((footage.len()..bytes).map(|i| (i * 31 % 251) as u8 ^ n.keys.secret_bytes()[0]));
    let blobs = blossom::seal_footage(&key, &c, &footage, 256 * 1024);
    let t0 = Instant::now();
    let mut ok = 0;
    let mut urls = vec![];
    for (_, _, url) in archivists {
        let mut all = true;
        for b in &blobs {
            // one retry: a first connection to an onion service can time out while its circuit builds
            let r = blossom::upload(url, &n.keys, &c, b).or_else(|e| {
                n.log(&format!("upload to {url} failed ({e}); retrying"));
                blossom::upload(url, &n.keys, &c, b)
            });
            if let Err(e) = &r {
                n.log(&format!("upload to {url} failed: {e}"));
            }
            if r.is_err() {
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

/// Every seat's revealed ballot (after `vote`), for the attendee's own reading of the outcome.
fn collect_reveals(n: &mut Node, a: &Alerted, r: &Rostered) -> Vec<Ballot> {
    let c = a.case_hex.clone();
    let seats = r.seats.clone();
    let mut seen = std::collections::HashSet::new();
    n.collect(
        secs(120),
        |env, _| match &env.msg {
            Msg::BallotReveal {
                case_id, ballot, ..
            } if *case_id == c
                && seats.contains(&env.sender)
                && seen.insert(env.sender.clone()) =>
            {
                Some(ballot.clone())
            }
            _ => None,
        },
        |v| v.len() >= seats.len(),
    )
}

/// Evidence as announced: recorder, blobs (hash, size), archivists.
type EvidenceItem = (String, Vec<(String, u64)>, Vec<String>);

const ARB_BOND_FLOOR: u64 = 10_000_000; // 0.1 BTC (§10.2)

/// Waits for the pre-signed forfeitures of `who` and keeps those that verify: per seat, its stake and its
/// seat forfeiture's pre-signature.
#[allow(clippy::too_many_arguments)]
fn wait_forfeits(
    n: &mut Node,
    c: &str,
    tier: u32,
    who: &[String],
    offers: &[(String, bitcoin::ScriptBuf, arb::Bond)],
    oxo: &bitcoin::XOnlyPublicKey,
    fee: u64,
    seizure: Option<&bitcoin::ScriptBuf>,
    refund: &bitcoin::ScriptBuf,
) -> HashMap<String, (arb::Bond, String)> {
    let mut out = HashMap::new();
    let Some(spk) = seizure else {
        return out;
    };
    let (cc, ww) = (c.to_string(), who.to_vec());
    let got = n.collect(
        secs(90),
        |env, _| match &env.msg {
            Msg::Forfeits {
                case_id,
                tier: t,
                stake,
                value,
                sigs,
            } if *case_id == cc && *t == tier && ww.contains(&env.sender) => {
                Some((env.sender.clone(), stake.clone(), *value, sigs.clone()))
            }
            _ => None,
        },
        |v| v.len() >= ww.len(),
    );
    for (w, stake, value, sigs) in got {
        let Some(b) = offers.iter().find(|o| o.0 == w).map(|o| o.2.clone()) else {
            continue;
        };
        if let Some(st) =
            arb::verify_forfeits(&b, &stake, value, &sigs, oxo, fee, spk, refund, &n.rpc)
        {
            out.insert(w, (st, sigs.last().cloned().unwrap_or_default()));
        }
    }
    out
}

/// The escalating party's side of one arbitration tier (§10.1–10.5): escalate, collect blind seat
/// offers, draw the panel from a block mined after offers close, disclose the case to the seats,
/// pay each its fee, then read the revealed verdicts and the tier commitment.
fn escalate_tier(
    n: &mut Node,
    a: &Alerted,
    view: &PoolView,
    tier: u32,
    reason: &str,
) -> Option<Ballot> {
    let c = a.case_hex.clone();
    let value: u64 = a.template.pots.iter().sum();
    let size = bitaid_node::arb::panel_size(tier);
    let okey = view.key_hex();
    n.send_case(
        &c,
        &[],
        Msg::Escalate {
            case_id: c.clone(),
            tier,
            reason: reason.into(),
        },
        false,
    );
    n.log(&format!("ESCALATE tier {tier} ({size} seats): {reason}"));
    let t0 = Instant::now();
    // blind taking: offers name only a bond and a payout address
    let end = Instant::now() + secs(num("--offer-window", 25u64));
    let mut offers: Vec<(String, bitcoin::ScriptBuf, arb::Bond)> = vec![];
    let oxo = wire::xonly(&okey).unwrap();
    while Instant::now() < end {
        let left = end.saturating_duration_since(Instant::now());
        let cc = c.clone();
        let Some((who, offer)) = n.wait(left, |env, _| match &env.msg {
            Msg::SeatOffer {
                case_id, tier: t, ..
            } if *case_id == cc && *t == tier => Some((env.sender.clone(), env.msg.clone())),
            _ => None,
        }) else {
            break;
        };
        if offers.iter().any(|o| o.0 == who) {
            continue;
        }
        // stake above exposure: a bond of at least twice what the verdict can move (§10.2)
        let ok = (|| {
            let b = arb::Bond::from_offer(&offer)?;
            let u = n.rpc.utxo(&b.op)?;
            (u.script_pubkey == b.tree(&oxo).script_pubkey()
                && u.value.to_sat() == b.value
                && b.value >= ARB_BOND_FLOOR.max(2 * value))
            .then_some(b)
        })();
        match ok {
            Some(b) => offers.push((who, b.payout.clone(), b)),
            _ => n.log(&format!(
                "seat offer from {} refused: bond missing or below twice the case value",
                &who[..8]
            )),
        }
    }
    if offers.len() < size {
        n.check(
            &format!("tier {tier}: at least {size} eligible arbitrators offered seats"),
            false,
            &format!("{} offered", offers.len()),
        );
        return None;
    }
    // the draw uses a block mined after offers closed, so no one could aim for a seat
    n.rpc.mine(1).ok();
    let h = n.rpc.height();
    let bh = n.rpc.block_hash(h).unwrap_or_default();
    let ids: Vec<String> = offers.iter().map(|o| o.0.clone()).collect();
    let seats = bitaid_node::arb::draw(&bh, &c, tier, &ids, size);
    let key = n.case_keys[&c];
    let sealed: Vec<String> = seats
        .iter()
        .map(|sid| {
            hex::encode(wire::seal(
                &n.keys,
                &wire::xonly(sid).unwrap(),
                c.as_bytes(),
                &key,
            ))
        })
        .collect();
    let mut seats = seats;
    // where a seat that misses its commit deadline refunds its fee (§10.4)
    let refund_spk = n.rpc.new_spk().unwrap_or_default();
    n.send_case(
        &c,
        &seats,
        Msg::Seated {
            case_id: c.clone(),
            tier,
            height: h,
            block_hash: bh.clone(),
            offers: ids.clone(),
            seats: seats.clone(),
            sealed_keys: sealed,
            refund_spk: refund_spk.to_hex_string(),
        },
        false,
    );
    n.check(&format!("tier {tier}: {size} of {} offering arbitrators drawn from block {h}, case disclosed only to them", ids.len()), true, &format!("{:.1} s after escalating", t0.elapsed().as_secs_f64()));
    // each seat pre-signs its bond's forfeitures before it is paid (§10.4, §12)
    let fee = bitaid_node::arb::seat_fee(a.template.arb_fee, tier);
    let r_arch = n
        .history
        .iter()
        .rev()
        .find_map(|e| match &e.msg {
            Msg::Roster {
                case_id,
                archivists,
                ..
            } if *case_id == c && e.sender == a.caller => Some(archivists.clone()),
            _ => None,
        })
        .unwrap_or_default();
    let seizure = arb::seizure_tree(&r_arch, &oxo).map(|t| t.0.script_pubkey());
    let mut stakes: HashMap<String, (arb::Bond, String)> = HashMap::new();
    let got = wait_forfeits(
        n,
        &c,
        tier,
        &seats,
        &offers,
        &oxo,
        fee,
        seizure.as_ref(),
        &refund_spk,
    );
    n.check(
        &format!("tier {tier}: every seat set aside a stake of 4× the {fee}-sat fee under its bond's script and pre-signed its forfeitures (2× to 4×, into the case's seizure output) and its seat forfeiture"),
        got.len() == seats.len(),
        &format!("{} of {}", got.len(), seats.len()),
    );
    stakes.extend(got);
    // each seat paid its fee directly by whoever escalated (§10.6, §11.11)
    let pay: Vec<(bitcoin::ScriptBuf, u64)> = seats
        .iter()
        .map(|sid| (offers.iter().find(|o| &o.0 == sid).unwrap().1.clone(), fee))
        .collect();
    match n.rpc.pay_many(&pay) {
        Ok(txid) => {
            n.rpc.mine(1).ok();
            n.send_case(
                &c,
                &seats,
                Msg::FeePaid {
                    case_id: c.clone(),
                    tier,
                    txid: txid.to_string(),
                },
                false,
            );
            n.check(
                &format!("tier {tier}: {size} × {fee} sats paid to the seats"),
                true,
                &txid.to_string()[..16],
            );
        }
        Err(e) => {
            n.check(&format!("tier {tier}: fees paid"), false, &e);
            return None;
        }
    }
    // §10.4: a seat that has not committed its vote by the deadline is forfeit — its pre-signed seat
    // forfeiture, co-signed by the pool, refunds its fee to the payer — and a replacement is drawn
    let mut committed_by: std::collections::HashSet<String> = Default::default();
    let mut forfeited: Vec<String> = vec![];
    let mut session = 400u32;
    loop {
        let (cc, ss) = (c.clone(), seats.clone());
        let deadline = secs(a.template.commit_deadline as u64 + 15);
        let have = committed_by.clone();
        for who in n.collect(
            deadline,
            |env, _| match &env.msg {
                Msg::VerdictCommit {
                    case_id, tier: t, ..
                } if *case_id == cc && *t == tier && ss.contains(&env.sender) => {
                    Some(env.sender.clone())
                }
                _ => None,
            },
            |v| {
                v.iter()
                    .chain(have.iter())
                    .collect::<std::collections::HashSet<_>>()
                    .len()
                    >= ss.len()
            },
        ) {
            committed_by.insert(who);
        }
        let missing: Vec<String> = seats
            .iter()
            .filter(|x| !committed_by.contains(*x))
            .cloned()
            .collect();
        if missing.is_empty() {
            break;
        }
        for m in missing {
            let Some((stake, sig)) = stakes.get(&m).cloned() else {
                n.check(
                    &format!("tier {tier}: seat forfeiture of {}", &m[..8]),
                    false,
                    "no pre-signed seat forfeiture",
                );
                return None;
            };
            let (mut tx, d) = stake.penalty_tx(&oxo, fee, &refund_spk);
            let res = pool::cosign(n, view, &c, &serialize_hex(&tx), 0, &d, session).and_then(
                |(osig, _, _)| {
                    stake.witness(&oxo, &mut tx, &hex::decode(&sig).unwrap_or_default(), &osig);
                    n.rpc.package(&tx)
                },
            );
            session += 10;
            n.check(
                &format!(
                    "tier {tier}: arbitrator {} missed its commit deadline ({} s); its seat forfeiture refunded the {fee}-sat fee to the payer, co-signed by the pool",
                    &m[..8],
                    a.template.commit_deadline
                ),
                res.is_ok(),
                &match &res {
                    Ok(t) => t.to_string()[..16].to_string(),
                    Err(e) => e.clone(),
                },
            );
            // a replacement drawn from the offers left, by a block mined after the forfeiture
            n.rpc.mine(1).ok();
            let h = n.rpc.height();
            let bh = n.rpc.block_hash(h).unwrap_or_default();
            let left: Vec<String> = ids
                .iter()
                .filter(|o| !seats.contains(o) && !forfeited.contains(o))
                .cloned()
                .collect();
            let Some(new) = bitaid_node::arb::draw(&bh, &c, tier, &left, 1).pop() else {
                n.check(
                    &format!("tier {tier}: an offer left to replace the forfeited seat"),
                    false,
                    "none; the escalation lapses",
                );
                return None;
            };
            let pos = seats.iter().position(|x| *x == m).unwrap();
            seats[pos] = new.clone();
            forfeited.push(m.clone());
            let key = n.case_keys[&c];
            n.send_case(
                &c,
                std::slice::from_ref(&new),
                Msg::Reseated {
                    case_id: c.clone(),
                    tier,
                    height: h,
                    block_hash: bh,
                    replaced: m.clone(),
                    seat: new.clone(),
                    sealed_key: hex::encode(wire::seal(
                        &n.keys,
                        &wire::xonly(&new).unwrap(),
                        c.as_bytes(),
                        &key,
                    )),
                },
                false,
            );
            let got = wait_forfeits(
                n,
                &c,
                tier,
                std::slice::from_ref(&new),
                &offers,
                &oxo,
                fee,
                seizure.as_ref(),
                &refund_spk,
            );
            stakes.extend(got);
            let spk = offers.iter().find(|o| o.0 == new).unwrap().1.clone();
            match n.rpc.pay_many(&[(spk, fee)]) {
                Ok(txid) => {
                    n.rpc.mine(1).ok();
                    n.send_case(
                        &c,
                        std::slice::from_ref(&new),
                        Msg::FeePaid {
                            case_id: c.clone(),
                            tier,
                            txid: txid.to_string(),
                        },
                        false,
                    );
                    n.check(
                        &format!("tier {tier}: replacement {} drawn from the {} offers left by block {h}, staked, pre-signed and paid", &new[..8], left.len()),
                        stakes.contains_key(&new),
                        &txid.to_string()[..16],
                    );
                }
                Err(e) => {
                    n.check(&format!("tier {tier}: replacement fee paid"), false, &e);
                    return None;
                }
            }
        }
    }
    // the revealed verdicts and the tier commitment
    let (cc, ss) = (c.clone(), seats.clone());
    let mut seen = std::collections::HashSet::new();
    let reveals: Vec<(String, Ballot)> = n.collect(
        secs(num("--verdict-wait", 600u64)),
        |env, _| match &env.msg {
            Msg::VerdictReveal {
                case_id,
                tier: t,
                verdict,
                ..
            } if *case_id == cc
                && *t == tier
                && ss.contains(&env.sender)
                && seen.insert(env.sender.clone()) =>
            {
                Some((env.sender.clone(), verdict.clone()))
            }
            _ => None,
        },
        |v| v.len() >= size,
    );
    let cc = c.clone();
    let committed = n.wait(secs(180), |env, _| match &env.msg {
        Msg::TierCommitted {
            case_id,
            tier: t,
            txid,
        } if *case_id == cc && *t == tier => Some(txid.clone()),
        _ => None,
    });
    let commitment = bitaid_node::arb::tier_commitment(&c, tier, &seats, &reveals);
    let on_chain = committed
        .as_ref()
        .map(|t| n.rpc.has_op_return(t, &commitment))
        .unwrap_or(false);
    n.check(&format!("tier {tier}: {} of {size} verdicts revealed; roster and answers committed on chain (OP_RETURN)", reveals.len()), on_chain, &committed.unwrap_or_default());
    let votes: Vec<Ballot> = reveals.iter().map(|x| x.1.clone()).collect();
    let verdict = bitaid_node::arb::supermajority(size, &votes);
    match &verdict {
        Some(v) => {
            let k = bitaid_node::arb::verdict_key(v);
            let dissent = votes
                .iter()
                .filter(|x| bitaid_node::arb::verdict_key(x) != k)
                .count();
            let pen = if dissent > 0 {
                format!("; {dissent} dissenter(s) owe {:.1}× the fee each, settled against the final ruling", bitaid_node::arb::penalty_factor(size, dissent))
            } else {
                String::from(", unanimous")
            };
            n.check(
                &format!(
                    "tier {tier}: two-thirds verdict ({} of {size}){pen}",
                    size - dissent
                ),
                true,
                &format!("{:.1} s from escalation", t0.elapsed().as_secs_f64()),
            );
        }
        // a hung panel is a legitimate result (§10.5): it decides nothing, the last verdict stands
        None => n.check(
            &format!("tier {tier}: no two-thirds verdict, so the tier decides nothing and the last verdict stands"),
            true,
            &format!("{:.1} s from escalation", t0.elapsed().as_secs_f64()),
        ),
    }
    verdict
}

/// Follows a tier someone else escalated: its panel, the revealed verdicts, the two-thirds verdict.
/// Returns None if no one escalates that tier within `start`, Some(None) if the tier hangs.
fn watch_tier(n: &mut Node, a: &Alerted, tier: u32, start: Duration) -> Option<Option<Ballot>> {
    let c = a.case_hex.clone();
    let cc = c.clone();
    n.wait(start, |env, _| match &env.msg {
        Msg::Escalate {
            case_id, tier: t, ..
        } if *case_id == cc && *t == tier => Some(()),
        _ => None,
    })?;
    n.log(&format!(
        "tier {tier} opened by another party; following it"
    ));
    let cc = c.clone();
    let seats = n.wait(secs(600), |env, _| match &env.msg {
        Msg::Seated {
            case_id,
            tier: t,
            seats,
            ..
        } if *case_id == cc && *t == tier => Some(seats.clone()),
        _ => None,
    })?;
    let (cc, mut ss) = (c.clone(), seats.clone());
    let mut seen = std::collections::HashSet::new();
    let votes: Vec<Ballot> = n.collect(
        secs(num("--verdict-wait", 600u64)),
        |env, _| match &env.msg {
            // a seat forfeit for missing its commit deadline, and its replacement (§10.4)
            Msg::Reseated {
                case_id,
                tier: t,
                replaced,
                seat,
                ..
            } if *case_id == cc && *t == tier => {
                if let Some(p) = ss.iter().position(|x| x == replaced) {
                    ss[p] = seat.clone();
                }
                None
            }
            Msg::VerdictReveal {
                case_id,
                tier: t,
                verdict,
                ..
            } if *case_id == cc
                && *t == tier
                && ss.contains(&env.sender)
                && seen.insert(env.sender.clone()) =>
            {
                Some(verdict.clone())
            }
            _ => None,
        },
        |v| v.len() >= seats.len(),
    );
    Some(bitaid_node::arb::supermajority(seats.len(), &votes))
}

/// A seat forfeiture this member's own records call for: the seat was paid at least the template's
/// commit deadline ago (by this member's clock), has not committed a vote, and the transaction is its
/// pre-signed seat forfeiture refunding the fee to the payer (§10.4).
#[allow(clippy::type_complexity)]
fn seat_forfeit_due(
    n: &Node,
    a: &Alerted,
    r: &Rostered,
    t: &Transaction,
    input: u32,
    vcommits: &HashMap<(String, u32), HashMap<String, String>>,
    fee_at: &HashMap<(String, u32, String), Instant>,
) -> Option<([u8; 32], String)> {
    if input != 0 {
        return None;
    }
    let rp = arb::Replay::build(&n.history, a, r, &n.rpc)?;
    let id = t.compute_txid();
    for (k, tier) in &rp.tiers {
        for seat in tier.seats.iter() {
            let Some((tx, d, _, _)) = rp.seat_forfeit(*k, seat) else {
                continue;
            };
            if tx.compute_txid() != id {
                continue;
            }
            let paid = fee_at.get(&(a.case_hex.clone(), *k, seat.clone()))?;
            let voted = vcommits
                .get(&(a.case_hex.clone(), *k))
                .map(|m| m.contains_key(seat))
                .unwrap_or(false);
            if voted || paid.elapsed() < secs(a.template.commit_deadline as u64) {
                return None;
            }
            return Some((
                d,
                format!(
                    "the seat forfeiture of {} on tier {k} (no vote by the deadline)",
                    &seat[..8]
                ),
            ));
        }
    }
    None
}

/// What a final case calls for, as this node's own replay of the log computes it: the forfeitures
/// its ruling settles (input 0 each) and every input of its seizure output's distribution, as
/// (txid, input, digest, description). Computed once per case and kept.
fn arb_due(n: &Node, a: &Alerted, r: &Rostered) -> Vec<(bitcoin::Txid, usize, [u8; 32], String)> {
    let Some(rp) = arb::Replay::build(&n.history, a, r, &n.rpc) else {
        return vec![];
    };
    let pens = rp.penalties();
    let mut out: Vec<(bitcoin::Txid, usize, [u8; 32], String)> = pens
        .iter()
        .map(|p| {
            (
                p.tx.compute_txid(),
                0,
                p.digest,
                format!(
                    "the forfeiture of {} sats ({:.1}× the fee) from the bond of {}",
                    p.amount,
                    p.step as f64 / 10.0,
                    &p.arbitrator[..8]
                ),
            )
        })
        .collect();
    if let Some((dist, prev)) = rp.distribution(&pens) {
        for i in 0..dist.input.len() {
            if let Some(d) = rp.distribution_digest(&dist, &prev, i) {
                out.push((
                    dist.compute_txid(),
                    i,
                    d,
                    format!("input {i} of the seizure output's distribution"),
                ));
            }
        }
    }
    out
}

fn verdict_classes(v: &Ballot) -> String {
    v.acts
        .iter()
        .map(|x| match x.class {
            Class::Intervention => "I",
            Class::Documentation => "D",
            Class::None => "-",
        })
        .collect::<Vec<_>>()
        .join(",")
}

/// An arbitrator's bond keys, for taking a seat.
struct SeatKeys {
    bond: OutPoint,
    bond_value: u64,
    bs: Scalar,
    bc: Scalar,
    bf: u32,
    payout: bitcoin::ScriptBuf,
    okey: String,
}

/// On taking a seat: set aside the seat's stake (4× its fee) under the bond's script and pre-sign its
/// forfeitures — one per penalty step into the case's seizure output (§10.4, §12) and the seat
/// forfeiture refunding the fee if this seat misses its commit deadline.
fn take_seat(
    n: &mut Node,
    k: &SeatKeys,
    a: Option<&Alerted>,
    r: Option<&Rostered>,
    case_id: &str,
    tier: u32,
    refund: &bitcoin::ScriptBuf,
) {
    let (Some(a), Some(r)) = (a, r) else {
        return;
    };
    let oxo = wire::xonly(&k.okey).unwrap();
    let me_bond = arb::Bond {
        op: k.bond,
        value: k.bond_value,
        scoped: xo(&k.bs),
        cold: xo(&k.bc),
        fallback: k.bf,
        payout: k.payout.clone(),
    };
    let Some((st, _)) = arb::seizure_tree(&r.archivists, &oxo) else {
        n.log("case names no archivists; no seizure output to forfeit to");
        return;
    };
    let fee = arb::seat_fee(a.template.arb_fee, tier);
    // the seat's stake: its own output, so forfeitures pre-signed for seats held at once never spend
    // the same coin
    let value = arb::SEAT_STAKE_STEPS * fee / 10;
    let sop = match n.rpc.fund(&me_bond.tree(&oxo).script_pubkey(), value) {
        Ok(op) => op,
        Err(e) => {
            n.log(&format!("seat stake not posted: {e}"));
            return;
        }
    };
    n.rpc.mine(1).ok();
    let stake = me_bond.stake(sop, value);
    let sigs: Vec<String> = stake
        .forfeit_digests(&oxo, fee, &st.script_pubkey(), refund)
        .iter()
        .map(|d| hex::encode(sign_bip340(&k.bs, d)))
        .collect();
    if !flag("--no-forfeits") {
        n.send_case(
            case_id,
            &[],
            Msg::Forfeits {
                case_id: case_id.to_string(),
                tier,
                stake: sop.to_string(),
                value,
                sigs,
            },
            false,
        );
    }
}

/// An arbitrator: posts a bond, offers seats blind, and when seated reviews the evidence and votes.
fn arbitrator(mut n: Node) -> i32 {
    let secp = Secp256k1::new();
    n.subscribe("svc", vec![Filter::kinds(&[kind::ANNOUNCE]).recent(3600)]);
    let Some(view) = pool::discover(
        &mut n,
        &arg("--pool").unwrap_or("bitaid".into()),
        secs(num("--setup-wait", 3600u64)),
    ) else {
        n.log("no oracle pool found");
        return 1;
    };
    let okey = view.key_hex();
    let (bs, bc) = (random_scalar(), random_scalar());
    let bf = n.rpc.height() + 52_560;
    let bt = outputs::bond(&secp, &xo(&bs), &xo(&bc), &wire::xonly(&okey).unwrap(), bf);
    let bond_value = num("--bond", 10_000_000u64);
    let bond = match n.rpc.fund(&bt.script_pubkey(), bond_value) {
        Ok(op) => op,
        Err(e) => {
            n.log(&format!("bond not posted: {e}"));
            return 1;
        }
    };
    n.rpc.mine(1).ok();
    let payout = n.rpc.new_spk().expect("payout address");
    let corrupt = flag("--corrupt");
    n.subscribe("cases", vec![Filter::kinds(&[kind::ALERT, kind::CASE])]);
    n.log(&format!(
        "arbitrator bond {} posted{}",
        &bond.to_string()[..12],
        if corrupt {
            " (corrupt: sides against the footage)"
        } else {
            ""
        }
    ));
    let me = n.me();
    let mut alerts: HashMap<String, Alerted> = HashMap::new();
    let mut rosters: HashMap<String, Rostered> = HashMap::new();
    let mut evidence: HashMap<String, Vec<EvidenceItem>> = HashMap::new();
    let mut escalator: HashMap<(String, u32), String> = HashMap::new();
    let mut seated: HashMap<(String, u32), Vec<String>> = HashMap::new();
    let mut commits: HashMap<(String, u32), std::collections::BTreeSet<String>> = HashMap::new();
    let mut reveals: HashMap<(String, u32), Vec<(String, Ballot)>> = HashMap::new();
    let mut mine: HashMap<(String, u32), (Ballot, [u8; 32])> = HashMap::new();
    let mut revealed: std::collections::HashSet<(String, u32)> = Default::default();
    let mut refunds: HashMap<(String, u32), bitcoin::ScriptBuf> = HashMap::new();
    // --challenge: tiers this arbitrator dissented on, and when it challenges if no party appeals
    let mut challenge_at: HashMap<(String, u32), Instant> = HashMap::new();
    let idle = num("--exit-after", 3600u64);
    let mut last = Instant::now();
    loop {
        if last.elapsed() > secs(idle) {
            return 0;
        }
        let due: Vec<(String, u32)> = challenge_at
            .iter()
            .filter(|(_, t)| Instant::now() >= **t)
            .map(|(k, _)| k.clone())
            .collect();
        for (c, tier) in due {
            challenge_at.remove(&(c.clone(), tier));
            if escalator.contains_key(&(c.clone(), tier + 1)) {
                n.log(&format!(
                    "tier {} opened by a party; no challenge needed",
                    tier + 1
                ));
                continue;
            }
            let (Some(a), Some(r)) = (alerts.get(&c).cloned(), rosters.get(&c).cloned()) else {
                continue;
            };
            n.check(
                &format!(
                    "dissented on tier {tier} and no party appealed: buying the re-roll to tier {} on a party's terms",
                    tier + 1
                ),
                true,
                "",
            );
            let v = escalate_tier(&mut n, &a, &view, tier + 1, "dissenter's re-roll");
            let mine_v = mine.get(&(c.clone(), tier)).map(|x| arb::verdict_key(&x.0));
            let upheld = v
                .as_ref()
                .map(|v| Some(arb::verdict_key(v)) == mine_v)
                .unwrap_or(false);
            n.check(
                &format!(
                    "tier {}: the larger panel {} the dissent",
                    tier + 1,
                    if upheld {
                        "agreed with"
                    } else {
                        "did not agree with"
                    }
                ),
                true,
                &v.as_ref()
                    .map(verdict_classes)
                    .unwrap_or("no verdict".into()),
            );
            // once the pool has attested the final outcome, collect the seizure output as the party
            // that paid for the deciding tier
            let cc = c.clone();
            let t = view.t;
            let mut who = std::collections::HashSet::new();
            let got = n.collect(
                secs(a.template.dispute_window as u64 + 600),
                |env, _| match &env.msg {
                    Msg::AttestShare { case_id, .. }
                        if *case_id == cc && who.insert(env.sender.clone()) =>
                    {
                        Some(())
                    }
                    _ => None,
                },
                |v| v.len() >= t,
            );
            n.check(
                "the pool attested the final outcome",
                got.len() >= t,
                &format!("{} members", got.len()),
            );
            collect_seizure(&mut n, &a, &r, &view);
            n.summary();
        }
        let Some(env) = n.wait(secs(2), |env, _| Some(env.clone())) else {
            continue;
        };
        last = Instant::now();
        let s = env.sender.clone();
        match env.msg {
            Msg::Alert { .. } => {
                if let Ok(a) = Alerted::check(&s, &env.msg, chain_view(&n.rpc), &okey) {
                    alerts.insert(a.case_hex.clone(), a);
                }
            }
            Msg::Roster { ref case_id, .. } => {
                if alerts.get(case_id).map(|a| a.caller == s).unwrap_or(false) {
                    if let Some(r) = Rostered::from_msg(&env.msg) {
                        rosters.insert(case_id.clone(), r);
                    }
                }
            }
            Msg::Evidence {
                case_id,
                blobs,
                archivists,
                ..
            } => evidence
                .entry(case_id)
                .or_default()
                .push((s, blobs, archivists)),
            Msg::Escalate { case_id, tier, .. } => {
                let Some(a) = alerts.get(&case_id) else {
                    continue;
                };
                if s == me {
                    continue;
                }
                escalator.insert((case_id.clone(), tier), s);
                // --tiers 1,2: the tiers this arbitrator serves (an operator's choice of workload)
                if let Some(ts) = arg("--tiers") {
                    if !ts.split(',').any(|x| x.trim().parse() == Ok(tier)) {
                        continue;
                    }
                }
                let value: u64 = a.template.pots.iter().sum();
                if bond_value < 2 * value {
                    n.log("not eligible: bond below twice the case value");
                    continue;
                }
                // blind: the offer is made knowing the fee, tier and value, not the parties or evidence
                n.send_case(
                    &case_id,
                    &[],
                    Msg::SeatOffer {
                        case_id: case_id.clone(),
                        tier,
                        bond: bond.to_string(),
                        bond_scoped: hex::encode(xo(&bs).serialize()),
                        bond_cold: hex::encode(xo(&bc).serialize()),
                        bond_fallback: bf,
                        bond_value,
                        payout_spk: payout.to_hex_string(),
                    },
                    false,
                );
                n.log(&format!(
                    "offered a seat on tier {tier} of {}",
                    &case_id[..8]
                ));
            }
            Msg::Seated {
                case_id,
                tier,
                seats,
                sealed_keys,
                refund_spk,
                ..
            } => {
                if escalator.get(&(case_id.clone(), tier)) != Some(&s) {
                    continue;
                }
                let refund = bitcoin::ScriptBuf::from_hex(&refund_spk).unwrap_or_default();
                refunds.insert((case_id.clone(), tier), refund.clone());
                if let Some(pos) = seats.iter().position(|x| *x == me) {
                    if let Some(k) = hex::decode(&sealed_keys[pos]).ok().and_then(|k| {
                        wire::unseal(&n.keys, &wire::xonly(&s).unwrap(), case_id.as_bytes(), &k)
                    }) {
                        n.add_case_key(&case_id, k.try_into().unwrap());
                        n.log(&format!(
                            "seated on tier {tier} of {} (seat {pos}); case disclosed",
                            &case_id[..8]
                        ));
                        let seat = SeatKeys {
                            bond,
                            bond_value,
                            bs,
                            bc,
                            bf,
                            payout: payout.clone(),
                            okey: okey.clone(),
                        };
                        take_seat(
                            &mut n,
                            &seat,
                            alerts.get(&case_id),
                            rosters.get(&case_id),
                            &case_id,
                            tier,
                            &refund,
                        );
                    }
                }
                seated.insert((case_id, tier), seats);
            }
            // §10.4: a seat that missed its commit deadline, replaced; the replacement takes the seat
            Msg::Reseated {
                case_id,
                tier,
                replaced,
                seat,
                sealed_key,
                ..
            } => {
                let key = (case_id.clone(), tier);
                if escalator.get(&key) != Some(&s) {
                    continue;
                }
                if let Some(list) = seated.get_mut(&key) {
                    if let Some(p) = list.iter().position(|x| *x == replaced) {
                        list[p] = seat.clone();
                    }
                }
                if seat == me {
                    if let Some(k) = hex::decode(&sealed_key).ok().and_then(|k| {
                        wire::unseal(&n.keys, &wire::xonly(&s).unwrap(), case_id.as_bytes(), &k)
                    }) {
                        n.add_case_key(&case_id, k.try_into().unwrap());
                        n.log(&format!(
                            "drawn on tier {tier} of {} to replace {}, whose seat was forfeit; case disclosed",
                            &case_id[..8],
                            &replaced[..8]
                        ));
                        let refund = refunds.get(&key).cloned().unwrap_or_default();
                        let sk = SeatKeys {
                            bond,
                            bond_value,
                            bs,
                            bc,
                            bf,
                            payout: payout.clone(),
                            okey: okey.clone(),
                        };
                        take_seat(
                            &mut n,
                            &sk,
                            alerts.get(&case_id),
                            rosters.get(&case_id),
                            &case_id,
                            tier,
                            &refund,
                        );
                    }
                }
            }
            Msg::FeePaid {
                case_id,
                tier,
                txid,
            } => {
                let key = (case_id.clone(), tier);
                let Some(seats) = seated.get(&key) else {
                    continue;
                };
                if !seats.contains(&me) || mine.contains_key(&key) {
                    continue;
                }
                let (Some(a), Some(r)) = (
                    alerts.get(&case_id).cloned(),
                    rosters.get(&case_id).cloned(),
                ) else {
                    continue;
                };
                let fee = bitaid_node::arb::seat_fee(a.template.arb_fee, tier);
                let got = n.rpc.paid_to(&txid, &payout);
                if got < fee {
                    n.log(&format!(
                        "fee not received ({got} of {fee} sats); not ruling"
                    ));
                    continue;
                }
                // review: fetch every recorder's evidence, decrypt it, read what the footage shows
                let cc = case_id.clone();
                for (who, blobs, arch) in n.collect(
                    secs(3),
                    |env, _| match &env.msg {
                        Msg::Evidence {
                            case_id,
                            blobs,
                            archivists,
                            ..
                        } if *case_id == cc => {
                            Some((env.sender.clone(), blobs.clone(), archivists.clone()))
                        }
                        _ => None,
                    },
                    |_| false,
                ) {
                    evidence
                        .entry(case_id.clone())
                        .or_default()
                        .push((who, blobs, arch));
                }
                let ek = tagged("Bitaid/evidence-key", &n.case_keys[&case_id]);
                let mut shows: HashMap<String, String> = HashMap::new();
                let mut kib = 0;
                for (who, blobs, arch) in evidence.get(&case_id).cloned().unwrap_or_default() {
                    let Some(url) = arch.first() else { continue };
                    let t_f = Instant::now();
                    let got: Option<Vec<Vec<u8>>> = blobs
                        .iter()
                        .map(|(h, _)| {
                            // one retry: an archive that times out once is asked again before the
                            // footage counts as missing
                            blossom::fetch(url, h)
                                .or_else(|e| {
                                    n.log(&format!(
                                        "fetch of {} from {url} failed ({e}); retrying",
                                        &h[..8]
                                    ));
                                    blossom::fetch(url, h)
                                })
                                .map_err(|e| {
                                    n.log(&format!(
                                        "fetch of {} from {url} failed again: {e}",
                                        &h[..8]
                                    ))
                                })
                                .ok()
                        })
                        .collect();
                    if t_f.elapsed() > secs(10) {
                        n.log(&format!(
                            "evidence of {} took {:.1} s to fetch",
                            &who[..8],
                            t_f.elapsed().as_secs_f64()
                        ));
                    }
                    let Some(plain) = got.and_then(|b| blossom::open_footage(&ek, &case_id, &b))
                    else {
                        continue;
                    };
                    kib += plain.len() / 1024;
                    let head = String::from_utf8_lossy(&plain[..plain.len().min(200)]).to_string();
                    if let Some(act) = head
                        .split("act=")
                        .nth(1)
                        .map(|x| x.chars().take(1).collect::<String>())
                    {
                        if head.contains(&format!("recorder={who}")) {
                            shows.insert(who, act);
                        }
                    }
                }
                let acts = r
                    .seats
                    .iter()
                    .enumerate()
                    .map(|(i, sid)| {
                        let shown = shows.get(sid).cloned().unwrap_or_default();
                        let mut c = class_of(&shown);
                        if corrupt {
                            c = match c {
                                Class::Intervention => Class::Documentation,
                                Class::Documentation => Class::Intervention,
                                x => x,
                            };
                        }
                        Act {
                            seat: i as u8,
                            class: c,
                            footage: None,
                        }
                    })
                    .collect();
                let verdict = Ballot {
                    acts,
                    outcome_achieved: true,
                    misuse: false,
                };
                n.log(&format!(
                    "reviewed {kib} KiB of footage from {} recorders; verdict {}",
                    shows.len(),
                    verdict_classes(&verdict)
                ));
                if flag("--no-vote") {
                    n.log("(test) took the seat and the fee, and never commits a vote");
                    mine.insert(key, (verdict, [0u8; 32]));
                    continue;
                }
                let salt: [u8; 32] = rand::random();
                n.send_case(
                    &case_id,
                    &[],
                    Msg::VerdictCommit {
                        case_id: case_id.clone(),
                        tier,
                        commitment: hex::encode(verdict.commitment(&salt)),
                    },
                    true,
                );
                mine.insert(key, (verdict, salt));
            }
            Msg::VerdictCommit { case_id, tier, .. } => {
                let key = (case_id.clone(), tier);
                if !seated.get(&key).map(|x| x.contains(&s)).unwrap_or(false) {
                    continue;
                }
                let set = commits.entry(key.clone()).or_default();
                set.insert(s);
                let all = set.len() >= seated[&key].len();
                if all && !revealed.contains(&key) {
                    if let Some((v, salt)) = mine.get(&key).cloned() {
                        revealed.insert(key.clone());
                        n.send_case(
                            &case_id,
                            &[],
                            Msg::VerdictReveal {
                                case_id: case_id.clone(),
                                tier,
                                verdict: v,
                                salt: hex::encode(salt),
                            },
                            true,
                        );
                    }
                }
            }
            Msg::TierCommitted { case_id, tier, .. } => {
                let key = (case_id.clone(), tier);
                if !flag("--challenge") || tier >= num("--max-tier", 2u32) {
                    continue;
                }
                let (Some(list), Some((my, _)), Some(seats), Some(a)) = (
                    reveals.get(&key),
                    mine.get(&key),
                    seated.get(&key),
                    alerts.get(&case_id),
                ) else {
                    continue;
                };
                let votes: Vec<Ballot> = list.iter().map(|x| x.1.clone()).collect();
                if let Some(v) = arb::supermajority(seats.len(), &votes) {
                    if arb::verdict_key(&v) != arb::verdict_key(my) {
                        let w = a.template.dispute_window as u64 / 2;
                        n.log(&format!(
                            "dissented on tier {tier} ({} against my {}); challenging in {w} s unless a party appeals",
                            verdict_classes(&v),
                            verdict_classes(my)
                        ));
                        challenge_at.insert(key, Instant::now() + secs(w));
                    }
                }
            }
            Msg::VerdictReveal {
                case_id,
                tier,
                verdict,
                ..
            } => {
                let key = (case_id.clone(), tier);
                let Some(seats) = seated.get(&key).cloned() else {
                    continue;
                };
                if !seats.contains(&s) {
                    continue;
                }
                let list = reveals.entry(key.clone()).or_default();
                if !list.iter().any(|x| x.0 == s) {
                    list.push((s, verdict));
                }
                // the first seat posts the tier commitment once every verdict is revealed
                if list.len() == seats.len() && seats.first() == Some(&me) {
                    let cm = bitaid_node::arb::tier_commitment(&case_id, tier, &seats, list);
                    match n.rpc.op_return(&cm) {
                        Ok(txid) => {
                            n.rpc.mine(1).ok();
                            n.send_case(
                                &case_id,
                                &[],
                                Msg::TierCommitted {
                                    case_id: case_id.clone(),
                                    tier,
                                    txid: txid.to_string(),
                                },
                                false,
                            );
                            n.log(&format!(
                                "tier {tier} commitment on chain in {}",
                                &txid.to_string()[..16]
                            ));
                        }
                        Err(e) => n.log(&format!("tier commitment failed: {e}")),
                    }
                }
            }
            _ => {}
        }
    }
}

// =================================================================== caller

fn caller(mut n: Node) -> i32 {
    let secp = Secp256k1::new();
    n.subscribe("svc", vec![Filter::kinds(&[kind::ANNOUNCE]).recent(3600)]);
    let Some(view) = pool::discover(
        &mut n,
        &arg("--pool").unwrap_or("bitaid".into()),
        secs(num("--setup-wait", 3600u64)),
    ) else {
        n.check("oracle pool found and checked on the relays", false, "");
        return n.summary();
    };
    let okey = view.key_hex();
    n.check(
        &format!(
            "oracle pool found and checked: {} members, threshold {}, {} nonces",
            view.members.len(),
            view.t,
            view.batch.r.len()
        ),
        true,
        &okey[..16],
    );
    let want_arch = num("--archivists", 1usize);
    let archivists = n.all_services("archivist", want_arch, secs(60));
    n.log(&format!(
        "pool {}…, {} archivist(s)",
        &okey[..12],
        archivists.len()
    ));

    // responders find the pool at the same moment; give them time to post bonds and listen
    let delay = num("--alert-delay", 15u64);
    n.log(&format!(
        "pool ready; alerting in {delay} s so responders can start listening"
    ));
    std::thread::sleep(secs(delay));

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
        arb_fee: num("--arb-fee", 20_000u64),
        refund_delay: 12_960,
        refund_xpub: bitcoin::bip32::Xpub::from_priv(&secp, &xpriv).to_string(),
        commit_deadline: num("--commit-deadline", 60u32),
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

    // ------------------------------------------------ nonces reserved by the pool
    let nonces: Vec<String> = match pool::reserve_nonces(&mut n, &view, &c) {
        Ok((_, pts)) => pts.iter().map(point_hex).collect(),
        Err(e) => {
            n.check("pool reserved nonces for the case", false, &e);
            return n.summary();
        }
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
            archivists: archivists.iter().map(|x| x.0.clone()).collect(),
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
        // the pool members, then the case's archivists, who co-sign its seizure output (§12)
        for id in view.identities().iter().chain(r.archivists.iter()) {
            sealed.push(hex::encode(wire::seal(
                &n.keys,
                &wire::xonly(id).unwrap(),
                c.as_bytes(),
                &case_key,
            )));
        }
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
            archivists: r.archivists.clone(),
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
    let leaf = &tree.scripts[funding_leaf::ACCEPT];
    let dd = txbuild::scriptspend_digest(
        &inc,
        0,
        &[txbuild::txout(total, tree.script_pubkey())],
        leaf,
    );
    let t_co = Instant::now();
    let osig = match pool::cosign(&mut n, &view, &c, &serialize_hex(&inc), 0, &dd, 1) {
        Ok((sig, sessions, signers)) => {
            n.check(
                &format!(
                    "pool co-signed the incident (FROST, {} of {} members)",
                    signers.len(),
                    view.members.len()
                ),
                bitaid_core::oracle::verify_bip340(&view.public.xonly(), &dd, &sig),
                &format!(
                    "{sessions} session(s), signers {signers:?}, {:.2} s",
                    t_co.elapsed().as_secs_f64()
                ),
            );
            sig.to_vec()
        }
        Err(e) => {
            n.check("pool co-signed the incident transaction", false, &e);
            return n.summary();
        }
    };
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
    let paid = settle(&mut n, &a, &set, &view, true);
    if flag("--mine") {
        n.rpc.mine(1).ok();
    }
    // settled means: the incident confirmed, and a payout of every pot broadcast and confirmed
    let pots = set.pot_outpoints.iter().flatten().count();
    let confirmed = set
        .payouts
        .iter()
        .filter(|x| {
            paid.iter()
                .any(|(p, l)| *p == x.ending.pot && *l == x.ending.label)
        })
        .filter(|x| n.rpc.confirmations(&x.tx.compute_txid()) > 0)
        .count();
    let spent = n.rpc.confirmations(&set.incident_txid) > 0 && confirmed == pots;
    n.check(
        &format!(
            "all {pots} pots settled on chain by the attested outcome ({confirmed} payouts confirmed)"
        ),
        spent,
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
    n.subscribe("svc", vec![Filter::kinds(&[kind::ANNOUNCE]).recent(3600)]);
    let Some(view) = pool::discover(
        &mut n,
        &arg("--pool").unwrap_or("bitaid".into()),
        secs(num("--setup-wait", 3600u64)),
    ) else {
        n.check("oracle pool found and checked on the relays", false, "");
        return n.summary();
    };
    let okey = view.key_hex();
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
    let my_ballot = ballot_from_args(r.seats.len(), my_seat);
    vote(&mut n, &a, &r, my_ballot.clone());
    // --escalate: if the attending vote does not settle the case, take it to arbitration (§10.1).
    // --appeal: re-roll a verdict that rules against this attendee's claim to the next tier (§10.5),
    // up to --max-tier. Every party follows each tier, including appeals filed by others.
    if flag("--escalate") || flag("--appeal") {
        let ballots = collect_reveals(&mut n, &a, &r);
        if let Decision::Escalate(why) =
            decide(r.seats.len(), a.template.pots, &a.template, &ballots)
        {
            let max_tier = num("--max-tier", 2u32);
            let mut tier = 1;
            let mut verdict = if flag("--escalate") {
                n.check(
                    &format!("attending vote did not settle ({why}); escalating to arbitration"),
                    true,
                    "",
                );
                escalate_tier(&mut n, &a, &view, 1, &why)
            } else {
                n.log(&format!(
                    "attending vote did not settle ({why}); following the arbitration"
                ));
                watch_tier(&mut n, &a, 1, secs(600)).flatten()
            };
            let mut standing: Option<Ballot> = None;
            loop {
                match verdict.take() {
                    Some(v) => standing = Some(v),
                    None => n.log(&format!(
                        "tier {tier}: no two-thirds verdict; {}",
                        if standing.is_some() {
                            "the last verdict stands"
                        } else {
                            "the deadlock stands"
                        }
                    )),
                }
                let Some(v) = standing.clone() else {
                    // a hung first panel leaves the case undecided, like a deadlocked attending vote:
                    // the party that escalated takes it on to the next tier
                    if flag("--escalate") && tier < max_tier {
                        tier += 1;
                        n.check(
                            &format!("no verdict yet; taking the case on to tier {tier}"),
                            true,
                            "",
                        );
                        verdict = escalate_tier(&mut n, &a, &view, tier, "hung panel");
                        continue;
                    }
                    match watch_tier(
                        &mut n,
                        &a,
                        tier + 1,
                        secs(a.template.dispute_window as u64 + 10),
                    ) {
                        Some(v2) => {
                            tier += 1;
                            verdict = v2;
                            continue;
                        }
                        None => break,
                    }
                };
                let mine_ok = v
                    .acts
                    .get(my_seat)
                    .map(|x| x.class == my_ballot.acts[my_seat].class)
                    .unwrap_or(false);
                n.log(&format!(
                    "standing verdict after tier {tier}: {} — {}",
                    verdict_classes(&v),
                    if mine_ok {
                        "upholds my claim"
                    } else {
                        "against my claim"
                    }
                ));
                if !mine_ok && flag("--appeal") && tier < max_tier {
                    tier += 1;
                    n.check(
                        &format!("appealing the verdict against my claim to tier {tier}"),
                        true,
                        "",
                    );
                    verdict = escalate_tier(&mut n, &a, &view, tier, "appeal");
                    continue;
                }
                // another party may appeal within the window; follow it if so
                match watch_tier(
                    &mut n,
                    &a,
                    tier + 1,
                    secs(a.template.dispute_window as u64 + 10),
                ) {
                    Some(v2) => {
                        tier += 1;
                        verdict = v2;
                    }
                    None => break,
                }
            }
        }
    }
    let paid = settle(&mut n, &a, &set, &view, flag("--broadcast"));
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
    if flag("--escalate") || flag("--appeal") {
        collect_seizure(&mut n, &a, &r, &view);
    }
    n.summary()
}

/// After a case is final, the party that paid for its deciding tier collects what the ruling seizes:
/// each incoherent arbitrator's pre-signed forfeiture, co-signed by the pool, moves the penalty from
/// its bond into the case's seizure output; the case's archivists and the pool then co-sign the
/// distribution of §12 (vindicated dissenters, then the appeal subsidy). Every co-signer replays the
/// log and signs only what its own replay calls for.
fn collect_seizure(n: &mut Node, a: &Alerted, r: &Rostered, view: &PoolView) {
    let c = a.case_hex.clone();
    // read whatever is still in flight into the log
    let _ = n.collect(secs(3), |_, _| None::<()>, |_| false);
    let Some(rp) = arb::Replay::build(&n.history, a, r, &n.rpc) else {
        return;
    };
    let Some((ft, _)) = rp.final_ruling() else {
        return;
    };
    if rp.tiers[&ft].escalator != n.me() {
        return;
    }
    let pens = rp.penalties();
    if pens.is_empty() {
        n.log("no incoherent votes against the final ruling; nothing to forfeit");
        return;
    }
    let oxo = rp.oracle;
    let mut session = 100;
    let mut ok_all = true;
    // --greedy (test): also ask the pool to take a penalty from an arbitrator who ruled with the final
    // verdict, and the archivists to sign a distribution paying everything to this party; both must refuse
    if flag("--greedy") {
        let fin = &rp.tiers[&ft];
        let fk = arb::verdict_key(&rp.final_ruling().unwrap().1);
        let coherent = fin
            .reveals
            .iter()
            .find(|x| arb::verdict_key(&x.1) == fk)
            .map(|x| x.0.clone());
        if let (Some(who), Some(spk)) = (coherent, rp.seizure_spk()) {
            let b = fin.offers[&who].clone();
            let (tx, d) = b.penalty_tx(&oxo, 4 * arb::seat_fee(rp.base_fee, ft), &spk);
            let res = pool::cosign(n, view, &c, &serialize_hex(&tx), 0, &d, 900);
            n.check(
                &format!("the pool refuses to co-sign a forfeiture the log does not call for (coherent arbitrator {})", &who[..8]),
                res.is_err(),
                &res.err().unwrap_or_default(),
            );
        }
    }
    for p in &pens {
        let mut tx = p.tx.clone();
        let res = pool::cosign(n, view, &c, &serialize_hex(&tx), 0, &p.digest, session).and_then(
            |(osig, _, signers)| {
                p.bond.witness(
                    &oxo,
                    &mut tx,
                    &hex::decode(&p.pre).unwrap_or_default(),
                    &osig,
                );
                n.rpc.package(&tx).map(|t| (t, signers))
            },
        );
        session += 10;
        ok_all &= res.is_ok();
        let what = format!(
            "tier {} arbitrator {}: {:.1}× the {}-sat fee ({} sats) forfeited from its stake",
            p.tier,
            &p.arbitrator[..8],
            p.step as f64 / 10.0,
            arb::seat_fee(rp.base_fee, p.tier),
            p.amount
        );
        n.check(
            &format!("{what} into the case's seizure output by its pre-signed forfeiture and the pool's co-signature"),
            res.is_ok(),
            &match &res {
                Ok((t, signers)) => format!("{} (pool members {signers:?})", &t.to_string()[..16]),
                Err(e) => e.clone(),
            },
        );
    }
    if !ok_all {
        return;
    }
    n.rpc.mine(1).ok();
    let Some((mut dist, prev)) = rp.distribution(&pens) else {
        return;
    };
    let arch = rp.archivists.clone();
    let need = arch.len() / 2 + 1;
    if flag("--greedy") {
        let mut greedy = dist.clone();
        let total: u64 = greedy.output.iter().map(|o| o.value.to_sat()).sum();
        greedy.output = vec![
            bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(total),
                script_pubkey: r.payout_spks[0].clone(),
            },
            bitcoin::TxOut {
                value: bitcoin::Amount::ZERO,
                script_pubkey: bitaid_core::scripts::p2a(),
            },
        ];
        let gid = greedy.compute_txid().to_string();
        n.send_case(
            &c,
            &arch,
            Msg::SeizureRequest {
                case_id: c.clone(),
                tx: serialize_hex(&greedy),
            },
            false,
        );
        let cc = c.clone();
        let signed = n.wait(secs(20), |env, _| match &env.msg {
            Msg::SeizureSig { case_id, txid, .. } if *case_id == cc && *txid == gid => Some(()),
            _ => None,
        });
        n.check("the archivists refuse to sign a distribution the log does not call for (all to one party)", signed.is_none(), "");
    }
    let txid = dist.compute_txid().to_string();
    n.send_case(
        &c,
        &arch,
        Msg::SeizureRequest {
            case_id: c.clone(),
            tx: serialize_hex(&dist),
        },
        false,
    );
    let (cc, tt, aa) = (c.clone(), txid.clone(), arch.clone());
    let got = n.collect(
        secs(90),
        |env, _| match &env.msg {
            Msg::SeizureSig {
                case_id,
                txid,
                sigs,
            } if *case_id == cc && *txid == tt && aa.contains(&env.sender) => {
                Some((env.sender.clone(), sigs.clone()))
            }
            _ => None,
        },
        |v| v.len() >= need,
    );
    n.check(
        &format!(
            "seizure distribution signed by {} of {} archivist(s) after their own replay",
            got.len(),
            arch.len()
        ),
        got.len() >= need,
        "",
    );
    for i in 0..dist.input.len() {
        let Some(d) = rp.distribution_digest(&dist, &prev, i) else {
            return;
        };
        let mut m: HashMap<bitcoin::XOnlyPublicKey, Vec<u8>> = HashMap::new();
        for (who, sigs) in &got {
            if let (Some(k), Some(g)) = (wire::xonly(who), sigs.get(i)) {
                if arb::schnorr_ok(&k, &d, g) {
                    m.insert(k, hex::decode(g).unwrap());
                }
            }
        }
        match pool::cosign(n, view, &c, &serialize_hex(&dist), i as u32, &d, session) {
            Ok((osig, _, _)) => {
                if rp.distribution_witness(&mut dist, i, &osig, &m).is_none() {
                    n.check(
                        "seizure distribution witness",
                        false,
                        "too few archivist signatures",
                    );
                    return;
                }
            }
            Err(e) => {
                n.check("pool co-signed the seizure distribution", false, &e);
                return;
            }
        }
        session += 10;
    }
    let res = n.rpc.package(&dist);
    n.rpc.mine(1).ok();
    let vind = rp.vindicated();
    let detail: Vec<String> = dist
        .output
        .iter()
        .filter(|o| o.value.to_sat() > 0)
        .map(|o| {
            let who = if vind.iter().any(|v| v.1 == o.script_pubkey) {
                "to a vindicated dissenter"
            } else if r.payout_spks.contains(&o.script_pubkey) {
                "to the appellant (appeal subsidy and excess)"
            } else {
                "to the archivists"
            };
            format!("{} sats {who}", o.value.to_sat())
        })
        .collect();
    let confirmed = res
        .as_ref()
        .map(|t| n.rpc.confirmations(t) > 0)
        .unwrap_or(false);
    n.check(
        &format!(
            "seizure output distributed (§12) by the pool and the archivists: {}",
            detail.join(", ")
        ),
        confirmed,
        &match &res {
            Ok(t) => t.to_string()[..16].to_string(),
            Err(e) => e.clone(),
        },
    );
}

#[allow(dead_code)]
fn unused(_: OutPoint) -> Option<Scalar> {
    scalar_from("")
}
