//! The oracle pool behind the node (Specification §3.3, B.3), over the same relays as everything else.
//!
//! Members run the FROST key generation and one Feldman-verified nonce batch on stored (non-ephemeral)
//! announcement events, so callers and responders that start later read the pool's public data from
//! the relays and check it themselves. In service:
//! * a caller proposes nonce indices for its case and needs t members to reserve them;
//! * a caller coordinates the FROST co-signature of the incident transaction, every member checking the
//!   transaction against the case before committing, and a member that commits but stalls is replaced;
//! * every member replays the case's ballots itself and releases its attestation share in public;
//!   anyone combines t valid shares, and a share for any other outcome is signed evidence against
//!   the member who released it. No member, and no coordinator, can attest alone.
use crate::node::{point_hex, Node};
use crate::nostr::{kind, Filter};
use crate::wire::{self, Msg};
use bitaid_oracle::attest::{self, Share};
use bitaid_oracle::conv;
use bitaid_oracle::keygen::{MemberKey, PoolPublic};
use bitaid_oracle::nonces::{self, Batch, BatchPublic, Commitments};
use frost_secp256k1_tr as frost;
use musig2::secp::{Point, Scalar};
use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

/// What a non-member needs: the pool key, every member's identity, and the nonce batch's public side.
#[derive(Clone)]
pub struct PoolView {
    pub name: String,
    pub t: usize,
    pub members: Vec<u16>,
    /// member id -> identity key (hex x-only)
    pub ids: BTreeMap<u16, String>,
    pub public: PoolPublic,
    pub batch: BatchPublic,
}

impl PoolView {
    /// The pool key as it appears in scripts (x-only, hex).
    pub fn key_hex(&self) -> String {
        hex::encode(self.public.xonly())
    }
    pub fn member_of(&self, identity: &str) -> Option<u16> {
        self.ids
            .iter()
            .find(|(_, v)| v.as_str() == identity)
            .map(|(k, _)| *k)
    }
    pub fn identities(&self) -> Vec<String> {
        self.members.iter().map(|m| self.ids[m].clone()).collect()
    }
}

fn pool_tags(name: &str) -> Vec<Vec<String>> {
    vec![vec!["pool".into(), name.into()]]
}

fn send_pool(n: &mut Node, name: &str, m: Msg) {
    n.send(kind::ANNOUNCE, pool_tags(name), m, None);
}

/// Reads the pool's setup from the relays and checks it: every listed member ready with the same key
/// and qualified dealers, the nonce batch rebuilt from the dealers' commitments.
pub fn discover(n: &mut Node, name: &str, timeout: Duration) -> Option<PoolView> {
    n.subscribe(
        "pool-view",
        vec![Filter::kinds(&[kind::ANNOUNCE]).recent(3600)],
    );
    let nm = name.to_string();
    let end = Instant::now() + timeout;
    let mut hello: BTreeMap<u16, (String, u16)> = BTreeMap::new(); // member -> (identity, t)
    let mut ready: BTreeMap<u16, (String, String, Vec<u16>, Vec<u16>)> = BTreeMap::new();
    let mut commits: BTreeMap<String, Commitments> = BTreeMap::new(); // by sender identity
    loop {
        let left = end.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return None;
        }
        let env = n.wait(left, |env, _| match &env.msg {
            Msg::PoolHello { pool, .. }
            | Msg::PoolReady { pool, .. }
            | Msg::PoolNonceCommit { pool, .. }
                if *pool == nm =>
            {
                Some(env.clone())
            }
            _ => None,
        })?;
        match env.msg {
            Msg::PoolHello { member, t, .. } => {
                hello.insert(member, (env.sender.clone(), t));
            }
            Msg::PoolReady {
                member,
                key,
                public,
                members,
                qualified,
                ..
            } => {
                ready.insert(
                    member,
                    (
                        env.sender.clone(),
                        format!("{key}|{public}"),
                        members,
                        qualified,
                    ),
                );
            }
            Msg::PoolNonceCommit { commitments, .. } => {
                if let Ok(c) = serde_json::from_str::<Commitments>(&commitments) {
                    commits.insert(env.sender.clone(), c);
                }
            }
            _ => {}
        }
        let Some((_, first, members, qualified)) = ready.values().next().cloned() else {
            continue;
        };
        if ready.len() < members.len() {
            continue;
        }
        // every member ready, from the identity it said hello with, agreeing on key, public data and dealers
        let agree = ready.iter().all(|(m, (id, kp, ms, q))| {
            *kp == first
                && *ms == members
                && *q == qualified
                && hello.get(m).map(|h| &h.0) == Some(id)
        });
        if !agree {
            n.log("pool setup: members disagree; not using this pool");
            return None;
        }
        let ids: BTreeMap<u16, String> = members.iter().map(|m| (*m, hello[m].0.clone())).collect();
        // a dealer's commitments count only if published by that dealer's own identity
        let by_dealer: BTreeMap<u16, Commitments> = commits
            .iter()
            .filter(|(sender, c)| ids.get(&c.dealer) == Some(*sender))
            .map(|(_, c)| (c.dealer, c.clone()))
            .collect();
        let q: BTreeSet<u16> = qualified.iter().copied().collect();
        if !q.iter().all(|d| by_dealer.contains_key(d)) {
            continue; // commitments still arriving
        }
        let public = frost::keys::PublicKeyPackage::deserialize(
            &hex::decode(first.split('|').nth(1)?).ok()?,
        )
        .ok()?;
        let batch = nonces::public_view(&members, &by_dealer, &q);
        let t = hello[&members[0]].1 as usize;
        return Some(PoolView {
            name: name.into(),
            t,
            members,
            ids,
            public: PoolPublic { public },
            batch,
        });
    }
}

// =================================================================== member

pub struct MemberCfg {
    pub name: String,
    pub id: u16,
    pub n: u16,
    pub t: u16,
    pub batch: usize,
    pub stall: bool,
    pub liar: bool,
    pub wait: Duration,
}

pub struct Member {
    pub cfg: MemberCfg,
    pub key: MemberKey,
    pub batch: Batch,
    pub view: PoolView,
}

fn collect_pool<T>(
    n: &mut Node,
    name: &str,
    want: usize,
    wait: Duration,
    mut f: impl FnMut(&wire::Envelope) -> Option<(u16, T)>,
) -> BTreeMap<u16, T> {
    let nm = name.to_string();
    let mut out = BTreeMap::new();
    let end = Instant::now() + wait;
    while out.len() < want {
        let left = end.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        let got = n.wait(left, |env, e| {
            if e.tag("pool") != Some(nm.as_str()) {
                return None;
            }
            f(env)
        });
        match got {
            Some((k, v)) => {
                out.insert(k, v);
            }
            None => break,
        }
    }
    out
}

/// Key generation and the nonce batch, over the relays.
pub fn setup(n: &mut Node, cfg: MemberCfg) -> Result<Member, String> {
    let name = cfg.name.clone();
    let me = cfg.id;
    n.subscribe(
        "pool-setup",
        vec![Filter::kinds(&[kind::ANNOUNCE]).recent(3600)],
    );
    std::thread::sleep(Duration::from_millis(300));
    send_pool(
        n,
        &name,
        Msg::PoolHello {
            pool: name.clone(),
            member: me,
            n: cfg.n,
            t: cfg.t,
        },
    );
    // the newest hello per member wins: a member that restarted (or a stale process left from an
    // earlier run) said hello under another identity, and only the newest one is still listening.
    // Once all are present, a short grace lets a newer hello replace an older one.
    let mut seen: BTreeMap<u16, (u64, wire::Hex32)> = BTreeMap::new();
    let end = Instant::now() + cfg.wait;
    let mut grace: Option<Instant> = None;
    loop {
        let stop = grace.unwrap_or(end).min(end);
        let left = stop.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        let got = n.wait(left, |env, e| {
            if e.tag("pool") != Some(name.as_str()) {
                return None;
            }
            match &env.msg {
                Msg::PoolHello { member, .. } => Some((*member, e.created_at, env.sender.clone())),
                _ => None,
            }
        });
        let Some((m, at, who)) = got else { break };
        if seen.get(&m).map_or(true, |(t, _)| at >= *t) {
            seen.insert(m, (at, who));
        }
        if grace.is_none() && seen.len() >= cfg.n as usize {
            grace = Some(Instant::now() + Duration::from_secs(10));
        }
    }
    let hellos: BTreeMap<u16, wire::Hex32> = seen.into_iter().map(|(m, (_, w))| (m, w)).collect();
    if hellos.len() < cfg.n as usize {
        return Err(format!(
            "only {} of {} members said hello",
            hellos.len(),
            cfg.n
        ));
    }
    let members: Vec<u16> = hellos.keys().copied().collect();
    let idx = |m: u16| wire::xonly(&hellos[&m]).unwrap();
    n.log("all pool members present");
    // ---- FROST DKG
    let mut rng = rand::thread_rng();
    let (s1, p1) =
        frost::keys::dkg::part1(conv::id(me), cfg.n, cfg.t, &mut rng).map_err(|e| e.to_string())?;
    send_pool(
        n,
        &name,
        Msg::PoolDkg1 {
            pool: name.clone(),
            member: me,
            package: hex::encode(p1.serialize().unwrap()),
        },
    );
    let ids = hellos.clone();
    let r1 = collect_pool(n, &name, cfg.n as usize - 1, cfg.wait, |env| {
        match &env.msg {
            Msg::PoolDkg1 {
                member, package, ..
            } if *member != me && ids.get(member) == Some(&env.sender) => {
                frost::keys::dkg::round1::Package::deserialize(&hex::decode(package).ok()?)
                    .ok()
                    .map(|p| (*member, p))
            }
            _ => None,
        }
    });
    let r1: BTreeMap<frost::Identifier, _> =
        r1.into_iter().map(|(m, p)| (conv::id(m), p)).collect();
    let (s2, out) = frost::keys::dkg::part2(s1, &r1).map_err(|e| e.to_string())?;
    // every other member's share, each sealed to it, in one message (relays rate-limit bursts)
    let mut bundle = vec![];
    for (to, pkg) in out {
        let to_n = *members.iter().find(|&&i| conv::id(i) == to).unwrap();
        let aad = format!("{name}/dkg2/{me}/{to_n}");
        let sealed = wire::seal(
            &n.keys,
            &idx(to_n),
            aad.as_bytes(),
            &pkg.serialize().unwrap(),
        );
        bundle.push((to_n, hex::encode(sealed)));
    }
    send_pool(
        n,
        &name,
        Msg::PoolDkg2 {
            pool: name.clone(),
            from: me,
            sealed: bundle,
        },
    );
    let keys = n.keys;
    let r2 = collect_pool(n, &name, cfg.n as usize - 1, cfg.wait, |env| {
        match &env.msg {
            Msg::PoolDkg2 { from, sealed, .. }
                if *from != me && ids.get(from) == Some(&env.sender) =>
            {
                let mine = &sealed.iter().find(|(to, _)| *to == me)?.1;
                let aad = format!("{name}/dkg2/{from}/{me}");
                let pt = wire::unseal(
                    &keys,
                    &wire::xonly(&env.sender)?,
                    aad.as_bytes(),
                    &hex::decode(mine).ok()?,
                )?;
                frost::keys::dkg::round2::Package::deserialize(&pt)
                    .ok()
                    .map(|p| (*from, p))
            }
            _ => None,
        }
    });
    let r2: BTreeMap<frost::Identifier, _> =
        r2.into_iter().map(|(m, p)| (conv::id(m), p)).collect();
    let (kp, pp) =
        frost::keys::dkg::part3(&s2, &r1, &r2).map_err(|e| format!("key generation: {e}"))?;
    let key = MemberKey {
        id: me,
        key_package: kp,
        public: pp,
    };
    n.log(&format!("pool key {}", hex::encode(key.xonly())));
    // ---- nonce batch
    let dealer = nonces::Dealer::new(me, cfg.batch, cfg.t);
    let mine_c = dealer.commitments(1);
    send_pool(
        n,
        &name,
        Msg::PoolNonceCommit {
            pool: name.clone(),
            commitments: serde_json::to_string(&mine_c).unwrap(),
        },
    );
    let mut bundle = vec![];
    for &to in &members {
        if to != me {
            let sh = serde_json::to_vec(&dealer.shares_for(to, 1)).unwrap();
            let aad = format!("{name}/nonce/{me}/{to}");
            bundle.push((
                to,
                hex::encode(wire::seal(&n.keys, &idx(to), aad.as_bytes(), &sh)),
            ));
        }
    }
    send_pool(
        n,
        &name,
        Msg::PoolNonceShare {
            pool: name.clone(),
            from: me,
            sealed: bundle,
        },
    );
    let mut commits = collect_pool(n, &name, cfg.n as usize - 1, cfg.wait, |env| {
        match &env.msg {
            Msg::PoolNonceCommit { commitments, .. } => {
                let c: Commitments = serde_json::from_str(commitments).ok()?;
                (c.dealer != me && ids.get(&c.dealer) == Some(&env.sender)).then_some((c.dealer, c))
            }
            _ => None,
        }
    });
    commits.insert(me, mine_c);
    let shares = collect_pool(n, &name, cfg.n as usize - 1, cfg.wait, |env| {
        match &env.msg {
            Msg::PoolNonceShare { from, sealed, .. }
                if *from != me && ids.get(from) == Some(&env.sender) =>
            {
                let mine = &sealed.iter().find(|(to, _)| *to == me)?.1;
                let aad = format!("{name}/nonce/{from}/{me}");
                let pt = wire::unseal(
                    &keys,
                    &wire::xonly(&env.sender)?,
                    aad.as_bytes(),
                    &hex::decode(mine).ok()?,
                );
                Some((
                    *from,
                    pt.and_then(|p| serde_json::from_slice::<nonces::Shares>(&p).ok()),
                ))
            }
            _ => None,
        }
    });
    let mut received = BTreeMap::new();
    received.insert(me, dealer.shares_for(me, 1));
    let mut bad = vec![];
    for m in &members {
        if *m == me {
            continue;
        }
        match shares.get(m).cloned().flatten() {
            Some(s)
                if commits
                    .get(m)
                    .map(|c| nonces::verify_share(c, &s))
                    .unwrap_or(false) =>
            {
                received.insert(*m, s);
            }
            _ => bad.push(*m),
        }
    }
    send_pool(
        n,
        &name,
        Msg::PoolNonceStatus {
            pool: name.clone(),
            member: me,
            bad: bad.clone(),
        },
    );
    let statuses = collect_pool(n, &name, cfg.n as usize - 1, cfg.wait, |env| {
        match &env.msg {
            Msg::PoolNonceStatus { member, bad, .. }
                if *member != me && ids.get(member) == Some(&env.sender) =>
            {
                Some((*member, bad.clone()))
            }
            _ => None,
        }
    });
    let mut qualified: BTreeSet<u16> = members.iter().copied().collect();
    for b in bad.iter().chain(statuses.values().flatten()) {
        qualified.remove(b);
    }
    let batch = nonces::finish(me, &members, &commits, &received, &qualified);
    let public_hex = hex::encode(key.public.serialize().unwrap());
    send_pool(
        n,
        &name,
        Msg::PoolReady {
            pool: name.clone(),
            member: me,
            key: hex::encode(key.xonly()),
            public: public_hex,
            members: members.clone(),
            qualified: qualified.iter().copied().collect(),
        },
    );
    n.log(&format!(
        "pool ready: {} nonces, qualified dealers {:?}",
        cfg.batch, qualified
    ));
    let view = PoolView {
        name: name.clone(),
        t: cfg.t as usize,
        members: members.clone(),
        ids: hellos.clone(),
        public: key.pool(),
        batch: batch.public(),
    };
    Ok(Member {
        cfg,
        key,
        batch,
        view,
    })
}

impl Member {
    /// This member's FROST commitment for a co-signing session, after checking what it will sign.
    pub fn commit(&self) -> (frost::round1::SigningNonces, String) {
        let (nonces, c) = frost::round1::commit(
            self.key.key_package.signing_share(),
            &mut rand::thread_rng(),
        );
        (nonces, hex::encode(c.serialize().unwrap()))
    }

    /// Signs a package only if its message is the digest this member already checked.
    pub fn sign(
        &self,
        package_hex: &str,
        nonces: &frost::round1::SigningNonces,
        digest: &[u8; 32],
    ) -> Result<String, &'static str> {
        let pkg = hex::decode(package_hex)
            .ok()
            .and_then(|b| frost::SigningPackage::deserialize(&b).ok())
            .ok_or("unreadable package")?;
        if !pkg
            .signing_commitments()
            .contains_key(&conv::id(self.key.id))
        {
            return Err("this member was not chosen for the session");
        }
        if pkg.message() != digest {
            return Err("not the digest this member checked");
        }
        let sh = frost::round2::sign(&pkg, nonces, &self.key.key_package)
            .map_err(|_| "signing failed")?;
        Ok(hex::encode(sh.serialize()))
    }

    /// The public attestation share for outcome `m` on nonce `index`; refuses a second outcome.
    pub fn attest(&mut self, index: usize, m: &[u8; 32]) -> Result<String, &'static str> {
        let mut msg = *m;
        if self.cfg.liar {
            msg[31] ^= 1;
        }
        let sh = attest::share(&self.key, &mut self.batch, index, &msg)?;
        Ok(serde_json::to_string(&sh).unwrap())
    }
}

// =================================================================== client side

/// Proposes unused nonce indices for the three pots and waits until t members reserve them.
pub fn reserve_nonces(
    n: &mut Node,
    view: &PoolView,
    case: &str,
) -> Result<(Vec<u32>, Vec<Point>), String> {
    let size = view.batch.r.len() as u32;
    for attempt in 0..4 {
        let mut idx: Vec<u32> = Vec::new();
        while idx.len() < 3 {
            let j = rand::random::<u32>() % size;
            if !idx.contains(&j) {
                idx.push(j);
            }
        }
        n.send_case(
            case,
            &view.identities(),
            Msg::NonceRequest {
                case_id: case.into(),
                indices: idx.clone(),
            },
            false,
        );
        let (c, v, want) = (case.to_string(), view.clone(), idx.clone());
        let acks = n.collect(
            Duration::from_secs(20),
            |env, _| match &env.msg {
                Msg::NonceAssignment {
                    case_id,
                    member,
                    indices,
                    nonces,
                } if *case_id == c
                    && *indices == want
                    && v.member_of(&env.sender) == Some(*member) =>
                {
                    // the points must be the batch's own
                    let ok = indices.iter().zip(nonces).all(|(j, r)| {
                        v.batch.r.get(*j as usize).map(point_hex).as_deref() == Some(r.as_str())
                    });
                    ok.then_some(*member)
                }
                _ => None,
            },
            |got| got.len() >= v.members.len(),
        );
        if acks.len() >= view.t {
            n.log(&format!(
                "nonces {idx:?} reserved by {} of {} members",
                acks.len(),
                view.members.len()
            ));
            return Ok((
                idx.clone(),
                idx.iter().map(|j| view.batch.r[*j as usize]).collect(),
            ));
        }
        n.log(&format!(
            "attempt {attempt}: only {} members reserved {idx:?}; trying other indices",
            acks.len()
        ));
    }
    Err("the pool did not reserve nonces".into())
}

/// Coordinates a FROST co-signature over `digest` (ROAST-style: stallers are excluded and replaced).
/// Returns the signature, the sessions used and the signers.
/// `input` is the input co-signed; `first` the first session number (each transaction a caller has
/// co-signed uses its own range of sessions).
#[allow(clippy::too_many_arguments)]
pub fn cosign(
    n: &mut Node,
    view: &PoolView,
    case: &str,
    tx_hex: &str,
    input: u32,
    digest: &[u8; 32],
    first: u32,
) -> Result<([u8; 64], u32, Vec<u16>), String> {
    cosign_tries(n, view, case, tx_hex, input, digest, first, 4)
}

/// `cosign` with at most `tries` sessions (one, to test a refusal at a given moment).
#[allow(clippy::too_many_arguments)]
pub fn cosign_tries(
    n: &mut Node,
    view: &PoolView,
    case: &str,
    tx_hex: &str,
    input: u32,
    digest: &[u8; 32],
    first: u32,
    tries: u32,
) -> Result<([u8; 64], u32, Vec<u16>), String> {
    let mut excluded: BTreeSet<u16> = BTreeSet::new();
    for session in first..first + tries {
        n.send_case(
            case,
            &view.identities(),
            Msg::CosignRequest {
                case_id: case.into(),
                session,
                tx: tx_hex.into(),
                input,
            },
            false,
        );
        let (c, v, ex) = (case.to_string(), view.clone(), excluded.clone());
        let commits = n.collect(
            Duration::from_secs(30),
            |env, _| match &env.msg {
                Msg::PoolCommit {
                    case_id,
                    session: s,
                    member,
                    commitment,
                } if *case_id == c
                    && *s == session
                    && v.member_of(&env.sender) == Some(*member)
                    && !ex.contains(member) =>
                {
                    frost::round1::SigningCommitments::deserialize(&hex::decode(commitment).ok()?)
                        .ok()
                        .map(|x| (*member, x))
                }
                _ => None,
            },
            |got| got.len() >= v.t,
        );
        if commits.len() < view.t {
            // members still busy (replaying the case, on a slow link) may answer the next session
            if session + 1 < first + 4 {
                n.log(&format!(
                    "session {session}: only {} members committed; trying again",
                    commits.len()
                ));
                continue;
            }
            return Err(format!("only {} members committed", commits.len()));
        }
        let chosen: Vec<u16> = commits.iter().map(|x| x.0).collect();
        let cm: BTreeMap<frost::Identifier, _> =
            commits.into_iter().map(|(m, x)| (conv::id(m), x)).collect();
        let package = frost::SigningPackage::new(cm, digest);
        n.send_case(
            case,
            &view.identities(),
            Msg::PoolPackage {
                case_id: case.into(),
                session,
                package: hex::encode(package.serialize().unwrap()),
            },
            false,
        );
        let (c, v, ch) = (case.to_string(), view.clone(), chosen.clone());
        let shares = n.collect(
            Duration::from_secs(6),
            |env, _| match &env.msg {
                Msg::PoolSigShare {
                    case_id,
                    session: s,
                    member,
                    share,
                } if *case_id == c
                    && *s == session
                    && ch.contains(member)
                    && v.member_of(&env.sender) == Some(*member) =>
                {
                    frost::round2::SignatureShare::deserialize(&hex::decode(share).ok()?)
                        .ok()
                        .map(|x| (*member, x))
                }
                _ => None,
            },
            |got| got.len() >= ch.len(),
        );
        if shares.len() < chosen.len() {
            for m in &chosen {
                if !shares.iter().any(|x| x.0 == *m) {
                    n.log(&format!(
                        "pool member {m} committed but did not sign session {session}; replaced"
                    ));
                    excluded.insert(*m);
                }
            }
            continue;
        }
        let sh: BTreeMap<frost::Identifier, _> =
            shares.into_iter().map(|(m, x)| (conv::id(m), x)).collect();
        let sig =
            frost::aggregate(&package, &sh, &view.public.public).map_err(|e| e.to_string())?;
        let mut out = [0u8; 64];
        out.copy_from_slice(&sig.serialize().unwrap());
        return Ok((out, session, chosen));
    }
    Err("no session completed".into())
}

/// Collects attestation shares for a case until every pot has t valid shares for one outcome.
/// Returns, per pot, the outcome message and the combined scalar; `notes` names members whose valid
/// shares were for a different outcome than the one that combined (signed evidence against them).
/// Per pot: the attested outcome message and the combined scalar.
pub type Attested = BTreeMap<u8, ([u8; 32], Scalar)>;

pub fn attestations(
    n: &mut Node,
    view: &PoolView,
    case: &str,
    pots: &[u8],
    indices: &[u32],
    timeout: Duration,
) -> (Attested, Vec<String>) {
    let mut by_pot: BTreeMap<u8, Vec<Share>> = BTreeMap::new();
    let mut done: BTreeMap<u8, ([u8; 32], Scalar)> = BTreeMap::new();
    let mut notes = vec![];
    let end = Instant::now() + timeout;
    // once every pot has combined, keep listening (20 s: over Tor a member can lag) for the remaining members' shares: a valid
    // share for another outcome is evidence against its member and is recorded, not ignored
    let mut linger: Option<Instant> = None;
    loop {
        let all_in =
            by_pot.values().map(|v| v.len()).sum::<usize>() >= pots.len() * view.members.len();
        if done.len() == pots.len() {
            let l = *linger.get_or_insert(Instant::now() + Duration::from_secs(20));
            if all_in || Instant::now() >= l {
                break;
            }
        }
        let left = end.saturating_duration_since(Instant::now());
        let left = match linger {
            Some(l) => left.min(l.saturating_duration_since(Instant::now())),
            None => left,
        };
        if left.is_zero() {
            if done.len() == pots.len() {
                break;
            }
            if Instant::now() >= end {
                break;
            }
            continue;
        }
        let (c, v) = (case.to_string(), view.clone());
        // t members saying the deadlock stands end the wait: no attestation will come
        let dead: BTreeSet<u16> = n
            .history
            .iter()
            .filter(|e| matches!(&e.msg, Msg::Deadlock { case_id } if *case_id == c))
            .filter_map(|e| v.member_of(&e.sender))
            .collect();
        if dead.len() >= v.t {
            notes.push(
                "deadlock: no verdict at any tier; the case closes by its refund locktime".into(),
            );
            break;
        }
        let Some((pot, sh)) = n.wait(left.min(Duration::from_secs(2)), |env, _| match &env.msg {
            Msg::AttestShare {
                case_id,
                pot,
                share,
            } if *case_id == c => {
                let sh: Share = serde_json::from_str(share).ok()?;
                (v.member_of(&env.sender) == Some(sh.member)).then_some((*pot, sh))
            }
            _ => None,
        }) else {
            if done.len() == pots.len() || Instant::now() >= end {
                break;
            }
            continue;
        };
        if indices.get(pot as usize).map(|j| *j as usize) != Some(sh.index) {
            notes.push(format!(
                "member {}: share on a nonce not assigned to this pot, ignored",
                sh.member
            ));
            continue;
        }
        if !attest::verify(&view.public, &view.batch, &sh) {
            notes.push(format!("member {}: invalid share, rejected", sh.member));
            continue;
        }
        let list = by_pot.entry(pot).or_default();
        list.push(sh.clone());
        if done.contains_key(&pot) {
            continue;
        }
        let msgs: BTreeSet<[u8; 32]> = list.iter().map(|s| s.message).collect();
        for m in msgs {
            if let Ok(s) = attest::combine(&view.public, &view.batch, list, &m, view.t) {
                done.insert(pot, (m, s));
                break;
            }
        }
    }
    for (pot, list) in &by_pot {
        if let Some((m, _)) = done.get(pot) {
            for s in list.iter().filter(|s| &s.message != m) {
                notes.push(format!("pool member {}: valid share for a different outcome on pot {pot} — signed evidence against it", s.member));
            }
        }
    }
    (done, notes)
}
