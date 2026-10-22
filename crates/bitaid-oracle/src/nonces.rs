//! Nonce batches (Specification B.3 "Nonces"). For every index j of a batch, each member deals a random
//! polynomial of degree t−1 with Feldman commitments and sends every other member its share privately;
//! each recipient checks every share against the dealer's commitments. A dealer whose share fails is
//! disqualified for the batch unless it publishes the disputed share and that share verifies. The nonce
//! k_j is the sum of the qualified dealers' constant terms: nobody knows it, any t members hold shares
//! of it, and everyone can compute R_j and each member's public nonce share R_{j,i}. Each R_j is
//! normalised to even y (all shares negated where needed), as BIP340 requires.
use musig2::secp::{MaybePoint, MaybeScalar, Point, Scalar, G};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

fn sc(x: u16) -> Scalar {
    Scalar::try_from(x as u128).unwrap()
}

/// What one dealer broadcasts for a batch: commitments C_{j,k} = a_{j,k}·G.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Commitments {
    pub dealer: u16,
    pub batch: u64,
    pub c: Vec<Vec<Point>>, // [j][k]
}

/// What one dealer sends privately to member `to`: f_j(to) for every j.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Shares {
    pub dealer: u16,
    pub to: u16,
    pub batch: u64,
    pub s: Vec<Scalar>,
}

pub struct Dealer {
    pub id: u16,
    poly: Vec<Vec<Scalar>>, // [j][k]
}

impl Batch {
    pub fn public(&self) -> BatchPublic {
        BatchPublic {
            batch: self.batch,
            qualified: self.qualified.clone(),
            r: self.r.clone(),
            public: self.public.clone(),
        }
    }
}

impl Dealer {
    pub fn new(id: u16, batch_size: usize, t: u16) -> Self {
        let poly = (0..batch_size)
            .map(|_| {
                (0..t)
                    .map(|_| bitaid_core::oracle::random_scalar())
                    .collect()
            })
            .collect();
        Dealer { id, poly }
    }
    pub fn commitments(&self, batch: u64) -> Commitments {
        Commitments {
            dealer: self.id,
            batch,
            c: self
                .poly
                .iter()
                .map(|p| p.iter().map(|a| *a * G).collect())
                .collect(),
        }
    }
    pub fn shares_for(&self, to: u16, batch: u64) -> Shares {
        let x = sc(to);
        let s = self
            .poly
            .iter()
            .map(|p| {
                let mut acc = MaybeScalar::Zero;
                for a in p.iter().rev() {
                    acc = acc * x + *a;
                }
                acc.not_zero().expect("nonzero share (negligible failure)")
            })
            .collect();
        Shares {
            dealer: self.id,
            to,
            batch,
            s,
        }
    }
}

/// `Σ_k C_k · i^k`: the public image of dealer's share for member i.
pub fn eval_commit(c: &[Point], i: u16) -> MaybePoint {
    let x = sc(i);
    let mut acc = MaybePoint::Infinity;
    for ck in c.iter().rev() {
        acc = acc * x + *ck;
    }
    acc
}

pub fn verify_share(c: &Commitments, s: &Shares) -> bool {
    c.c.len() == s.s.len()
        && c.c
            .iter()
            .zip(&s.s)
            .all(|(cj, sj)| eval_commit(cj, s.to) == MaybePoint::from(*sj * G))
}

/// The public side of a batch: nonce points and every member's public nonce shares.
#[derive(Clone, Debug)]
pub struct BatchPublic {
    pub batch: u64,
    pub qualified: BTreeSet<u16>,
    pub r: Vec<Point>,
    pub public: Vec<BTreeMap<u16, Point>>,
}

/// Computes the public side of a batch from the dealers' broadcast commitments alone.
pub fn public_view(
    members: &[u16],
    commits: &BTreeMap<u16, Commitments>,
    qualified: &BTreeSet<u16>,
) -> BatchPublic {
    let b = commits.values().next().unwrap();
    let mut r = Vec::new();
    let mut public = Vec::new();
    for j in 0..b.c.len() {
        // sum the qualified dealers' commitments coefficient by coefficient, then evaluate once per member
        let t = b.c[j].len();
        let agg: Vec<Point> = (0..t)
            .map(|k| {
                let mut acc = MaybePoint::Infinity;
                for d in qualified {
                    acc += commits[d].c[j][k];
                }
                acc.not_inf().expect("commitment")
            })
            .collect();
        let rj = agg[0];
        let flip = !rj.has_even_y();
        let mut pubs = BTreeMap::new();
        for &i in members {
            let p = eval_commit(&agg, i).not_inf().expect("public share");
            pubs.insert(i, if flip { -p } else { p });
        }
        r.push(if flip { -rj } else { rj });
        public.push(pubs);
    }
    BatchPublic {
        batch: b.batch,
        qualified: qualified.clone(),
        r,
        public,
    }
}

/// One member's view of a completed batch.
#[derive(Clone, Debug)]
pub struct Batch {
    pub batch: u64,
    pub me: u16,
    pub qualified: BTreeSet<u16>,
    /// R_j for each index, even y.
    pub r: Vec<Point>,
    /// This member's secret share k_{j,me}.
    pub mine: Vec<Scalar>,
    /// Public nonce shares R_{j,i} for every member i (sign-adjusted with R_j).
    pub public: Vec<BTreeMap<u16, Point>>,
    /// Indices already spent on an attestation, with the message they were spent on.
    pub spent: BTreeMap<usize, [u8; 32]>,
}

/// Combines what member `me` received. `commits`: every dealer's broadcast; `received`: the shares
/// dealt to `me`; `qualified`: dealers not disqualified (agreed through complaints on the network).
pub fn finish(
    me: u16,
    members: &[u16],
    commits: &BTreeMap<u16, Commitments>,
    received: &BTreeMap<u16, Shares>,
    qualified: &BTreeSet<u16>,
) -> Batch {
    let pv = public_view(members, commits, qualified);
    let mut mine = Vec::with_capacity(pv.r.len());
    for j in 0..pv.r.len() {
        let mut kj = MaybeScalar::Zero;
        for d in qualified {
            kj += received[d].s[j];
        }
        let kj = kj.not_zero().expect("share");
        // R_j was negated in the public view if it had odd y; negate the share to match
        let raw: MaybePoint = qualified
            .iter()
            .fold(MaybePoint::Infinity, |a, d| a + commits[d].c[j][0]);
        mine.push(if raw == MaybePoint::from(pv.r[j]) {
            kj
        } else {
            -kj
        });
    }
    Batch {
        batch: pv.batch,
        me,
        qualified: qualified.clone(),
        r: pv.r,
        mine,
        public: pv.public,
        spent: BTreeMap::new(),
    }
}

/// Runs a whole batch in one process: every member deals, every share is verified, and every member
/// derives its view. `bad_dealer` deals one corrupted share to test disqualification.
pub fn run_local(
    members: &[u16],
    t: u16,
    size: usize,
    batch: u64,
    bad_dealer: Option<u16>,
) -> (Vec<Batch>, BTreeSet<u16>) {
    let dealers: Vec<Dealer> = members.iter().map(|&d| Dealer::new(d, size, t)).collect();
    let commits: BTreeMap<u16, Commitments> = dealers
        .iter()
        .map(|d| (d.id, d.commitments(batch)))
        .collect();
    let mut qualified: BTreeSet<u16> = members.iter().copied().collect();
    let mut inbox: BTreeMap<u16, BTreeMap<u16, Shares>> = BTreeMap::new();
    for d in &dealers {
        for &to in members {
            let mut s = d.shares_for(to, batch);
            if Some(d.id) == bad_dealer && to == members[0] {
                s.s[0] = (s.s[0] + Scalar::one()).not_zero().unwrap();
            }
            if !verify_share(&commits[&d.id], &s) {
                qualified.remove(&d.id); // complaint upheld: the dealer cannot publish a share that verifies
            }
            inbox.entry(to).or_default().insert(d.id, s);
        }
    }
    let views = members
        .iter()
        .map(|&m| finish(m, members, &commits, &inbox[&m], &qualified))
        .collect();
    (views, qualified)
}
