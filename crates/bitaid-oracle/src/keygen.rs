//! The pool key by distributed key generation (FROST DKG, Specification B.3 "Key").
//!
//! Three steps per member: `part1` broadcasts commitments and a proof of knowledge; `part2` sends each
//! other member its share privately; `part3` verifies every share received against the dealers'
//! commitments and derives the member's key share and every member's public verifying share. The
//! result is tweaked as BIP86 prescribes, so the pool key used in scripts is the tweaked key Q.
use crate::conv;
use frost_secp256k1_tr as frost;
use musig2::secp::{Point, Scalar};
use std::collections::BTreeMap;

/// The pool's public data: what anyone needs to verify attestation shares and co-signatures.
#[derive(Clone)]
pub struct PoolPublic {
    pub public: frost::keys::PublicKeyPackage,
}

impl PoolPublic {
    pub fn pool_key(&self) -> Point {
        conv::group_key(&self.public)
    }
    /// The pool key with even y, as BIP340 attestations use it.
    pub fn even_key(&self) -> Point {
        let q = self.pool_key();
        if q.has_even_y() {
            q
        } else {
            -q
        }
    }
    /// Member `i`'s public share, sign-adjusted to interpolate to the even-y key.
    pub fn attest_public(&self, i: u16) -> Point {
        let p = conv::verifying_share(&self.public, i);
        if self.pool_key().has_even_y() {
            p
        } else {
            -p
        }
    }
    pub fn xonly(&self) -> [u8; 32] {
        self.pool_key().serialize_xonly()
    }
}

/// One member's result: its secret share and the pool's public data.
#[derive(Clone)]
pub struct MemberKey {
    pub id: u16,
    pub key_package: frost::keys::KeyPackage,
    pub public: frost::keys::PublicKeyPackage,
}

impl MemberKey {
    pub fn pool(&self) -> PoolPublic {
        PoolPublic {
            public: self.public.clone(),
        }
    }
    /// The pool key Q as used in scripts (x-only) and for attestations (with even y).
    pub fn pool_key(&self) -> Point {
        conv::group_key(&self.public)
    }
    /// This member's share, sign-adjusted so the shares interpolate to the even-y form of Q.
    pub fn attest_share(&self) -> Scalar {
        let x = conv::share_scalar(&self.key_package);
        if self.pool_key().has_even_y() {
            x
        } else {
            -x
        }
    }
    /// Member `i`'s public share, sign-adjusted the same way.
    pub fn attest_public(&self, i: u16) -> Point {
        let p = conv::verifying_share(&self.public, i);
        if self.pool_key().has_even_y() {
            p
        } else {
            -p
        }
    }
    pub fn xonly(&self) -> [u8; 32] {
        self.pool_key().serialize_xonly()
    }
}

/// Runs the whole DKG in one process (tests, tools). On the network each member runs the same three
/// parts and exchanges the packages (`net`).
pub fn run_local(n: u16, t: u16) -> Vec<MemberKey> {
    let mut rng = rand::thread_rng();
    let mut s1 = BTreeMap::new();
    let mut r1 = BTreeMap::new();
    for i in 1..=n {
        let (sec, pkg) = frost::keys::dkg::part1(conv::id(i), n, t, &mut rng).expect("part1");
        s1.insert(i, sec);
        r1.insert(conv::id(i), pkg);
    }
    let mut s2 = BTreeMap::new();
    let mut inbox: BTreeMap<
        frost::Identifier,
        BTreeMap<frost::Identifier, frost::keys::dkg::round2::Package>,
    > = BTreeMap::new();
    for i in 1..=n {
        let others: BTreeMap<_, _> = r1
            .iter()
            .filter(|(k, _)| **k != conv::id(i))
            .map(|(k, v)| (*k, v.clone()))
            .collect();
        let (sec, out) = frost::keys::dkg::part2(s1.remove(&i).unwrap(), &others).expect("part2");
        s2.insert(i, sec);
        for (to, pkg) in out {
            inbox.entry(to).or_default().insert(conv::id(i), pkg);
        }
    }
    (1..=n)
        .map(|i| {
            let others: BTreeMap<_, _> = r1
                .iter()
                .filter(|(k, _)| **k != conv::id(i))
                .map(|(k, v)| (*k, v.clone()))
                .collect();
            let (kp, pp) =
                frost::keys::dkg::part3(&s2[&i], &others, &inbox[&conv::id(i)]).expect("part3");
            MemberKey {
                id: i,
                key_package: kp,
                public: pp,
            }
        })
        .collect()
}
