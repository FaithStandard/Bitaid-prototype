//! Conversions between the FROST crate's types and the `secp` types used elsewhere.
use frost_secp256k1_tr as frost;
use musig2::secp::{Point, Scalar};

pub fn share_scalar(kp: &frost::keys::KeyPackage) -> Scalar {
    Scalar::from_slice(&kp.signing_share().serialize()).expect("valid share")
}

pub fn element(bytes: &[u8]) -> Point {
    Point::from_slice(bytes).expect("valid point")
}

pub fn group_key(pk: &frost::keys::PublicKeyPackage) -> Point {
    element(&pk.verifying_key().serialize().expect("serialise"))
}

pub fn verifying_share(pk: &frost::keys::PublicKeyPackage, i: u16) -> Point {
    let id = frost::Identifier::try_from(i).unwrap();
    element(&pk.verifying_shares()[&id].serialize().expect("serialise"))
}

pub fn id(i: u16) -> frost::Identifier {
    frost::Identifier::try_from(i).unwrap()
}
