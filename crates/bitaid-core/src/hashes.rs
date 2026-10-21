//! BIP340-style tagged hashes and the outcome messages the oracle attests.
use bitcoin::hashes::{sha256, Hash, HashEngine};

/// `SHA256(SHA256(tag) || SHA256(tag) || msg)`.
pub fn tagged(tag: &str, msg: &[u8]) -> [u8; 32] {
    let t = sha256::Hash::hash(tag.as_bytes());
    let mut e = sha256::Hash::engine();
    e.input(t.as_ref());
    e.input(t.as_ref());
    e.input(msg);
    sha256::Hash::from_engine(e).to_byte_array()
}

/// The message the oracle signs for one ending of one pot of one case:
/// `tagged("Bitaid/outcome", case || "|" || pot || "|" || label)`.
pub fn outcome_msg(case: &str, pot: &str, label: &str) -> [u8; 32] {
    tagged("Bitaid/outcome", format!("{case}|{pot}|{label}").as_bytes())
}

pub fn sha256(b: &[u8]) -> [u8; 32] {
    sha256::Hash::hash(b).to_byte_array()
}
