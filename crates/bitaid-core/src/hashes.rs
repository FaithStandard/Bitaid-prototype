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

/// The message the oracle attests for one outcome (Specification B.3, "Outcome identifiers"):
/// `tagged("Bitaid/outcome", case_id[32] || set_version[u32 LE] || pot[u8] || class[u8] || len(split)[u8] || split)`.
/// `split` is the bucket vector, or the harmed responder's seat for a deposit seized to one responder,
/// or empty.
pub fn outcome_msg(
    case_id: &[u8; 32],
    set_version: u32,
    pot: u8,
    class: u8,
    split: &[u8],
) -> [u8; 32] {
    assert!(split.len() < 256);
    let mut b = Vec::with_capacity(39 + split.len());
    b.extend_from_slice(case_id);
    b.extend_from_slice(&set_version.to_le_bytes());
    b.push(pot);
    b.push(class);
    b.push(split.len() as u8);
    b.extend_from_slice(split);
    tagged("Bitaid/outcome", &b)
}

/// A 32-byte case id from a human-readable handle (tests and tools; on the network the case id is the
/// alert event's id).
pub fn case_id(handle: &str) -> [u8; 32] {
    sha256(handle.as_bytes())
}

pub fn sha256(b: &[u8]) -> [u8; 32] {
    sha256::Hash::hash(b).to_byte_array()
}
