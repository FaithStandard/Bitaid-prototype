//! The script outputs of Specification Appendix B.1. None has a key path; every leaf that can
//! move funds before the fallback needs two keys, one of them the oracle pool's.
use crate::scripts::{after_height, nums, two_keys};
use crate::tree::ScriptTree;
use bitcoin::secp256k1::{Secp256k1, Verification};
use bitcoin::XOnlyPublicKey;

/// Leaf indices of the funding output.
pub mod funding_leaf {
    /// Caller's wallet key + oracle co-signature (withdrawal while no alert is open).
    pub const WITHDRAW: usize = 0;
    /// Caller's scoped key + oracle co-signature (the template's incident transaction).
    pub const ACCEPT: usize = 1;
    /// Wallet key alone after the fallback height.
    pub const FALLBACK: usize = 2;
}

/// Caller's funding output: deposit, bounty and reward before any incident.
pub fn funding<C: Verification>(
    secp: &Secp256k1<C>,
    wallet: &XOnlyPublicKey,
    scoped: &XOnlyPublicKey,
    oracle: &XOnlyPublicKey,
    fallback_height: u32,
) -> ScriptTree {
    ScriptTree::new(
        secp,
        nums(),
        vec![
            two_keys(wallet, oracle),
            two_keys(scoped, oracle),
            after_height(fallback_height, wallet),
        ],
    )
}

/// Leaf indices of the bond output.
pub mod bond_leaf {
    /// Operator's scoped key + oracle co-signature: pre-signed forfeitures only.
    pub const FORFEIT: usize = 0;
    /// Operator's cold wallet key + oracle co-signature: withdrawal after the hold.
    pub const WITHDRAW: usize = 1;
    /// Cold key alone after the fallback height.
    pub const FALLBACK: usize = 2;
}

/// A bond: responder, arbitrator, archivist or delegate.
pub fn bond<C: Verification>(
    secp: &Secp256k1<C>,
    scoped: &XOnlyPublicKey,
    cold: &XOnlyPublicKey,
    oracle: &XOnlyPublicKey,
    fallback_height: u32,
) -> ScriptTree {
    ScriptTree::new(
        secp,
        nums(),
        vec![
            two_keys(scoped, oracle),
            two_keys(cold, oracle),
            after_height(fallback_height, cold),
        ],
    )
}

/// Leaf indices of an insurer buffer.
pub mod buffer_leaf {
    /// Client's scoped key + oracle co-signature: draws into incidents and the client's forfeitures.
    pub const DRAW: usize = 0;
    /// Insurer's wallet key + oracle co-signature: withdrawal when the layer backs nothing open.
    pub const WITHDRAW: usize = 1;
    /// Insurer's key alone after the fallback height.
    pub const FALLBACK: usize = 2;
}

/// An insurer buffer layer behind a client.
pub fn buffer<C: Verification>(
    secp: &Secp256k1<C>,
    client_scoped: &XOnlyPublicKey,
    insurer: &XOnlyPublicKey,
    oracle: &XOnlyPublicKey,
    fallback_height: u32,
) -> ScriptTree {
    ScriptTree::new(
        secp,
        nums(),
        vec![
            two_keys(client_scoped, oracle),
            two_keys(insurer, oracle),
            after_height(fallback_height, insurer),
        ],
    )
}
