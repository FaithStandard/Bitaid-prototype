//! Bitaid escrow core (prototype, milestone M1).
//!
//! Everything a node needs to build and check one incident's escrow, independent of networking:
//! the funding, bond and buffer outputs (Specification Appendix B.1), the incident outputs and
//! the enumeration of every ending of each pot (§11.11), the pre-signed payout set as MuSig2
//! adaptor signatures encrypted to the oracle's attestation points (§3.2–3.3), the oracle's
//! attestation, and the deterministic replay of the anchored event log (§7.2).
//!
//! This is a prototype for testing and review, not production software. It must not hold real funds.

pub mod endings;
pub mod eventlog;
pub mod hashes;
pub mod musig;
pub mod oracle;
pub mod outputs;
pub mod payouts;
pub mod presign;
pub mod scripts;
pub mod tree;
pub mod txbuild;

pub use bitcoin;
pub use musig2;
