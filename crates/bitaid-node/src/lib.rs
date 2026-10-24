//! Bitaid node (prototype, milestone M3): the caller, responder, archivist and oracle roles as one
//! daemon, exchanging the messages of Specification Appendix B.2 over Nostr relays and storing
//! evidence on Blossom-compatible servers.
//!
//! This is a prototype for testing and review, not production software. It must not hold real funds.
pub mod blossom;
pub mod case;
pub mod chain;
pub mod node;
pub mod nostr;
pub mod relay;
pub mod settle;
pub mod wire;
