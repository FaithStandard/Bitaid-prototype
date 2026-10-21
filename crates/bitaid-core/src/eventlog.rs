//! Deterministic replay of the anchored event log (Specification §7.2), reduced to the events whose
//! order decides outcomes: funding outputs and their withdrawal authorisations, alerts and
//! acceptances, bonds and their exits, seats, and committed and revealed votes.
//!
//! Ordering: by referenced block height; within a height, by kind in dependency order — events that
//! end or invalidate something first, then postings (funding, bonds), then alerts, then acceptances
//! and seats, then vote commitments, then reveals — so that nothing is applied before what it relies
//! on; events of the same kind are ordered by their hash. Every node that holds the same set of
//! events reaches the same state, whatever order they arrived in.
use crate::hashes::sha256;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Kind {
    Funding {
        out: String,
    },
    WithdrawalAuthorised {
        out: String,
    },
    Alert {
        case: String,
        out: String,
    },
    Accept {
        case: String,
        resp: String,
    },
    Bond {
        op: String,
    },
    BondExit {
        op: String,
    },
    Seat {
        case: String,
        op: String,
    },
    Commit {
        case: String,
        op: String,
        c: String,
    },
    Reveal {
        case: String,
        op: String,
        vote: String,
        salt: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    /// Referenced block height.
    pub h: u32,
    #[serde(flatten)]
    pub kind: Kind,
}

impl Event {
    /// Event id: SHA-256 of the canonical JSON encoding.
    pub fn id(&self) -> [u8; 32] {
        sha256(&serde_json::to_vec(self).expect("serialise"))
    }
    /// Rank within a height: what ends or invalidates first, then what starts, then what relies on it.
    pub fn rank(&self) -> u8 {
        match self.kind {
            Kind::WithdrawalAuthorised { .. } | Kind::BondExit { .. } => 0,
            Kind::Funding { .. } | Kind::Bond { .. } => 1,
            Kind::Alert { .. } => 2,
            Kind::Accept { .. } | Kind::Seat { .. } => 3,
            Kind::Commit { .. } => 4,
            Kind::Reveal { .. } => 5,
        }
    }
    fn order_key(&self) -> (u32, u8, [u8; 32]) {
        (self.h, self.rank(), self.id())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct AlertState {
    pub out: String,
    pub backed: bool,
    pub accepted: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct State {
    pub funding: BTreeMap<String, String>,
    pub alerts: BTreeMap<String, AlertState>,
    pub bonds: BTreeMap<String, String>,
    pub seats: BTreeMap<String, Vec<String>>,
    pub votes: BTreeMap<String, (String, Option<String>)>,
}

impl State {
    /// SHA-256 of the canonical encoding: nodes compare states, and checkpoints anchor it.
    pub fn digest(&self) -> [u8; 32] {
        sha256(&serde_json::to_vec(self).expect("serialise"))
    }
}

pub fn replay(events: &[Event]) -> State {
    let mut ev: Vec<&Event> = events.iter().collect();
    ev.sort_by_key(|e| e.order_key());
    let mut st = State::default();
    for e in ev {
        match &e.kind {
            Kind::Funding { out } => {
                st.funding.insert(out.clone(), "live".into());
            }
            Kind::WithdrawalAuthorised { out } => {
                st.funding.insert(out.clone(), "spent".into());
            }
            Kind::Alert { case, out } => {
                let backed = st.funding.get(out).map(|s| s == "live").unwrap_or(false);
                st.alerts.insert(
                    case.clone(),
                    AlertState {
                        out: out.clone(),
                        backed,
                        accepted: vec![],
                    },
                );
            }
            Kind::Accept { case, resp } => {
                let active = st.bonds.get(resp).map(|s| s == "active").unwrap_or(false);
                if let Some(a) = st.alerts.get_mut(case) {
                    if a.backed && active {
                        a.accepted.push(resp.clone());
                    }
                }
            }
            Kind::Bond { op } => {
                st.bonds.insert(op.clone(), "active".into());
            }
            Kind::BondExit { op } => {
                st.bonds.insert(op.clone(), "exiting".into());
            }
            Kind::Seat { case, op } => {
                if st.bonds.get(op).map(|s| s == "active").unwrap_or(false) {
                    st.seats.entry(case.clone()).or_default().push(op.clone());
                }
            }
            Kind::Commit { case, op, c } => {
                st.votes.insert(format!("{case}|{op}"), (c.clone(), None));
            }
            Kind::Reveal {
                case,
                op,
                vote,
                salt,
            } => {
                if let Some(v) = st.votes.get_mut(&format!("{case}|{op}")) {
                    if hex::encode(sha256(format!("{vote}{salt}").as_bytes())) == v.0 {
                        v.1 = Some(vote.clone());
                    }
                }
            }
        }
    }
    st
}
