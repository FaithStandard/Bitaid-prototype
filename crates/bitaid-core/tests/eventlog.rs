//! Event-log replay: same events in any arrival order give the same state; the same-height race
//! between a withdrawal authorisation and an alert resolves against the alert; votes reveal only
//! against their commitment.
use bitaid_core::eventlog::{replay, Event, Kind};
use bitaid_core::hashes::sha256;
use rand::seq::SliceRandom;

fn ev(h: u32, kind: Kind) -> Event {
    Event { h, kind }
}

#[test]
fn order_independent_and_races() {
    let commit = hex::encode(sha256(b"guiltysalt1"));
    let mut events = vec![
        ev(100, Kind::Funding { out: "f1".into() }),
        ev(100, Kind::Funding { out: "f2".into() }),
        ev(101, Kind::Bond { op: "r1".into() }),
        ev(101, Kind::Bond { op: "r2".into() }),
        ev(
            105,
            Kind::Alert {
                case: "c1".into(),
                out: "f1".into(),
            },
        ),
        ev(
            105,
            Kind::Accept {
                case: "c1".into(),
                resp: "r1".into(),
            },
        ),
        // same height: withdrawal authorised for f2 and an alert on f2 -> the withdrawal comes first
        ev(
            106,
            Kind::Alert {
                case: "c2".into(),
                out: "f2".into(),
            },
        ),
        ev(106, Kind::WithdrawalAuthorised { out: "f2".into() }),
        // a bond exit at the height of an acceptance -> the exit comes first, acceptance refused
        ev(
            107,
            Kind::Accept {
                case: "c1".into(),
                resp: "r2".into(),
            },
        ),
        ev(107, Kind::BondExit { op: "r2".into() }),
        ev(108, Kind::Bond { op: "a1".into() }),
        ev(
            109,
            Kind::Seat {
                case: "c1".into(),
                op: "a1".into(),
            },
        ),
        ev(
            110,
            Kind::Commit {
                case: "c1".into(),
                op: "a1".into(),
                c: commit,
            },
        ),
        ev(
            111,
            Kind::Reveal {
                case: "c1".into(),
                op: "a1".into(),
                vote: "guilty".into(),
                salt: "salt1".into(),
            },
        ),
    ];
    let base = replay(&events);
    assert!(base.alerts["c1"].backed);
    assert_eq!(base.alerts["c1"].accepted, vec!["r1".to_string()]);
    assert!(
        !base.alerts["c2"].backed,
        "alert on a withdrawn output must show unbacked"
    );
    assert_eq!(base.votes["c1|a1"].1.as_deref(), Some("guilty"));
    let mut rng = rand::thread_rng();
    for _ in 0..2000 {
        events.shuffle(&mut rng);
        assert_eq!(replay(&events).digest(), base.digest());
    }
    // a reveal that does not match the commitment is ignored
    events.push(ev(
        112,
        Kind::Reveal {
            case: "c1".into(),
            op: "a1".into(),
            vote: "innocent".into(),
            salt: "x".into(),
        },
    ));
    assert_eq!(replay(&events).votes["c1|a1"].1.as_deref(), Some("guilty"));
}
