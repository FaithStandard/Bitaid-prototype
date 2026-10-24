//! Settlement by the attending vote (Specification §9), read deterministically from the revealed
//! ballots, so the oracle and every party compute the same outcome.
//!
//! Prototype simplifications, all on the side of escalating rather than guessing: every attendee
//! votes at the 0.1 floor weight (no labor history yet), so weights are equal; a seat's class needs
//! 80% of the ballots; the outcome needs 80% of the ballots; any ballot claiming misuse sends the
//! case to arbitration, since only a panel can seize a deposit (C1.1).
use crate::wire::{Ballot, Class, Template};
use bitaid_core::endings::{endings, step_for, Ending, EndingKind, Pot};

#[derive(Debug, Clone, PartialEq)]
pub enum Decision {
    /// One ending per non-empty pot, in pot order.
    Settled(Vec<Ending>),
    /// No supermajority, or a claim only a panel can decide.
    Escalate(String),
}

const SUPER: f64 = 0.8;

/// Converts weights into bucket counts summing to `units` (largest remainder, first on a tie).
pub fn buckets(weights: &[f64], units: u32) -> Vec<u32> {
    let total: f64 = weights.iter().sum();
    if total <= 0.0 {
        return vec![0; weights.len()];
    }
    let exact: Vec<f64> = weights.iter().map(|w| w / total * units as f64).collect();
    let mut v: Vec<u32> = exact.iter().map(|x| x.floor() as u32).collect();
    let mut left = units - v.iter().sum::<u32>();
    let mut order: Vec<usize> = (0..v.len()).collect();
    order.sort_by(|&a, &b| {
        let (ra, rb) = (exact[a] - exact[a].floor(), exact[b] - exact[b].floor());
        rb.partial_cmp(&ra).unwrap().then(a.cmp(&b))
    });
    for i in order {
        if left == 0 {
            break;
        }
        if weights[i] > 0.0 {
            v[i] += 1;
            left -= 1;
        }
    }
    v
}

fn find(k: usize, pot: Pot, kind: &EndingKind) -> Ending {
    endings(k)
        .into_iter()
        .find(|e| e.pot == pot && &e.kind == kind)
        .expect("every bucket vector is in the set")
}

/// `pots` are the pot values; `ballots` the revealed ballots of the seated responders.
pub fn decide(k: usize, pots: [u64; 3], t: &Template, ballots: &[Ballot]) -> Decision {
    if ballots.is_empty() {
        return Decision::Escalate("no ballots".into());
    }
    let n = ballots.len() as f64;
    if ballots.iter().any(|b| b.misuse) {
        return Decision::Escalate("misuse claimed: a panel decides the deposit (C1.1)".into());
    }
    // class of each seat by supermajority
    let mut classes = Vec::with_capacity(k);
    for seat in 0..k {
        let class_of = |b: &Ballot| {
            b.acts
                .iter()
                .find(|a| a.seat as usize == seat)
                .map(|a| a.class.clone())
                .unwrap_or(Class::None)
        };
        let mut best: Option<(Class, usize)> = None;
        for c in [Class::Intervention, Class::Documentation, Class::None] {
            let cnt = ballots.iter().filter(|b| class_of(b) == c).count();
            if best.as_ref().map(|b| cnt > b.1).unwrap_or(true) {
                best = Some((c, cnt));
            }
        }
        let (c, cnt) = best.unwrap();
        if (cnt as f64) < SUPER * n {
            return Decision::Escalate(format!("seat {seat}: no 80% agreement on its class"));
        }
        classes.push(c);
    }
    let yes = ballots.iter().filter(|b| b.outcome_achieved).count() as f64;
    let achieved = if yes >= SUPER * n {
        true
    } else if n - yes >= SUPER * n {
        false
    } else {
        return Decision::Escalate("no 80% agreement on the outcome".into());
    };
    let interveners = classes
        .iter()
        .filter(|c| **c == Class::Intervention)
        .count() as f64;
    let documenters = classes
        .iter()
        .filter(|c| **c == Class::Documentation)
        .count() as f64;
    let ip = t.intervener_pct as f64;
    let (wi, wd) = match (interveners > 0.0, documenters > 0.0) {
        (true, true) => (ip / interveners, (100.0 - ip) / documenters),
        (true, false) => (100.0 / interveners, 0.0),
        (false, true) => (0.0, 100.0 / documenters),
        (false, false) => (0.0, 0.0),
    };
    let weights: Vec<f64> = classes
        .iter()
        .map(|c| match c {
            Class::Intervention => wi,
            Class::Documentation => wd,
            Class::None => 0.0,
        })
        .collect();
    let units = 100 / step_for(k);
    let v = buckets(&weights, units);
    let anyone = interveners + documenters > 0.0;
    let mut out = Vec::new();
    for p in Pot::ALL {
        if pots[p.index()] == 0 {
            continue;
        }
        let kind = match p {
            Pot::Deposit => EndingKind::ToCaller,
            // the reward follows the bounty split; a genuine attempt that failed earns the good-faith share
            Pot::Reward if achieved && interveners > 0.0 => EndingKind::Split(v.clone()),
            Pot::Reward if interveners > 0.0 => EndingKind::GoodFaith(v.clone()),
            Pot::Reward => EndingKind::ToCaller,
            Pot::Bounty if anyone => EndingKind::Split(v.clone()),
            Pot::Bounty => EndingKind::ToCaller,
        };
        out.push(find(k, p, &kind));
    }
    Decision::Settled(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::Act;

    fn t() -> Template {
        Template {
            pots: [1, 1, 1],
            intervener_pct: 70,
            good_faith_pct: 50,
            max_signers: 5,
            joining_window: 10,
            dispute_window: 10,
            refund_delay: 100,
            refund_xpub: String::new(),
        }
    }
    fn ballot(classes: &[Class], ok: bool) -> Ballot {
        Ballot {
            acts: classes
                .iter()
                .enumerate()
                .map(|(i, c)| Act {
                    seat: i as u8,
                    class: c.clone(),
                    footage: None,
                })
                .collect(),
            outcome_achieved: ok,
            misuse: false,
        }
    }

    #[test]
    fn unanimous_two_interveners_one_documenter() {
        use Class::*;
        let b = ballot(&[Intervention, Intervention, Documentation], true);
        let d = decide(3, [1000, 1000, 1000], &t(), &[b.clone(), b.clone(), b]);
        let Decision::Settled(e) = d else { panic!() };
        assert_eq!(e[0].label, "returned");
        // 35/35/30 in 10% buckets: (4, 3, 3), the remainder to the first on a tie
        assert_eq!(e[1].label, "paid (4, 3, 3)");
        assert_eq!(e[2].label, "split (4, 3, 3)");
    }

    #[test]
    fn disagreement_and_misuse_escalate() {
        use Class::*;
        let a = ballot(&[Intervention, Documentation], true);
        let b = ballot(&[Documentation, Documentation], true);
        assert!(matches!(
            decide(2, [1, 1, 1], &t(), &[a.clone(), b]),
            Decision::Escalate(_)
        ));
        let mut m = a.clone();
        m.misuse = true;
        assert!(matches!(
            decide(2, [1, 1, 1], &t(), &[a, m]),
            Decision::Escalate(_)
        ));
    }

    #[test]
    fn failed_attempt_earns_good_faith() {
        use Class::*;
        let b = ballot(&[Intervention], false);
        let Decision::Settled(e) = decide(1, [1, 1, 1], &t(), &[b]) else {
            panic!()
        };
        assert_eq!(e[1].label, "good-faith share (10,)");
    }
}
