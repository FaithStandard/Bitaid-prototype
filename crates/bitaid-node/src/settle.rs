//! Settlement by the attending vote (Specification §9), read deterministically from the revealed
//! ballots, so the oracle and every party compute the same outcome.
//!
//! Prototype simplifications, all on the side of escalating rather than guessing: every attendee
//! votes at the 0.1 floor weight (no labor history yet), so weights are equal; a seat's class needs
//! 80% of the ballots; the outcome needs 80% of the ballots; any ballot claiming misuse sends the
//! case to arbitration, since only a panel can seize a deposit (C1.1).
use crate::wire::{Ballot, Class, Fault, Template};
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

/// The responder two thirds of the seats find at fault in their ballots (§9: misconduct starts a
/// ruling), with the gravest severity those two thirds share: the case goes to a tier-1 panel with no
/// escalation filed, its fee advanced from the accused's bond. Attendees never decide it themselves.
pub fn misconduct_trigger(k: usize, ballots: &[Ballot]) -> Option<Fault> {
    let mut best: Option<Fault> = None;
    for seat in 0..k as u8 {
        let named: Vec<&Fault> = ballots
            .iter()
            .filter_map(|b| b.faults.iter().filter(|f| f.seat == seat).max_by_key(|f| f.severity))
            .collect();
        // two thirds of the seats other than the accused (whose own ballot does not count)
        if 3 * named.len() < 2 * (k - 1).max(1) {
            continue;
        }
        // the gravest severity at least two thirds of the seats reach
        let mut sev: Vec<_> = named.iter().map(|f| f.severity).collect();
        sev.sort();
        let reach = sev[sev.len() - (2 * (k - 1).max(1)).div_ceil(3)];
        let f = Fault { seat, severity: reach, harmed: named[0].harmed };
        if best.as_ref().is_none_or(|b| f.severity > b.severity) {
            best = Some(f);
        }
    }
    best
}

/// `pots` are the pot values; `ballots` the revealed ballots of the seated responders.
/// The 80% is of the seats, not of the ballots revealed: a missing ballot counts as no agreement, so
/// one silent attendee cannot narrow the base (review finding D-8).
pub fn decide(k: usize, pots: [u64; 3], t: &Template, ballots: &[Ballot]) -> Decision {
    if let Some(f) = misconduct_trigger(k, ballots) {
        return Decision::Escalate(format!(
            "misconduct: two thirds of the seats find seat {} at fault ({:?}); a panel decides (§9)",
            f.seat, f.severity
        ));
    }
    decide_of(k, pots, t, ballots, k.max(ballots.len()), &[])
}

/// `zero`: seats whose bounty and reward share a panel's fault finding removes (§12, bounty split
/// step 3), redistributed within the same pool.
fn decide_of(k: usize, pots: [u64; 3], t: &Template, ballots: &[Ballot], of: usize, zero: &[usize]) -> Decision {
    if ballots.is_empty() {
        return Decision::Escalate("no ballots".into());
    }
    let n = of as f64;
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
    let no = ballots.len() as f64 - yes;
    let achieved = if yes >= SUPER * n {
        true
    } else if no >= SUPER * n {
        false
    } else {
        return Decision::Escalate("no 80% agreement on the outcome".into());
    };
    // a seat found at fault keeps its class but loses its share, which its pool's others take
    let paid = |i: usize, c: &Class| !zero.contains(&i) && *c != Class::None;
    let interveners = classes
        .iter()
        .enumerate()
        .filter(|(i, c)| **c == Class::Intervention && paid(*i, c))
        .count() as f64;
    let documenters = classes
        .iter()
        .enumerate()
        .filter(|(i, c)| **c == Class::Documentation && paid(*i, c))
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
        .enumerate()
        .map(|(i, c)| if zero.contains(&i) { (i, &Class::None) } else { (i, c) })
        .map(|(_, c)| match c {
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

/// Deemed consent with an unpaid dissent (§9, "a dissent pays to be heard"): the window closed and
/// no one paid a panel, so the ballots that keep a class below 80% are dropped and the case settles on
/// the largest group of ballots giving the same answers, provided it holds at least two thirds of the
/// seats; otherwise the vote stays split (whoever wants it decided pays a panel, or the refund).
pub fn decide_unpaid_dissent(k: usize, pots: [u64; 3], t: &Template, ballots: &[Ballot]) -> Decision {
    let first = decide(k, pots, t, ballots);
    // a misuse flag is an answer like any other: unpaid, it is dropped with the rest of the dissent
    // (review: a free holdout otherwise); attendees alone never seize, so a winning group that
    // claims misuse still does not settle
    // a misconduct finding by two thirds is never dropped as a dissent: it goes to a panel
    if matches!(first, Decision::Settled(_)) || misconduct_trigger(k, ballots).is_some() {
        return first;
    }
    let key = |b: &Ballot| crate::arb::verdict_key(b);
    let mut best: Vec<Ballot> = vec![];
    for b in ballots {
        let g: Vec<Ballot> = ballots.iter().filter(|x| key(x) == key(b)).cloned().collect();
        if g.len() > best.len() {
            best = g;
        }
    }
    if 3 * best.len() < 2 * k {
        return first;
    }
    decide_of(k, pots, t, &best, best.len(), &[])
}

/// A panel's ruling (§10.5, §12), as opposed to the attendees' ballots: one verdict decides. A ruling
/// of caller misuse seizes the deposit by merit and, the whole offer being forfeit, pays the bounty
/// and the reward to the attendees too, by merit, equally if the ruling classes no one (review finding
/// D-3: before, a misuse ruling could not settle and the case went to the refund, to the troll).
pub fn decide_panel(k: usize, pots: [u64; 3], t: &Template, verdict: &Ballot) -> Decision {
    // a panel's fault findings decide: the seat at fault loses its share (its bond is forfeited at
    // the finding's severity apart from the pots, §11.8)
    let zero: Vec<usize> = verdict.faults.iter().map(|f| f.seat as usize).collect();
    if !verdict.misuse {
        return decide_of(k, pots, t, std::slice::from_ref(verdict), 1, &zero);
    }
    let mut plain = verdict.clone();
    plain.misuse = false;
    plain.outcome_achieved = true;
    let Decision::Settled(base) = decide_of(k, pots, t, std::slice::from_ref(&plain), 1, &zero) else {
        return Decision::Escalate("misuse ruling without a split".into());
    };
    // the split the bounty takes under the panel's classes, or equal shares among the seats
    let units = 100 / step_for(k);
    let split = base
        .iter()
        .find_map(|e| match (&e.pot, &e.kind) {
            (Pot::Bounty, EndingKind::Split(v)) => Some(v.clone()),
            _ => None,
        })
        .unwrap_or_else(|| buckets(&vec![1.0; k], units));
    let mut out = Vec::new();
    for p in Pot::ALL {
        if pots[p.index()] == 0 {
            continue;
        }
        let kind = match p {
            Pot::Deposit => EndingKind::SeizedByMerit,
            Pot::Reward | Pot::Bounty => EndingKind::Split(split.clone()),
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
            dispute_blocks: 2,
            arb_fee: 20_000,
            refund_delay: 100,
            refund_xpub: String::new(),
            commit_blocks: 3,
            reveal_blocks: 2,
            review_delay: 2,
            review_pct: None,
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
            misuse: false, faults: vec![],
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

    #[test]
    fn a_misuse_ruling_settles_with_the_whole_offer_forfeit() {
        let t = crate::wire::Template {
            pots: [100_000, 600_000, 300_000],
            intervener_pct: 70,
            good_faith_pct: 50,
            max_signers: 3,
            joining_window: 15,
            dispute_blocks: 3,
            arb_fee: 20_000,
            refund_delay: 12_960,
            refund_xpub: String::new(),
            commit_blocks: 4,
            reveal_blocks: 3,
            review_delay: 2,
            review_pct: None,
        };
        let v = Ballot { acts: vec![], outcome_achieved: false, misuse: true, faults: vec![] };
        let Decision::Settled(ends) = decide_panel(3, t.pots, &t, &v) else {
            panic!("a misuse ruling must settle");
        };
        assert_eq!(ends.len(), 3);
        assert_eq!(ends[0].kind, EndingKind::SeizedByMerit);
        assert!(matches!(ends[1].kind, EndingKind::Split(_)));
        assert!(matches!(ends[2].kind, EndingKind::Split(_)));
        // the attendees' own ballots still cannot seize: only a panel decides misuse
        assert!(matches!(decide(3, t.pots, &t, &[v]), Decision::Escalate(_)));
    }

    #[test]
    fn two_thirds_finding_a_seat_at_fault_sends_the_case_to_a_panel_and_a_lone_accuser_does_not() {
        use crate::wire::{Fault, Severity};
        use Class::*;
        let b = ballot(&[Intervention, Intervention, Documentation], true);
        let mut acc = b.clone();
        acc.faults = vec![Fault { seat: 0, severity: Severity::Misconduct, harmed: Option::None }];
        let mut lapse = b.clone();
        lapse.faults = vec![Fault { seat: 0, severity: Severity::Lapse, harmed: Option::None }];
        // one of three: the attendees settle as if no one accused (the accuser escalates at its cost)
        assert!(matches!(decide(3, [1, 1, 1], &t(), &[b.clone(), b.clone(), acc.clone()]), Decision::Settled(_)));
        // two of three: a panel decides, at the gravest severity both reach
        let f = misconduct_trigger(3, &[acc.clone(), lapse.clone(), b.clone()]).unwrap();
        assert_eq!((f.seat, f.severity), (0, Severity::Lapse));
        assert!(matches!(decide(3, [1, 1, 1], &t(), &[acc.clone(), lapse, b.clone()]), Decision::Escalate(m) if m.contains("misconduct")));
        assert_eq!(misconduct_trigger(3, &[acc.clone(), acc.clone(), b]).unwrap().severity, Severity::Misconduct);
        // two seats: the one other than the accused is the two thirds
        let b2 = ballot(&[Intervention, Intervention], true);
        let mut a2 = b2.clone();
        a2.faults = vec![Fault { seat: 1, severity: Severity::Misconduct, harmed: Some(0) }];
        assert!(matches!(decide(2, [1, 1, 1], &t(), &[a2, b2]), Decision::Escalate(m) if m.contains("misconduct")));
    }

    #[test]
    fn a_panel_finding_removes_the_share_of_the_seat_at_fault() {
        use crate::wire::{Fault, Severity};
        use Class::*;
        let mut v = ballot(&[Intervention, Intervention, Documentation], true);
        v.faults = vec![Fault { seat: 0, severity: Severity::Misconduct, harmed: Option::None }];
        let Decision::Settled(e) = decide_panel(3, [1000, 1000, 1000], &t(), &v) else { panic!() };
        // seat 0's 35% goes to the other intervener: 70/0/30 of the bounty
        assert_eq!(e[2].label, "split (0, 7, 3)");
        assert_eq!(e[1].label, "paid (0, 7, 3)");
    }

    #[test]
    fn an_unpaid_dissent_is_dropped_when_the_rest_hold_two_thirds() {
        use crate::wire::Act;
        let mut t = crate::wire::Template {
            pots: [100_000, 600_000, 300_000],
            intervener_pct: 70,
            good_faith_pct: 50,
            max_signers: 3,
            joining_window: 15,
            dispute_blocks: 3,
            arb_fee: 20_000,
            refund_delay: 12_960,
            refund_xpub: String::new(),
            commit_blocks: 4,
            reveal_blocks: 3,
            review_delay: 2,
            review_pct: None,
        };
        t.max_signers = 3;
        let act = |s: u8, c: Class| Act { seat: s, class: c, footage: None };
        let honest = Ballot {
            acts: vec![act(0, Class::Intervention), act(1, Class::Documentation), act(2, Class::Documentation)],
            outcome_achieved: true,
            misuse: false, faults: vec![],
        };
        let mut dissent = honest.clone();
        dissent.acts[0].class = Class::None;
        let ballots = [honest.clone(), honest.clone(), dissent.clone()];
        assert!(matches!(decide(3, t.pots, &t, &ballots), Decision::Escalate(_)));
        assert!(matches!(decide_unpaid_dissent(3, t.pots, &t, &ballots), Decision::Settled(_)));
        // one against one of three seats: still split
        assert!(matches!(
            decide_unpaid_dissent(3, t.pots, &t, &[honest, dissent]),
            Decision::Escalate(_)
        ));
    }
}
