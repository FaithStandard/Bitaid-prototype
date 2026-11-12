//! The arbitration fee market (specification §10.6, §10.7): one prevailing seat fee, moved by the
//! funded backlog, and two queues. Integer arithmetic only (sats, parts per million), so every node
//! that replays the same postings at the same heights reaches the same fee.
//!
//! * Once every `STEP_BLOCKS` the fee moves by `STEP_PPM` × clamp((B − T)/T, −1, 1), where B is the
//!   active queue's weighted backlog and T one day of the pool's capacity.
//! * Rising, the step halves for each further week (`WEEK_BLOCKS`) of unbroken congestion (B > T),
//!   so no shortage lifts the fee past about 16× where it began; the count resets once B ≤ T.
//! * Falling, it stops at the reference fee (the median of the last `REF_CASES` cleared cases)
//!   unless the active queue is empty.
//! * A case posted below the fee, or priced out after `GRACE_BLOCKS`, waits in standby as a standing
//!   bid; when the fee comes down to it, the highest bid goes first, then responder legitimacy, then
//!   age. Standby ends at the case's last hearing height (refund height less a hearing's length).
//! * Only the active queue counts as demand.
use std::collections::VecDeque;

pub const STEP_BLOCKS: u32 = 18;
pub const STEP_PPM: i64 = 25_000;
pub const WEEK_BLOCKS: u32 = 1_008;
pub const GRACE_BLOCKS: u32 = 36;
pub const REF_CASES: usize = 100;
const PPM: i64 = 1_000_000;

/// A case's posting: the seat fee its escalator funded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bid {
    pub case: String,
    /// the seat fee posted, in sats
    pub fee: u64,
    /// the case's weight in the backlog (the seasoned responders who attended it; at least 1)
    pub weight: u64,
    pub posted_at: u32,
    /// the last height at which the case can still be heard before its refund height
    pub last_hearing: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// fell below the fee: a top-up within the grace window keeps it active
    Graced { case: String, until: u32 },
    PricedOut { case: String },
    /// the fee came down to a standing bid: seated at `fee`, the rest of the posting returned
    Promoted { case: String, fee: u64 },
    /// its bid never met the fee before its last hearing: the case ends by refund
    Expired { case: String },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Placement {
    Active,
    Standby,
}

#[derive(Clone, Debug)]
pub struct Market {
    pub fee: u64,
    cleared: VecDeque<u64>,
    /// consecutive steps with the backlog above a day of capacity
    over_steps: u32,
    /// the height of the next step
    next_step: u32,
    /// (bid, priced below the fee since)
    active: Vec<(Bid, Option<u32>)>,
    standby: Vec<Bid>,
}

impl Market {
    pub fn new(fee: u64, height: u32) -> Market {
        Market {
            fee: fee.max(1),
            cleared: VecDeque::from(vec![fee.max(1)]),
            over_steps: 0,
            next_step: height + STEP_BLOCKS,
            active: vec![],
            standby: vec![],
        }
    }

    /// The median fee at which the last REF_CASES cases cleared (lower median).
    pub fn reference(&self) -> u64 {
        let mut v: Vec<u64> = self.cleared.iter().copied().collect();
        v.sort_unstable();
        v[(v.len() - 1) / 2]
    }

    /// The active queue's weighted backlog.
    pub fn backlog(&self) -> u64 {
        self.active.iter().map(|x| x.0.weight.max(1)).sum()
    }
    pub fn is_active(&self, case: &str) -> bool {
        self.active.iter().any(|x| x.0.case == case)
    }
    pub fn is_standby(&self, case: &str) -> bool {
        self.standby.iter().any(|x| x.case == case)
    }

    /// Posts a case: active if its fee meets the prevailing one, else a standing bid.
    pub fn post(&mut self, bid: Bid) -> Placement {
        self.active.retain(|x| x.0.case != bid.case);
        self.standby.retain(|x| x.case != bid.case);
        if bid.fee >= self.fee {
            self.active.push((bid, None));
            Placement::Active
        } else {
            self.standby.push(bid);
            Placement::Standby
        }
    }

    /// A party tops a case up to `fee`: active again if that meets the prevailing fee.
    pub fn top_up(&mut self, case: &str, fee: u64) -> Option<Placement> {
        if let Some(a) = self.active.iter_mut().find(|x| x.0.case == case) {
            a.0.fee = a.0.fee.max(fee);
            if a.0.fee >= self.fee {
                a.1 = None;
            }
            return Some(Placement::Active);
        }
        let i = self.standby.iter().position(|x| x.case == case)?;
        let mut b = self.standby.remove(i);
        b.fee = b.fee.max(fee);
        Some(self.post(b))
    }

    /// A case left the active queue by being heard: its fee joins the reference.
    pub fn clear(&mut self, case: &str) {
        if let Some(i) = self.active.iter().position(|x| x.0.case == case) {
            self.active.remove(i);
            self.cleared.push_back(self.fee);
            while self.cleared.len() > REF_CASES {
                self.cleared.pop_front();
            }
        }
    }

    /// Runs every step due by `height`, with `capacity_day` the cases (weighted) the pool clears in
    /// a day; returns what happened to the queues, in order.
    pub fn advance(&mut self, height: u32, capacity_day: u64) -> Vec<Event> {
        let mut out = vec![];
        while self.next_step <= height {
            let h = self.next_step;
            self.step(capacity_day.max(1));
            self.queues(h, &mut out);
            self.next_step += STEP_BLOCKS;
        }
        out
    }

    fn step(&mut self, t: u64) {
        let b = self.backlog();
        let x = (((b as i128 - t as i128) * PPM as i128) / t as i128).clamp(-PPM as i128, PPM as i128) as i64;
        self.over_steps = if b > t { self.over_steps + 1 } else { 0 };
        let mut step = STEP_PPM * x / PPM;
        if step > 0 {
            // each further week of unbroken congestion halves the rise
            let halvings = (self.over_steps.saturating_sub(1) / (WEEK_BLOCKS / STEP_BLOCKS)).min(30);
            step >>= halvings;
        }
        let f = self.fee as i128;
        let mut new = (f + f * step as i128 / PPM as i128).max(1) as u64;
        if step < 0 && !self.active.is_empty() {
            new = new.max(self.fee.min(self.reference()));
        }
        self.fee = new;
    }

    fn queues(&mut self, h: u32, out: &mut Vec<Event>) {
        // a case past its last hearing no longer waits for a panel (it ended by refund, or was never
        // seated): it leaves the backlog, so a lapsed posting does not keep the fee up
        self.active.retain(|x| h < x.0.last_hearing);
        // price-out: below the fee for GRACE_BLOCKS moves a case to standby
        let fee = self.fee;
        let mut moved = vec![];
        for (b, since) in self.active.iter_mut() {
            if b.fee >= fee {
                *since = None;
            } else {
                match *since {
                    None => {
                        *since = Some(h);
                        out.push(Event::Graced { case: b.case.clone(), until: h + GRACE_BLOCKS });
                    }
                    Some(s) if h >= s + GRACE_BLOCKS => moved.push(b.case.clone()),
                    _ => {}
                }
            }
        }
        for c in moved {
            let i = self.active.iter().position(|x| x.0.case == c).unwrap();
            let (b, _) = self.active.remove(i);
            out.push(Event::PricedOut { case: c });
            self.standby.push(b);
        }
        // standby: expired bids end; bids the fee has come down to are seated, best first
        let mut i = 0;
        while i < self.standby.len() {
            if h >= self.standby[i].last_hearing {
                let b = self.standby.remove(i);
                out.push(Event::Expired { case: b.case });
            } else {
                i += 1;
            }
        }
        self.standby.sort_by(|a, b| {
            b.fee
                .cmp(&a.fee)
                .then(b.weight.cmp(&a.weight))
                .then(a.posted_at.cmp(&b.posted_at))
                .then(a.case.cmp(&b.case))
        });
        while self.standby.first().is_some_and(|b| b.fee >= self.fee) {
            let mut b = self.standby.remove(0);
            out.push(Event::Promoted { case: b.case.clone(), fee: self.fee });
            b.fee = self.fee;
            self.active.push((b, None));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bid(c: usize, fee: u64, h: u32) -> Bid {
        Bid { case: format!("c{c}"), fee, weight: 1, posted_at: h, last_hearing: h + 20_000 }
    }

    #[test]
    fn steady_at_capacity_the_fee_holds() {
        let mut m = Market::new(10_000, 0);
        for i in 0..8 {
            m.post(bid(i, 10_000, 0));
        }
        m.advance(18 * 100, 8);
        assert_eq!(m.fee, 10_000);
    }

    #[test]
    fn a_shortage_never_lifts_the_fee_past_about_sixteen_times() {
        let mut m = Market::new(10_000, 0);
        let mut h = 0;
        for w in 0..52 {
            // a backlog of twice a day of capacity, every bid topped up to the fee
            for i in 0..16 {
                m.post(bid(w * 100 + i, u64::MAX / 4, h));
            }
            h += WEEK_BLOCKS;
            m.advance(h, 8);
            let first_week = w == 0;
            if first_week {
                // 56 steps of +2.5%: about 4×
                assert!(m.fee > 35_000 && m.fee < 45_000, "{}", m.fee);
            }
            for i in 0..16 {
                m.clear(&format!("c{}", w * 100 + i));
            }
            for i in 0..16 {
                m.post(bid(w * 100 + 50 + i, u64::MAX / 4, h));
            }
        }
        assert!(m.fee < 10_000 * 17, "{}", m.fee);
        assert!(m.fee > 10_000 * 12, "{}", m.fee);
    }

    #[test]
    fn falling_stops_at_the_reference_unless_the_queue_is_empty() {
        let mut m = Market::new(10_000, 0);
        m.post(bid(1, 50_000, 0));
        m.fee = 40_000;
        m.advance(18 * 500, 100);
        assert_eq!(m.fee, 10_000, "held at the reference while a case waits");
        m.clear("c1");
        m.advance(18 * 1_000, 100);
        assert!(m.fee < 10_000, "an empty queue lets it fall: {}", m.fee);
    }

    #[test]
    fn priced_out_after_the_grace_window_and_heard_when_the_fee_comes_down() {
        let mut m = Market::new(10_000, 0);
        assert_eq!(m.post(bid(1, 10_000, 0)), Placement::Active);
        m.fee = 12_000;
        let ev = m.advance(18, 1);
        assert!(matches!(&ev[0], Event::Graced { .. }));
        assert!(m.is_active("c1"));
        let ev = m.advance(18 * 3, 1);
        assert!(ev.contains(&Event::PricedOut { case: "c1".into() }), "{ev:?}");
        assert!(m.is_standby("c1"));
        // nothing active: the fee falls to the standing bid, which is then seated
        let ev = m.advance(18 * 30, 1);
        assert!(ev.iter().any(|e| matches!(e, Event::Promoted { case, fee } if case == "c1" && *fee <= 10_000)), "{ev:?}");
        assert!(m.is_active("c1"));
    }

    #[test]
    fn a_top_up_inside_the_grace_window_keeps_the_case() {
        let mut m = Market::new(10_000, 0);
        m.post(bid(1, 10_000, 0));
        m.fee = 12_000;
        m.advance(18, 1);
        assert_eq!(m.top_up("c1", 13_000), Some(Placement::Active));
        let ev = m.advance(18 * 4, 1);
        assert!(!ev.iter().any(|e| matches!(e, Event::PricedOut { .. })), "{ev:?}");
    }

    #[test]
    fn standby_order_is_bid_then_legitimacy_then_age_and_bids_expire() {
        let mut m = Market::new(10_000, 0);
        m.post(Bid { case: "low".into(), fee: 5_000, weight: 9, posted_at: 0, last_hearing: 50_000 });
        m.post(Bid { case: "old".into(), fee: 8_000, weight: 1, posted_at: 0, last_hearing: 50_000 });
        m.post(Bid { case: "new".into(), fee: 8_000, weight: 1, posted_at: 5, last_hearing: 50_000 });
        m.post(Bid { case: "legit".into(), fee: 8_000, weight: 3, posted_at: 9, last_hearing: 50_000 });
        m.post(Bid { case: "late".into(), fee: 1, weight: 1, posted_at: 0, last_hearing: 100 });
        assert_eq!(m.backlog(), 0, "standing bids add nothing to demand");
        let ev = m.advance(18 * 40, 1);
        let order: Vec<&str> = ev
            .iter()
            .filter_map(|e| match e {
                Event::Promoted { case, .. } => Some(case.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(&order[..3], &["legit", "old", "new"]);
        assert!(ev.contains(&Event::Expired { case: "late".into() }));
    }

    #[test]
    fn replays_agree() {
        let run = || {
            let mut m = Market::new(7_777, 3);
            let mut all = vec![];
            for i in 0..300u32 {
                m.post(Bid { case: format!("c{i}"), fee: 7_000 + (i as u64 * 37) % 3_000, weight: 1 + (i as u64 % 3), posted_at: i * 9, last_hearing: i * 9 + 3_000 });
                all.extend(m.advance(i * 9, 20));
                if i % 3 == 0 {
                    m.clear(&format!("c{}", i / 2));
                }
            }
            (m.fee, all)
        };
        assert_eq!(run(), run());
    }
}
