//! Every ending of each pot (Specification §11.11). The incident set holds three pots, each in
//! its own output, so each needs payouts only for its own endings and the counts add.
//!
//! Splits among signing responders are rounded into buckets: 10% steps for up to three signing
//! responders, 20% steps for four or five. A vector gives each responder's number of buckets and
//! sums to the whole pot. Vectors are enumerated in lexicographic order.

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum Pot {
    Deposit,
    Reward,
    Bounty,
}

impl Pot {
    pub const ALL: [Pot; 3] = [Pot::Deposit, Pot::Reward, Pot::Bounty];
    pub fn name(self) -> &'static str {
        match self {
            Pot::Deposit => "deposit",
            Pot::Reward => "reward",
            Pot::Bounty => "bounty",
        }
    }
    pub fn index(self) -> usize {
        self as usize
    }
}

/// How a pot is paid out in one ending.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EndingKind {
    /// The whole pot back to the caller (deposit returned, bounty returned, reward withheld).
    ToCaller,
    /// Deposit seized and paid by the merit vector fixed at acceptance.
    SeizedByMerit,
    /// Deposit seized and paid to one responder the caller harmed.
    SeizedToHarmed(usize),
    /// Split by a bucket vector (bounty split, or reward paid).
    Split(Vec<u32>),
    /// Reward paid at the good-faith share by a bucket vector; the rest back to the caller.
    GoodFaith(Vec<u32>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ending {
    pub pot: Pot,
    pub label: String,
    pub kind: EndingKind,
}

/// Bucket step in percent for `k` signing responders.
pub fn step_for(k: usize) -> u32 {
    if k <= 3 {
        10
    } else {
        20
    }
}

/// All vectors of `k` non-negative bucket counts summing to `100 / step`, in lexicographic order.
pub fn vectors(k: usize, step: u32) -> Vec<Vec<u32>> {
    let units = 100 / step;
    let mut out = Vec::new();
    let mut cur = Vec::with_capacity(k);
    fn rec(k: usize, left: u32, cur: &mut Vec<u32>, out: &mut Vec<Vec<u32>>) {
        if cur.len() == k {
            if left == 0 {
                out.push(cur.clone());
            }
            return;
        }
        for v in 0..=left {
            cur.push(v);
            rec(k, left - v, cur, out);
            cur.pop();
        }
    }
    if k > 0 {
        rec(k, units, &mut cur, &mut out);
    }
    out
}

/// Formats a vector the way the reference implementation labels it: `(1, 0, 4)`, `(10,)`.
pub fn fmt_vec(v: &[u32]) -> String {
    let parts: Vec<String> = v.iter().map(|x| x.to_string()).collect();
    if v.len() == 1 {
        format!("({},)", parts[0])
    } else {
        format!("({})", parts.join(", "))
    }
}

/// All endings of the three pots for `k` signing responders.
pub fn endings(k: usize) -> Vec<Ending> {
    let vs = vectors(k, step_for(k));
    let mut e = Vec::new();
    let d = Pot::Deposit;
    e.push(Ending {
        pot: d,
        label: "returned".into(),
        kind: EndingKind::ToCaller,
    });
    e.push(Ending {
        pot: d,
        label: "seized by merit weight".into(),
        kind: EndingKind::SeizedByMerit,
    });
    for i in 0..k {
        e.push(Ending {
            pot: d,
            label: format!("seized to harmed responder {i}"),
            kind: EndingKind::SeizedToHarmed(i),
        });
    }
    let r = Pot::Reward;
    for v in &vs {
        e.push(Ending {
            pot: r,
            label: format!("paid {}", fmt_vec(v)),
            kind: EndingKind::Split(v.clone()),
        });
    }
    for v in &vs {
        e.push(Ending {
            pot: r,
            label: format!("good-faith share {}", fmt_vec(v)),
            kind: EndingKind::GoodFaith(v.clone()),
        });
    }
    e.push(Ending {
        pot: r,
        label: "withheld".into(),
        kind: EndingKind::ToCaller,
    });
    let b = Pot::Bounty;
    for v in &vs {
        e.push(Ending {
            pot: b,
            label: format!("split {}", fmt_vec(v)),
            kind: EndingKind::Split(v.clone()),
        });
    }
    e.push(Ending {
        pot: b,
        label: "returned whole to the caller".into(),
        kind: EndingKind::ToCaller,
    });
    e
}

/// Counts per pot (deposit, reward, bounty).
pub fn counts(k: usize) -> (usize, usize, usize) {
    let e = endings(k);
    let c = |p: Pot| e.iter().filter(|x| x.pot == p).count();
    (c(Pot::Deposit), c(Pot::Reward), c(Pot::Bounty))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn published_counts() {
        assert_eq!(counts(5), (7, 253, 127));
        let (a, b, c) = counts(5);
        assert_eq!(a + b + c, 387);
        assert_eq!(vectors(5, 20).len(), 126);
    }
    #[test]
    fn labels_match_reference_format() {
        assert_eq!(fmt_vec(&[0, 0, 0, 0, 5]), "(0, 0, 0, 0, 5)");
        assert_eq!(fmt_vec(&[10]), "(10,)");
        assert_eq!(vectors(3, 10).first().unwrap(), &vec![0, 0, 10]);
    }
}
