//! Arbitration (Specification §10): the deterministic parts every party recomputes for itself —
//! panel sizes, the seat draw from a block hash, the two-thirds supermajority, the asymmetric
//! penalty and the tier commitment.
use crate::wire::Ballot;
use bitaid_core::hashes::tagged;

/// Panel size of a tier: 3 at first instance, 7, 15, 31, then doubling (§10.5).
pub fn panel_size(tier: u32) -> usize {
    match tier {
        0 | 1 => 3,
        2 => 7,
        3 => 15,
        4 => 31,
        n => 31 * 2usize.pow(n - 4) + (2usize.pow(n - 4) - 1),
    }
}

/// Fee per seat at a tier: the base plus 25% per tier above the first (§10.5).
pub fn seat_fee(base: u64, tier: u32) -> u64 {
    base * (100 + 25 * (tier.saturating_sub(1) as u64)) / 100
}

/// Seats drawn from the offers by randomness from a block mined after offers closed (§10.2):
/// each offer is ranked by tagged_hash(block hash ‖ case ‖ tier ‖ offerer); the lowest `n` win.
/// Speed of offering buys nothing, and anyone holding the offers and the block can check the draw.
pub fn draw(block_hash: &str, case: &str, tier: u32, offers: &[String], n: usize) -> Vec<String> {
    let mut ranked: Vec<([u8; 32], String)> = offers
        .iter()
        .map(|o| {
            let mut b = hex::decode(block_hash).unwrap_or_default();
            b.extend_from_slice(case.as_bytes());
            b.extend_from_slice(&tier.to_le_bytes());
            b.extend_from_slice(o.as_bytes());
            (tagged("Bitaid/seat-draw", &b), o.clone())
        })
        .collect();
    ranked.sort();
    ranked.dedup_by(|a, b| a.1 == b.1);
    ranked.into_iter().take(n).map(|x| x.1).collect()
}

/// A verdict's identity for counting: two arbitrators agree when their answers are identical.
pub fn verdict_key(v: &Ballot) -> Vec<u8> {
    let mut b = Vec::new();
    ciborium::into_writer(v, &mut b).unwrap();
    b
}

/// The verdict that at least two thirds of the panel gave, if any (§10.5: every tier decides by ⅔).
pub fn supermajority(n: usize, votes: &[Ballot]) -> Option<Ballot> {
    let need = (2 * n).div_ceil(3);
    for v in votes {
        let k = verdict_key(v);
        if votes.iter().filter(|x| verdict_key(x) == k).count() >= need {
            return Some(v.clone());
        }
    }
    None
}

/// The isolation penalty factor for a dissenter on a panel of `n` where a share `p` dissented (§10.4):
/// 2 + 2·(1/3 − p)/(1/3 − 1/n), p clamped to [1/n, 1/3], capped at 4; 2 on panels of 3.
pub fn penalty_factor(n: usize, dissenters: usize) -> f64 {
    if n <= 3 {
        return 2.0;
    }
    let nf = n as f64;
    let p = (dissenters as f64 / nf).clamp(1.0 / nf, 1.0 / 3.0);
    (2.0 + 2.0 * ((1.0 / 3.0 - p) / (1.0 / 3.0 - 1.0 / nf))).min(4.0)
}

/// The tier commitment (B.2): a hash of the case, the tier, the roster and every revealed answer,
/// carried in one OP_RETURN. The oracle attests a tier's verdict only once this is on chain.
pub fn tier_commitment(
    case: &str,
    tier: u32,
    seats: &[String],
    reveals: &[(String, Ballot)],
) -> [u8; 32] {
    let mut b = case.as_bytes().to_vec();
    b.extend_from_slice(&tier.to_le_bytes());
    let mut s = seats.to_vec();
    s.sort();
    for x in s {
        b.extend_from_slice(x.as_bytes());
    }
    let mut r: Vec<(String, Vec<u8>)> = reveals
        .iter()
        .map(|(k, v)| (k.clone(), verdict_key(v)))
        .collect();
    r.sort();
    for (k, v) in r {
        b.extend_from_slice(k.as_bytes());
        b.extend_from_slice(&v);
    }
    tagged("Bitaid/tier-commitment", &b)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{Act, Class};

    fn v(c: &[Class]) -> Ballot {
        Ballot {
            acts: c
                .iter()
                .enumerate()
                .map(|(i, c)| Act {
                    seat: i as u8,
                    class: c.clone(),
                    footage: None,
                })
                .collect(),
            outcome_achieved: true,
            misuse: false,
        }
    }

    #[test]
    fn sizes_fees_penalties() {
        assert_eq!(
            (panel_size(1), panel_size(2), panel_size(3), panel_size(4)),
            (3, 7, 15, 31)
        );
        assert_eq!(seat_fee(20_000, 1), 20_000);
        assert_eq!(seat_fee(20_000, 2), 25_000);
        assert_eq!(penalty_factor(3, 1), 2.0);
        assert!(
            (penalty_factor(15, 1) - 4.0).abs() < 1e-9,
            "lone dissenter on 15 pays 4x"
        );
        assert!(
            (penalty_factor(15, 5) - 2.0).abs() < 1e-9,
            "a third dissenting pays 2x"
        );
    }

    #[test]
    fn draw_is_deterministic_and_order_free() {
        let offers: Vec<String> = (0..9).map(|i| format!("arb{i}")).collect();
        let a = draw("00ff", "case", 1, &offers, 3);
        let mut rev = offers.clone();
        rev.reverse();
        assert_eq!(
            a,
            draw("00ff", "case", 1, &rev, 3),
            "arrival order does not matter"
        );
        assert_ne!(
            a,
            draw("00fe", "case", 1, &offers, 3),
            "another block, another panel"
        );
        assert_eq!(a.len(), 3);
    }

    #[test]
    fn two_thirds() {
        use Class::*;
        let (good, bad) = (
            v(&[Intervention, Documentation]),
            v(&[Documentation, Intervention]),
        );
        assert_eq!(
            supermajority(3, &[good.clone(), good.clone(), bad.clone()]),
            Some(good.clone())
        );
        assert_eq!(
            supermajority(3, &[good.clone(), bad.clone()]),
            Option::None,
            "two of three needed"
        );
        let seven: Vec<Ballot> = (0..7)
            .map(|i| if i < 4 { good.clone() } else { bad.clone() })
            .collect();
        assert_eq!(
            supermajority(7, &seven),
            Option::None,
            "4 of 7 is not two thirds"
        );
    }
}
