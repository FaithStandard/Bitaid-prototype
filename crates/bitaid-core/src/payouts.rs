//! Amounts and destinations of each ending.
//!
//! Rules (deterministic, so every signer builds byte-identical transactions):
//! * shares are `value × buckets / units`, rounded down;
//! * the rounding remainder goes to the recipient with the largest share (the first, on a tie);
//! * a share below the dust limit of a taproot output (330 sat) is merged into the largest;
//! * the good-faith share is `good_faith_pct` of the pot, split by the vector; the rest returns to the caller.
use crate::endings::{Ending, EndingKind};
use bitcoin::ScriptBuf;

pub const DUST: u64 = 330;

#[derive(Clone, Debug)]
pub struct Parties {
    pub caller: ScriptBuf,
    pub responders: Vec<ScriptBuf>,
    /// Merit weights fixed at acceptance, one per signing responder.
    pub merit: Vec<u32>,
    pub good_faith_pct: u64,
}

fn by_weights(value: u64, weights: &[u32], to: &[ScriptBuf]) -> Vec<(u64, ScriptBuf)> {
    let total: u64 = weights.iter().map(|&w| w as u64).sum();
    assert!(total > 0, "weights must not all be zero");
    let mut shares: Vec<(u64, usize)> = weights
        .iter()
        .enumerate()
        .filter(|(_, &w)| w > 0)
        .map(|(i, &w)| (value * w as u64 / total, i))
        .collect();
    let paid: u64 = shares.iter().map(|s| s.0).sum();
    // largest share, first on a tie, takes the rounding remainder
    let big = (0..shares.len())
        .max_by(|&a, &b| shares[a].0.cmp(&shares[b].0).then(b.cmp(&a)))
        .unwrap();
    shares[big].0 += value - paid;
    let big_id = shares[big].1;
    // shares below dust are merged into the largest
    let dust: u64 = shares
        .iter()
        .filter(|s| s.1 != big_id && s.0 < DUST)
        .map(|s| s.0)
        .sum();
    shares.retain(|s| s.1 == big_id || s.0 >= DUST);
    if let Some(b) = shares.iter_mut().find(|s| s.1 == big_id) {
        b.0 += dust;
    }
    shares
        .into_iter()
        .map(|(v, i)| (v, to[i].clone()))
        .collect()
}

/// Outputs of `ending` for a pot holding `value` sats (excluding the anchor).
pub fn outputs(ending: &Ending, value: u64, p: &Parties) -> Vec<(u64, ScriptBuf)> {
    match &ending.kind {
        EndingKind::ToCaller => vec![(value, p.caller.clone())],
        EndingKind::SeizedByMerit => by_weights(value, &p.merit, &p.responders),
        EndingKind::SeizedToHarmed(i) => vec![(value, p.responders[*i].clone())],
        EndingKind::Split(v) => by_weights(value, v, &p.responders),
        EndingKind::GoodFaith(v) => {
            let paid = value * p.good_faith_pct / 100;
            let mut o = by_weights(paid, v, &p.responders);
            if value - paid > 0 {
                o.push((value - paid, p.caller.clone()));
            }
            o
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::endings::endings;
    #[test]
    fn every_ending_pays_the_whole_pot() {
        let spk =
            |b: u8| ScriptBuf::from_bytes(vec![0x51, 0x20].into_iter().chain([b; 32]).collect());
        let p = Parties {
            caller: spk(0),
            responders: (1..=5).map(spk).collect(),
            merit: vec![3, 1, 2, 0, 1],
            good_faith_pct: 50,
        };
        for v in [1_000u64, 100_001, 600_000, 9_999_999] {
            for e in endings(5) {
                let o = outputs(&e, v, &p);
                assert_eq!(o.iter().map(|x| x.0).sum::<u64>(), v, "{} {}", e.label, v);
                if v >= 100_000 {
                    assert!(o.iter().all(|x| x.0 >= DUST), "{} {}", e.label, v);
                }
            }
        }
    }
}
