//! Transactions of an incident: acceptance (the incident transaction), payouts and refunds.
//! All are version 3 with zero fee and a pay-to-anchor output; whoever broadcasts one pays the
//! fee with a child spending the anchor (package relay with TRUC and ephemeral dust, Bitcoin Core 29+).
use crate::scripts::p2a;
use bitcoin::absolute::LockTime;
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::taproot::{LeafVersion, TapLeafHash};
use bitcoin::transaction::Version;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};

pub const VERSION: Version = Version(3);

fn input(op: OutPoint) -> TxIn {
    TxIn {
        previous_output: op,
        script_sig: ScriptBuf::new(),
        sequence: Sequence(0xffff_fffd),
        witness: Witness::new(),
    }
}

fn out(v: u64, spk: ScriptBuf) -> TxOut {
    TxOut {
        value: Amount::from_sat(v),
        script_pubkey: spk,
    }
}

/// Spends the funding output into one output per non-empty pot, plus the anchor.
pub fn incident(funding: OutPoint, pots: &[u64], pot_spk: &ScriptBuf) -> Transaction {
    let mut output: Vec<TxOut> = pots
        .iter()
        .filter(|&&v| v > 0)
        .map(|&v| out(v, pot_spk.clone()))
        .collect();
    output.push(out(0, p2a()));
    Transaction {
        version: VERSION,
        lock_time: LockTime::ZERO,
        input: vec![input(funding)],
        output,
    }
}

/// Pays one pot by one ending.
pub fn payout(pot: OutPoint, outs: &[(u64, ScriptBuf)]) -> Transaction {
    let mut output: Vec<TxOut> = outs.iter().map(|(v, s)| out(*v, s.clone())).collect();
    output.push(out(0, p2a()));
    Transaction {
        version: VERSION,
        lock_time: LockTime::ZERO,
        input: vec![input(pot)],
        output,
    }
}

/// Returns one pot to the caller once `height` is reached (the 90-day refund, one per pot).
pub fn refund(pot: OutPoint, value: u64, caller: &ScriptBuf, height: u32) -> Transaction {
    Transaction {
        version: VERSION,
        lock_time: LockTime::from_height(height).expect("height lock"),
        input: vec![input(pot)],
        output: vec![out(value, caller.clone()), out(0, p2a())],
    }
}

/// BIP341 key-path digest, SIGHASH_DEFAULT.
pub fn keyspend_digest(tx: &Transaction, idx: usize, prevouts: &[TxOut]) -> [u8; 32] {
    let mut c = SighashCache::new(tx);
    let h = c
        .taproot_key_spend_signature_hash(idx, &Prevouts::All(prevouts), TapSighashType::Default)
        .expect("sighash");
    *h.as_ref()
}

/// BIP342 script-path digest for `leaf`, SIGHASH_DEFAULT.
pub fn scriptspend_digest(
    tx: &Transaction,
    idx: usize,
    prevouts: &[TxOut],
    leaf: &ScriptBuf,
) -> [u8; 32] {
    let mut c = SighashCache::new(tx);
    let lh = TapLeafHash::from_script(leaf, LeafVersion::TapScript);
    let h = c
        .taproot_script_spend_signature_hash(
            idx,
            &Prevouts::All(prevouts),
            lh,
            TapSighashType::Default,
        )
        .expect("sighash");
    *h.as_ref()
}

pub fn txout(v: u64, spk: ScriptBuf) -> TxOut {
    out(v, spk)
}
