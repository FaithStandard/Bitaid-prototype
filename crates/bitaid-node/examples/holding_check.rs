//! The holding output on regtest (B.1): the oracle pool's key alone cannot move a seized entry bond;
//! the oracle with a majority of the archivist committee can; the arbitrator's cold key alone can take
//! it back only HOLD_RETURN blocks after the seizure confirmed.
//!   BITAID_RPC=http://bitaid:regtest@127.0.0.1:18443 BITAID_WALLET=w cargo run --release --example holding_check
use bitaid_core::oracle::{random_scalar, sign_bip340};
use bitaid_core::txbuild;
use bitaid_node::arb::{holding_tree, HOLD_RETURN};
use bitaid_node::chain::Rpc;
use bitaid_node::node::xo;
use bitcoin::consensus::encode::serialize_hex;
use bitcoin::{Transaction, Witness};
use serde_json::json;

fn main() {
    let rpc = Rpc::from_env();
    let (o, cold) = (random_scalar(), random_scalar());
    let arch: Vec<_> = (0..3).map(|_| random_scalar()).collect();
    let holders: Vec<_> = arch.iter().map(xo).collect();
    let (t, pol) = holding_tree(&xo(&o), &holders, &xo(&cold)).unwrap();
    // the archivists in the script's order
    let arch: Vec<_> = pol
        .devices
        .iter()
        .map(|k| *arch.iter().find(|s| xo(s) == *k).unwrap())
        .collect();
    let spk = t.script_pubkey();
    let value = 1_000_000u64;
    let to = rpc.new_spk().unwrap();
    let send = |tx: &Transaction| rpc.call("sendrawtransaction", json!([serialize_hex(tx)]));
    let fresh = || {
        let op = rpc.fund(&spk, value).unwrap();
        rpc.mine(1).unwrap();
        op
    };
    let spend = |op, seq: bitcoin::Sequence| {
        let mut tx = txbuild::payout(op, &[(value - 2_000, to.clone())]);
        tx.output.retain(|o| o.value.to_sat() > 0);
        tx.input[0].sequence = seq;
        tx
    };
    let digest = |tx: &Transaction, leaf: usize| {
        txbuild::scriptspend_digest(tx, 0, &[txbuild::txout(value, spk.clone())], &t.scripts[leaf])
    };
    let leaf_wit = |items: Vec<Vec<u8>>, leaf: usize| {
        let mut v = items;
        v.push(t.scripts[leaf].to_bytes());
        v.push(t.control(leaf).serialize());
        Witness::from_slice(&v)
    };
    // the committee's leaf: oracle, then arch[2], arch[1], arch[0] (CHECKSIGADD order, last key on top)
    let op1 = fresh();
    let mut tx = spend(op1, bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME);
    let d = digest(&tx, 0);
    let os = sign_bip340(&o, &d).to_vec();
    // 1. the oracle alone (no archivist signature)
    tx.input[0].witness = leaf_wit(vec![os.clone(), vec![], vec![], vec![]], 0);
    println!("oracle pool alone: {}", if send(&tx).is_ok() { "ACCEPTED (bad)" } else { "refused" });
    // 2. the oracle with one archivist of three
    tx.input[0].witness = leaf_wit(vec![os.clone(), vec![], vec![], sign_bip340(&arch[0], &d).to_vec()], 0);
    println!("oracle + 1 of 3 archivists: {}", if send(&tx).is_ok() { "ACCEPTED (bad)" } else { "refused" });
    // 3. three archivists without the oracle
    tx.input[0].witness = leaf_wit(
        vec![vec![0u8; 64], sign_bip340(&arch[2], &d).to_vec(), sign_bip340(&arch[1], &d).to_vec(), sign_bip340(&arch[0], &d).to_vec()],
        0,
    );
    println!("3 of 3 archivists, no oracle: {}", if send(&tx).is_ok() { "ACCEPTED (bad)" } else { "refused" });
    // 4. the oracle with a majority (2 of 3)
    tx.input[0].witness = leaf_wit(
        vec![os.clone(), vec![], sign_bip340(&arch[1], &d).to_vec(), sign_bip340(&arch[0], &d).to_vec()],
        0,
    );
    println!("oracle + 2 of 3 archivists (threshold {}): {}", pol.threshold, match send(&tx) { Ok(_) => "accepted".to_string(), Err(e) => format!("REFUSED: {e}") });
    // the cold key alone, before and after HOLD_RETURN
    let op2 = fresh();
    let mut tx = spend(op2, bitcoin::Sequence::from_height(HOLD_RETURN as u16));
    let d = digest(&tx, 1);
    tx.input[0].witness = leaf_wit(vec![sign_bip340(&cold, &d).to_vec()], 1);
    println!("cold key alone, 1 block after: {}", if send(&tx).is_ok() { "ACCEPTED (bad)" } else { "refused" });
    for _ in 0..HOLD_RETURN.div_ceil(500) {
        rpc.mine(500).unwrap();
    }
    println!("cold key alone, {HOLD_RETURN} blocks after: {}", match send(&tx) { Ok(_) => "accepted".to_string(), Err(e) => format!("REFUSED: {e}") });
}
