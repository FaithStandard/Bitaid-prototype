//! Scoped keys held on two or three devices (Specification B.1, B.4, §14.3), on Bitcoin Core regtest.
//!
//! * An arbitrator's bond whose scoped key is 2-of-2 (node and phone): a forfeiture signed by one
//!   device with the oracle is refused; with both devices it completes.
//! * A caller's funding output whose scoped key is 2-of-3 (phone, node, delegate): with the phone
//!   lost, node + delegate + oracle accept the incident; one device + oracle is refused; and the
//!   oracle is still required with any two devices.
mod common;
use bitaid_core::oracle::{random_scalar, sign_bip340, Oracle};
use bitaid_core::outputs::{self, bond_leaf, funding_leaf};
use bitaid_core::scripts::KeyPolicy;
use bitaid_core::txbuild;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::Witness;
use common::*;
use musig2::secp::{Scalar, G};

/// Witness for a policy leaf: oracle signature at the bottom, then device signatures in reverse
/// key order, empty for devices that do not sign.
fn policy_witness(
    oracle_sig: Option<[u8; 64]>,
    devices: &[(Scalar, bool)],
    digest: &[u8; 32],
    leaf: &bitcoin::ScriptBuf,
    control: Vec<u8>,
) -> Witness {
    let mut items: Vec<Vec<u8>> = vec![oracle_sig.map(|s| s.to_vec()).unwrap_or_default()];
    for (sk, signs) in devices.iter().rev() {
        items.push(if *signs {
            sign_bip340(sk, digest).to_vec()
        } else {
            vec![]
        });
    }
    items.push(leaf.to_bytes());
    items.push(control);
    Witness::from_slice(&items)
}

fn main() {
    let rpc = rpc_from_env();
    let secp = Secp256k1::new();
    let mut rep = Report(0, 0);
    let oracle = Oracle::new();
    let ox = xo(&oracle.secret_for_tests());

    // ---------------------------------------------------------------- arbitrator bond, 2-of-2
    let (node, phone, cold) = (random_scalar(), random_scalar(), random_scalar());
    let pol = KeyPolicy::of(2, vec![xo(&node), xo(&phone)]);
    let bt = outputs::bond_with(&secp, &pol, &xo(&cold), &ox, rpc.height() + 52_560);
    let bv = 200_000u64;
    let bop = rpc.fund(&bt.script_pubkey(), bv);
    let prev = [txbuild::txout(bv, bt.script_pubkey())];
    let leaf = &bt.scripts[bond_leaf::FORFEIT];
    let mut tx = txbuild::payout(bop, &[(bv, rpc.new_spk())]);
    let d = txbuild::scriptspend_digest(&tx, 0, &prev, leaf);
    let ctl = bt.control(bond_leaf::FORFEIT).serialize();
    tx.input[0].witness = policy_witness(
        Some(oracle.cosign(&d)),
        &[(node, true), (phone, false)],
        &d,
        leaf,
        ctl.clone(),
    );
    let r = rpc.package(&tx);
    rep.check(
        "2-of-2 bond: the node alone (with the oracle) is refused",
        r.is_err() && reasons(&r).contains("script-verify"),
        &reasons(&r),
    );
    tx.input[0].witness = policy_witness(
        Some(oracle.cosign(&d)),
        &[(node, false), (phone, true)],
        &d,
        leaf,
        ctl.clone(),
    );
    let r = rpc.package(&tx);
    rep.check(
        "2-of-2 bond: the phone alone (with the oracle) is refused",
        r.is_err() && reasons(&r).contains("script-verify"),
        &reasons(&r),
    );
    tx.input[0].witness =
        policy_witness(None, &[(node, true), (phone, true)], &d, leaf, ctl.clone());
    let r = rpc.package(&tx);
    rep.check(
        "2-of-2 bond: both devices without the oracle are refused",
        r.is_err(),
        &reasons(&r),
    );
    tx.input[0].witness = policy_witness(
        Some(oracle.cosign(&d)),
        &[(node, true), (phone, true)],
        &d,
        leaf,
        ctl,
    );
    let r = rpc.package(&tx);
    rep.check(
        "2-of-2 bond: node + phone + oracle complete the forfeiture",
        r.is_ok(),
        &reasons(&r),
    );
    rpc.mine(1);

    // ---------------------------------------------------------------- caller funding, 2-of-3
    let (w, cphone, cnode, deleg) = (
        random_scalar(),
        random_scalar(),
        random_scalar(),
        random_scalar(),
    );
    let cpol = KeyPolicy::of(2, vec![xo(&cphone), xo(&cnode), xo(&deleg)]);
    let ft = outputs::funding_with(&secp, &xo(&w), &cpol, &ox, rpc.height() + 52_560);
    let total = 1_000_000u64;
    let fop = rpc.fund(&ft.script_pubkey(), total);
    let pot_ctx = bitaid_core::musig::taproot_ctx(&[random_scalar() * G, random_scalar() * G]);
    let pot_spk = bitaid_core::musig::pot_script_pubkey(&pot_ctx);
    let mut inc = txbuild::incident(fop, &[100_000, 600_000, 300_000], &pot_spk);
    let prev = [txbuild::txout(total, ft.script_pubkey())];
    let leaf = &ft.scripts[funding_leaf::ACCEPT];
    let d = txbuild::scriptspend_digest(&inc, 0, &prev, leaf);
    let ctl = ft.control(funding_leaf::ACCEPT).serialize();
    inc.input[0].witness = policy_witness(
        Some(oracle.cosign(&d)),
        &[(cphone, false), (cnode, true), (deleg, false)],
        &d,
        leaf,
        ctl.clone(),
    );
    let r = rpc.package(&inc);
    rep.check(
        "2-of-3 funding: one device (the node) with the oracle is refused",
        r.is_err() && reasons(&r).contains("script-verify"),
        &reasons(&r),
    );
    inc.input[0].witness = policy_witness(
        None,
        &[(cphone, false), (cnode, true), (deleg, true)],
        &d,
        leaf,
        ctl.clone(),
    );
    let r = rpc.package(&inc);
    rep.check(
        "2-of-3 funding: two devices without the oracle are refused",
        r.is_err(),
        &reasons(&r),
    );
    inc.input[0].witness = policy_witness(
        Some(oracle.cosign(&d)),
        &[(cphone, false), (cnode, true), (deleg, true)],
        &d,
        leaf,
        ctl,
    );
    let r = rpc.package(&inc);
    rep.check(
        "2-of-3 funding: phone lost — node + delegate + oracle accept the incident",
        r.is_ok(),
        &reasons(&r),
    );
    rpc.mine(1);
    let wsz = inc.input[0].witness.size();
    rep.check(
        "Witness size of the 2-of-3 acceptance",
        true,
        &format!("{wsz} bytes (single scoped key: about 270)"),
    );

    println!("{} passed, {} failed", rep.0, rep.1);
    std::process::exit(if rep.1 == 0 { 0 } else { 1 });
}
