//! Where seized money goes (Specification §12, Appendix B.1), on Bitcoin Core regtest.
//!
//! An arbitrator's bond is forfeited by its pre-signed forfeiture, which pays restitution to the
//! harmed party directly and everything else to the case's seizure output. The seizure output is then
//! distributed only by the oracle pool together with a majority of the case's archivists: neither
//! group alone, and not too few archivists, can move it. If no distribution is signed in time, the
//! oracle pool with a majority of the case's parties pays it out after the relative timelock (one year
//! in the protocol; 10 blocks here), never the pool alone; last, after twice that, the parties' key.
mod common;
use bitaid_core::oracle::{random_scalar, sign_bip340, Oracle};
use bitaid_core::outputs::{self, bond_leaf, seizure_leaf};
use bitaid_core::scripts::KeyPolicy;
use bitaid_core::txbuild;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{Sequence, Witness};
use common::*;
use musig2::secp::Scalar;

const LOCK: u32 = 10;

fn main() {
    let rpc = rpc_from_env();
    let secp = Secp256k1::new();
    let mut rep = Report(0, 0);
    let oracle = Oracle::new();
    let ox = xo(&oracle.secret_for_tests());
    let archivists: Vec<Scalar> = (0..5).map(|_| random_scalar()).collect();
    let apol = KeyPolicy::of(3, archivists.iter().map(xo).collect());
    let harmed = random_scalar();
    let parties: Vec<Scalar> = (0..3).map(|_| random_scalar()).collect();
    let ppol = KeyPolicy::of(2, parties.iter().map(xo).collect());
    let seiz = outputs::seizure(&secp, &apol, &ox, &xo(&harmed), &ppol, LOCK);
    let harmed_spk = rpc.new_spk();

    // ---------------------------------------------------------------- an arbitrator's bond, forfeited
    let (kop, cold) = (random_scalar(), random_scalar());
    let bt = outputs::bond(&secp, &xo(&kop), &xo(&cold), &ox, rpc.height() + 52_560);
    let bv = 2_000_000u64;
    let forfeit_once = |rep: &mut Report, label: &str| {
        let bop = rpc.fund(&bt.script_pubkey(), bv);
        let restitution = 800_000u64;
        let mut f = txbuild::payout(
            bop,
            &[
                (restitution, harmed_spk.clone()),
                (bv - restitution, seiz.script_pubkey()),
            ],
        );
        let leaf = &bt.scripts[bond_leaf::FORFEIT];
        let d = txbuild::scriptspend_digest(&f, 0, &[txbuild::txout(bv, bt.script_pubkey())], leaf);
        let pre = sign_bip340(&kop, &d); // pre-signed when the arbitrator took the seat
        f.input[0].witness = Witness::from_slice(&[
            oracle.cosign(&d).to_vec(),
            pre.to_vec(),
            leaf.to_bytes(),
            bt.control(bond_leaf::FORFEIT).serialize(),
        ]);
        let r = rpc.package(&f);
        rep.check(label, r.is_ok(), &reasons(&r));
        rpc.mine(1);
        bitcoin::OutPoint {
            txid: f.compute_txid(),
            vout: 1,
        }
    };
    let sop = forfeit_once(&mut rep, "Forfeiture: restitution paid directly to the harmed party, the rest into the case's seizure output");
    let sv = bv - 800_000;

    // ---------------------------------------------------------------- distribution
    let reviewers: Vec<_> = (0..3).map(|_| rpc.new_spk()).collect();
    let arch_spks: Vec<_> = (0..5).map(|_| rpc.new_spk()).collect();
    let mut outs: Vec<(u64, bitcoin::ScriptBuf)> =
        reviewers.iter().map(|s| (60_000, s.clone())).collect(); // review premium
    outs.push((90_000, rpc.new_spk())); // panel fees
    outs.extend(arch_spks.iter().map(|s| (4_000, s.clone()))); // retention, 20 years at the case's rate
    let paid: u64 = outs.iter().map(|o| o.0).sum();
    outs.push((sv - paid, harmed_spk.clone())); // the excess back to the harmed party
    let mut dist = txbuild::payout(sop, &outs);
    let prev = [txbuild::txout(sv, seiz.script_pubkey())];
    let leaf = &seiz.scripts[seizure_leaf::DISTRIBUTE];
    let ctl = seiz.control(seizure_leaf::DISTRIBUTE).serialize();
    let d = txbuild::scriptspend_digest(&dist, 0, &prev, leaf);
    let wit = |orc: bool, signers: &[usize]| {
        let mut items: Vec<Vec<u8>> = vec![if orc {
            oracle.cosign(&d).to_vec()
        } else {
            vec![]
        }];
        for i in (0..5).rev() {
            items.push(if signers.contains(&i) {
                sign_bip340(&archivists[i], &d).to_vec()
            } else {
                vec![]
            });
        }
        items.push(leaf.to_bytes());
        items.push(ctl.clone());
        Witness::from_slice(&items)
    };
    dist.input[0].witness = wit(true, &[]);
    let r = rpc.package(&dist);
    rep.check("Seizure output: the oracle pool alone cannot distribute it (a captured majority takes nothing)", r.is_err() && reasons(&r).contains("script-verify"), &reasons(&r));
    dist.input[0].witness = wit(false, &[0, 1, 2]);
    let r = rpc.package(&dist);
    rep.check(
        "Seizure output: a majority of archivists (3 of 5) without the oracle cannot distribute it",
        r.is_err(),
        &reasons(&r),
    );
    dist.input[0].witness = wit(true, &[0, 3]);
    let r = rpc.package(&dist);
    rep.check(
        "Seizure output: the oracle with too few archivists (2 of 5) is refused",
        r.is_err() && reasons(&r).contains("script-verify"),
        &reasons(&r),
    );
    dist.input[0].witness = wit(true, &[1, 2, 4]);
    let r = rpc.package(&dist);
    rep.check("Seizure output: oracle + 3 of 5 archivists pay reviewers, panel, retention and the excess to the harmed party", r.is_ok(), &reasons(&r));
    rpc.mine(1);

    // ---------------------------------------------------------------- the pool's fallback
    // archivists gone: after the lock the oracle pool pays the seizure out by its replay, with a
    // majority of the case's parties, so neither one holdout party nor a captured pool alone decides
    let sop2 = forfeit_once(&mut rep, "A second forfeiture into a fresh seizure output");
    let mut pool = txbuild::payout(sop2, &[(sv, harmed_spk.clone())]);
    pool.input[0].sequence = Sequence(LOCK);
    let pl = seiz.scripts[seizure_leaf::POOL].clone();
    let pctl = seiz.control(seizure_leaf::POOL).serialize();
    let dp = txbuild::scriptspend_digest(&pool, 0, &prev, &pl);
    let pwit = |orc: bool, signers: &[usize]| {
        let mut items: Vec<Vec<u8>> = vec![if orc { oracle.cosign(&dp).to_vec() } else { vec![] }];
        for i in (0..3).rev() {
            items.push(if signers.contains(&i) { sign_bip340(&parties[i], &dp).to_vec() } else { vec![] });
        }
        items.push(pl.to_bytes());
        items.push(pctl.clone());
        Witness::from_slice(&items)
    };
    pool.input[0].witness = pwit(true, &[0, 2]);
    let early = rpc.package(&pool);
    rep.check(
        "Fallback: the oracle pool with 2 of 3 parties is refused before the timelock",
        early.is_err() && reasons(&early).contains("non-BIP68-final"),
        &reasons(&early),
    );
    rpc.mine(LOCK);
    pool.input[0].witness = pwit(true, &[]);
    let r = rpc.package(&pool);
    rep.check(
        "Fallback: after the timelock the oracle pool alone is still refused (a captured pool cannot pay itself)",
        r.is_err() && reasons(&r).contains("script-verify"),
        &reasons(&r),
    );
    pool.input[0].witness = pwit(true, &[1]);
    let r = rpc.package(&pool);
    rep.check(
        "Fallback: the oracle pool with 1 of 3 parties is refused",
        r.is_err() && reasons(&r).contains("script-verify"),
        &reasons(&r),
    );
    pool.input[0].witness = pwit(false, &[0, 1, 2]);
    let r = rpc.package(&pool);
    rep.check(
        "Fallback: every party without the oracle pool is refused before the parties' own lock",
        r.is_err() && reasons(&r).contains("script-verify"),
        &reasons(&r),
    );
    pool.input[0].witness = pwit(true, &[0, 2]);
    let late = rpc.package(&pool);
    rep.check("Fallback: archivists gone a year — the oracle pool with 2 of 3 parties pays out the seizure output (one holdout cannot stop it)", late.is_ok(), &reasons(&late));
    rpc.mine(1);

    // ---------------------------------------------------------------- the parties' last resort
    let sop3 = forfeit_once(&mut rep, "A third forfeiture into a fresh seizure output");
    let mut back = txbuild::payout(sop3, &[(sv, harmed_spk.clone())]);
    back.input[0].sequence = Sequence(LOCK);
    let fl = &seiz.scripts[seizure_leaf::FALLBACK];
    let db = txbuild::scriptspend_digest(&back, 0, &prev, fl);
    back.input[0].witness = Witness::from_slice(&[
        sign_bip340(&harmed, &db).to_vec(),
        fl.to_bytes(),
        seiz.control(seizure_leaf::FALLBACK).serialize(),
    ]);
    rpc.mine(LOCK);
    let early = rpc.package(&back);
    rep.check(
        "Fallback: the parties are refused when only the pool's timelock has passed",
        early.is_err() && reasons(&early).contains("script-verify"),
        &reasons(&early),
    );
    back.input[0].sequence = Sequence(2 * LOCK);
    let db = txbuild::scriptspend_digest(&back, 0, &prev, fl);
    back.input[0].witness = Witness::from_slice(&[
        sign_bip340(&harmed, &db).to_vec(),
        fl.to_bytes(),
        seiz.control(seizure_leaf::FALLBACK).serialize(),
    ]);
    rpc.mine(LOCK);
    let late = rpc.package(&back);
    rep.check("Fallback: pool and archivists both gone — the parties take the seizure output last", late.is_ok(), &reasons(&late));
    rpc.mine(1);

    println!("{} passed, {} failed", rep.0, rep.1);
    std::process::exit(if rep.1 == 0 { 0 } else { 1 });
}
