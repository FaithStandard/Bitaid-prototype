//! The oracle pool on Bitcoin Core regtest: a 7-member pool (threshold 4) made by DKG co-signs a
//! caller's acceptance with FROST while two members are offline and one stalls; the incident's payouts
//! are pre-signed against the pool's jointly generated nonces; four members' public attestation shares
//! combine into the scalar that completes the payout, which confirms on chain.
#[path = "../../bitaid-core/examples/common/mod.rs"]
mod common;
use bitaid_core::endings::Pot;
use bitaid_core::hashes::case_id;
use bitaid_core::oracle::{random_scalar, sign_bip340};
use bitaid_core::outputs::{self, funding_leaf};
use bitaid_core::payouts::Parties;
use bitaid_core::presign::{IncidentSet, IncidentTerms};
use bitaid_core::txbuild;
use bitaid_oracle::cosign::{sign_local, Behaviour};
use bitaid_oracle::{attest, keygen, nonces};
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{Witness, XOnlyPublicKey};
use common::*;
use musig2::secp::{Point, G};
use std::collections::BTreeMap;

fn main() {
    let rpc = rpc_from_env();
    let secp = Secp256k1::new();
    let mut rep = Report(0, 0);
    let (n, t) = (7u16, 4usize);
    let members: Vec<u16> = (1..=n).collect();
    let keys = keygen::run_local(n, t as u16);
    let q = keys[0].pool_key();
    let qx = XOnlyPublicKey::from_slice(&keys[0].xonly()).unwrap();
    let (views, _) = nonces::run_local(&members, t as u16, 3, 1, None);
    let mut views: BTreeMap<u16, nonces::Batch> = views.into_iter().map(|v| (v.me, v)).collect();
    rep.check(
        "Pool key by DKG (7 members, threshold 4) and a batch of jointly generated nonces",
        true,
        &hex::encode(keys[0].xonly()),
    );

    // ---------------------------------------------------------------- funding output naming the pool
    let (w, k) = (random_scalar(), random_scalar());
    let pots = [100_000u64, 600_000, 300_000];
    let total: u64 = pots.iter().sum();
    let ft = outputs::funding(&secp, &xo(&w), &xo(&k), &qx, rpc.height() + 52_560);
    let fop = rpc.fund(&ft.script_pubkey(), total);
    let resp: Vec<_> = (0..3).map(|_| random_scalar()).collect();
    let mut secrets = vec![k];
    secrets.extend(resp.iter().copied());
    let signers: Vec<Point> = secrets.iter().map(|s| *s * G).collect();
    let pot_spk = bitaid_core::musig::pot_script_pubkey(&bitaid_core::musig::taproot_ctx(&signers));
    let mut inc = txbuild::incident(fop, &pots, &pot_spk);
    let leaf = &ft.scripts[funding_leaf::ACCEPT];
    let d =
        txbuild::scriptspend_digest(&inc, 0, &[txbuild::txout(total, ft.script_pubkey())], leaf);
    let mut beh = BTreeMap::new();
    beh.insert(1, Behaviour::Offline);
    beh.insert(2, Behaviour::Offline);
    beh.insert(5, Behaviour::Stalls);
    let co = sign_local(&keys, &beh, t, &d).expect("co-signature");
    inc.input[0].witness = Witness::from_slice(&[
        co.signature.to_vec(),
        sign_bip340(&k, &d).to_vec(),
        leaf.to_bytes(),
        ft.control(funding_leaf::ACCEPT).serialize(),
    ]);
    let r = rpc.package(&inc);
    rep.check("Acceptance co-signed by the pool with FROST (2 offline, 1 stalling, replaced) and confirmed", r.is_ok(),
        &format!("{} sessions, signers {:?}; {}", co.sessions, co.signers, reasons(&r)));
    rpc.mine(1);

    // ---------------------------------------------------------------- pre-signed set against the pool
    let case = case_id(&format!("pool-{}", rpc.height()));
    let responders: Vec<_> = (0..3).map(|_| rpc.new_spk()).collect();
    let q_even = if q.has_even_y() { q } else { -q };
    let terms = IncidentTerms {
        case_id: case,
        set_version: 0,
        pots,
        parties: Parties {
            caller: rpc.new_spk(),
            responders: responders.clone(),
            merit: vec![1, 1, 1],
            good_faith_pct: 50,
        },
        signers,
        oracle: q_even,
        oracle_nonces: [views[&1].r[0], views[&1].r[1], views[&1].r[2]],
        refund_height: rpc.height() + 12_960,
    };
    let mut set = IncidentSet::build(terms, inc.compute_txid());
    set.sign_locally(&secrets);
    rep.check(
        "Payout set pre-signed against the pool's nonce points",
        set.verify_all(),
        &format!("{} payouts", set.len()),
    );

    // ---------------------------------------------------------------- attestation by any four members
    let ends = [
        (Pot::Deposit, "returned"),
        (Pot::Reward, "paid (6, 4, 0)"),
        (Pot::Bounty, "split (4, 3, 3)"),
    ];
    for (pot, label) in ends {
        let m = set.message(pot, label).unwrap();
        let mut shares = Vec::new();
        for id in [3u16, 4, 6, 7] {
            shares.push(
                attest::share(
                    &keys[id as usize - 1],
                    views.get_mut(&id).unwrap(),
                    pot.index(),
                    &m,
                )
                .unwrap(),
            );
        }
        let s = attest::combine(&keys[0], &views[&1], &shares, t).expect("combine");
        let tx = set.complete(pot, label, s).expect("completes");
        let r = rpc.package(&tx);
        rep.check(
            &format!(
                "{}: \"{label}\" completed by four members' public attestation shares and accepted",
                pot.name()
            ),
            r.is_ok(),
            &reasons(&r),
        );
    }
    rpc.mine(1);
    rep.check(
        "All three pots paid on chain",
        set.pot_outpoints.iter().flatten().all(|op| rpc.spent(op)),
        "",
    );

    println!("{} passed, {} failed", rep.0, rep.1);
    std::process::exit(if rep.1 == 0 { 0 } else { 1 });
}
