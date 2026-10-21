//! End-to-end incident on a Bitcoin Core regtest node, driven by the Rust core:
//! funding output → incident transaction (scoped key + oracle co-signature, zero fee, package relay)
//! → full pre-signed set (387 payouts + refunds, adaptor signatures) → oracle attestations → three
//! payouts confirmed; then the refund path, a bond forfeiture, the funding fallback, and the
//! transactions that must be refused.
//!
//! Run against a regtest node with a funded wallet "w":
//!   BITAID_CLI="bitcoin-cli -regtest -rpcuser=u -rpcpassword=p -rpcport=18543" \
//!   cargo run --release --example regtest_incident
use bitaid_core::endings::Pot;
use bitaid_core::hashes::outcome_msg;
use bitaid_core::oracle::{random_scalar, sign_bip340, Oracle};
use bitaid_core::outputs::{self, bond_leaf, funding_leaf};
use bitaid_core::payouts::Parties;
use bitaid_core::presign::{event_id, IncidentSet, IncidentTerms};
use bitaid_core::txbuild;
use bitcoin::consensus::encode::{deserialize_hex, serialize_hex};
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{
    Address, Amount, Network, OutPoint, ScriptBuf, Transaction, TxIn, TxOut, Txid, Witness,
    XOnlyPublicKey,
};
use musig2::secp::{Point, Scalar, G};
use serde_json::{json, Value};
use std::process::Command;
use std::str::FromStr;

struct Rpc(
    Vec<String>,
    std::cell::RefCell<std::collections::HashSet<String>>,
);
impl Rpc {
    fn call(&self, wallet: bool, args: &[&str]) -> Result<Value, String> {
        let mut c = Command::new(&self.0[0]);
        c.args(&self.0[1..]);
        if wallet {
            c.arg("-rpcwallet=w");
        }
        let o = c.args(args).output().map_err(|e| e.to_string())?;
        if !o.status.success() {
            return Err(String::from_utf8_lossy(&o.stderr).trim().to_string());
        }
        let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
        Ok(serde_json::from_str(&s).unwrap_or(Value::String(s)))
    }
    fn n(&self, args: &[&str]) -> Value {
        self.call(false, args)
            .unwrap_or_else(|e| panic!("{args:?}: {e}"))
    }
    fn w(&self, args: &[&str]) -> Value {
        self.call(true, args)
            .unwrap_or_else(|e| panic!("{args:?}: {e}"))
    }
    fn height(&self) -> u32 {
        self.n(&["getblockcount"]).as_u64().unwrap() as u32
    }
    fn mine(&self, k: u32) {
        let a = self.w(&["getnewaddress"]);
        self.n(&["generatetoaddress", &k.to_string(), a.as_str().unwrap()]);
    }
    fn new_spk(&self) -> ScriptBuf {
        let a = self.w(&["getnewaddress", "", "bech32m"]);
        Address::from_str(a.as_str().unwrap())
            .unwrap()
            .require_network(Network::Regtest)
            .unwrap()
            .script_pubkey()
    }
    /// Sends `sats` to `spk`, mines it, returns the outpoint.
    fn fund(&self, spk: &ScriptBuf, sats: u64) -> OutPoint {
        let addr = Address::from_script(spk, Network::Regtest)
            .unwrap()
            .to_string();
        let txid = self.w(&["sendtoaddress", &addr, &format!("{:.8}", sats as f64 / 1e8)]);
        let txid = txid.as_str().unwrap().to_string();
        let raw = self.w(&["gettransaction", &txid]);
        let tx: Transaction = deserialize_hex(raw["hex"].as_str().unwrap()).unwrap();
        let vout = tx
            .output
            .iter()
            .position(|o| &o.script_pubkey == spk)
            .unwrap() as u32;
        self.mine(1);
        OutPoint {
            txid: Txid::from_str(&txid).unwrap(),
            vout,
        }
    }
    /// Submits a zero-fee version-3 parent with a fee-paying child spending its anchor.
    fn package(&self, parent: &Transaction) -> Result<(), String> {
        let anchor = parent
            .output
            .iter()
            .position(|o| o.script_pubkey == bitaid_core::scripts::p2a())
            .unwrap() as u32;
        let utxos = self.w(&["listunspent", "1"]);
        let used = self.1.borrow().clone();
        let u = utxos
            .as_array()
            .unwrap()
            .iter()
            .find(|u| {
                u["amount"].as_f64().unwrap() > 0.01
                    && !used.contains(&format!("{}:{}", u["txid"].as_str().unwrap(), u["vout"]))
            })
            .unwrap();
        self.1
            .borrow_mut()
            .insert(format!("{}:{}", u["txid"].as_str().unwrap(), u["vout"]));
        let uval = (u["amount"].as_f64().unwrap() * 1e8).round() as u64;
        let child = Transaction {
            version: txbuild::VERSION,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![
                TxIn {
                    previous_output: OutPoint {
                        txid: parent.compute_txid(),
                        vout: anchor,
                    },
                    ..Default::default()
                },
                TxIn {
                    previous_output: OutPoint {
                        txid: Txid::from_str(u["txid"].as_str().unwrap()).unwrap(),
                        vout: u["vout"].as_u64().unwrap() as u32,
                    },
                    ..Default::default()
                },
            ],
            output: vec![TxOut {
                value: Amount::from_sat(uval - 20_000),
                script_pubkey: self.new_spk(),
            }],
        };
        let prev = json!([{"txid": parent.compute_txid().to_string(), "vout": anchor, "scriptPubKey": "51024e73", "amount": 0}]);
        let signed = self.w(&[
            "signrawtransactionwithwallet",
            &serialize_hex(&child),
            &prev.to_string(),
        ]);
        let r = self.call(
            false,
            &[
                "submitpackage",
                &json!([serialize_hex(parent), signed["hex"].as_str().unwrap()]).to_string(),
            ],
        )?;
        if r["package_msg"] == "success" {
            Ok(())
        } else {
            Err(r.to_string())
        }
    }
    fn spent(&self, op: &OutPoint) -> bool {
        matches!(self.call(false, &["gettxout", &op.txid.to_string(), &op.vout.to_string()]), Ok(Value::String(ref s)) if s.is_empty())
    }
}

/// The node's rejection reasons from a failed package submission.
fn reasons(r: &Result<(), String>) -> String {
    match r {
        Ok(()) => "accepted".into(),
        Err(e) => match serde_json::from_str::<Value>(e) {
            Ok(v) => v["tx-results"]
                .as_object()
                .map(|m| {
                    m.values()
                        .filter_map(|x| x["error"].as_str())
                        .collect::<Vec<_>>()
                        .join("; ")
                })
                .unwrap_or(e.clone()),
            Err(_) => e.clone(),
        },
    }
}

fn xo(s: &Scalar) -> XOnlyPublicKey {
    XOnlyPublicKey::from_slice(&(*s * G).serialize_xonly()).unwrap()
}

struct Report(u32, u32);
impl Report {
    fn check(&mut self, name: &str, ok: bool, detail: &str) {
        if ok {
            self.0 += 1
        } else {
            self.1 += 1
        }
        println!(
            "[{}] {name}{}",
            if ok { "PASS" } else { "FAIL" },
            if detail.is_empty() {
                String::new()
            } else {
                format!(" — {detail}")
            }
        );
    }
}

fn main() {
    let cli = std::env::var("BITAID_CLI")
        .unwrap_or("bitcoin-cli -regtest -rpcuser=u -rpcpassword=p -rpcport=18543".into());
    let rpc = Rpc(
        cli.split_whitespace().map(String::from).collect(),
        Default::default(),
    );
    let secp = Secp256k1::new();
    let mut rep = Report(0, 0);
    let mut oracle = Oracle::new();
    let ox = xo(&oracle.secret_for_tests());
    let (w, k) = (random_scalar(), random_scalar());
    let case = format!("case-{}", rpc.height());

    // ---------------------------------------------------------------- funding output
    let pots = [100_000u64, 600_000, 300_000];
    let total: u64 = pots.iter().sum();
    let fb_height = rpc.height() + 52_560;
    let ftree = outputs::funding(&secp, &xo(&w), &xo(&k), &ox, fb_height);
    let fop = rpc.fund(&ftree.script_pubkey(), total);
    rep.check(
        "Funding output created (no key path; wallet+oracle, scoped+oracle, wallet after 365 days)",
        true,
        &fop.to_string(),
    );

    // ---------------------------------------------------------------- acceptance
    let resp_secrets: Vec<Scalar> = (0..5).map(|_| random_scalar()).collect();
    let mut secrets = vec![k];
    secrets.extend(resp_secrets.iter().copied());
    let signers: Vec<Point> = secrets.iter().map(|s| *s * G).collect();
    let pot_ctx = bitaid_core::musig::taproot_ctx(&signers);
    let pot_spk = bitaid_core::musig::pot_script_pubkey(&pot_ctx);
    let mut inc = txbuild::incident(fop, &pots, &pot_spk);
    let prev_f = [txbuild::txout(total, ftree.script_pubkey())];
    let leaf = &ftree.scripts[funding_leaf::ACCEPT];
    let d = txbuild::scriptspend_digest(&inc, 0, &prev_f, leaf);
    // the scoped key alone must not move it
    let mut alone = inc.clone();
    alone.input[0].witness = Witness::from_slice(&[
        sign_bip340(&k, &d).to_vec(),
        sign_bip340(&k, &d).to_vec(),
        leaf.to_bytes(),
        ftree.control(funding_leaf::ACCEPT).serialize(),
    ]);
    let r = rpc.package(&alone);
    let why = reasons(&r);
    rep.check(
        "Scoped key alone cannot spend the funding output (script check)",
        r.is_err() && why.contains("script-verify"),
        &why,
    );
    inc.input[0].witness = Witness::from_slice(&[
        oracle.cosign(&d).to_vec(),
        sign_bip340(&k, &d).to_vec(),
        leaf.to_bytes(),
        ftree.control(funding_leaf::ACCEPT).serialize(),
    ]);
    let r = rpc.package(&inc);
    rep.check("Incident transaction: scoped key + oracle co-signature, zero fee, confirmed as a package with a fee-paying child", r.is_ok(), &r.err().unwrap_or_default());
    rpc.mine(1);
    let acc_height = rpc.height();

    // ---------------------------------------------------------------- pre-signed set
    let caller = rpc.new_spk();
    let responders: Vec<ScriptBuf> = (0..5).map(|_| rpc.new_spk()).collect();
    let nonces = Pot::ALL.map(|p| oracle.announce(&event_id(&case, p)));
    let terms = IncidentTerms {
        case: case.clone(),
        pots,
        parties: Parties {
            caller: caller.clone(),
            responders: responders.clone(),
            merit: vec![3, 1, 2, 1, 1],
            good_faith_pct: 50,
        },
        signers: signers.clone(),
        oracle: oracle.pubkey(),
        oracle_nonces: nonces,
        refund_height: acc_height + 12_960,
    };
    let t0 = std::time::Instant::now();
    let mut set = IncidentSet::build(terms, inc.compute_txid());
    set.sign_locally(&secrets);
    rep.check(
        "Full pre-signed set built and signed by all six parties, every partial verified",
        set.len() == 387 && set.verify_all(),
        &format!(
            "{} payouts + {} refunds in {:.2} s",
            set.len(),
            set.refunds.len(),
            t0.elapsed().as_secs_f64()
        ),
    );
    let refund = set.refund(Pot::Deposit).unwrap();
    let r = rpc.package(&refund);
    let why = reasons(&r);
    rep.check(
        "Refund refused before its height (90 days)",
        r.is_err() && why.contains("non-final"),
        &why,
    );

    // ---------------------------------------------------------------- settlement
    let outcomes = [
        (Pot::Deposit, "returned".to_string()),
        (Pot::Reward, "paid (2, 1, 1, 1, 0)".to_string()),
        (Pot::Bounty, "split (1, 1, 1, 1, 1)".to_string()),
    ];
    let reward_att = oracle
        .attest(
            &event_id(&case, Pot::Reward),
            &outcome_msg(&case, "reward", &outcomes[1].1),
        )
        .unwrap();
    rep.check(
        "Another ending's payout cannot be completed with this attestation",
        set.complete(Pot::Reward, "withheld", reward_att).is_none(),
        "",
    );
    for (pot, label) in &outcomes {
        let s = if *pot == Pot::Reward {
            reward_att
        } else {
            oracle
                .attest(
                    &event_id(&case, *pot),
                    &outcome_msg(&case, pot.name(), label),
                )
                .unwrap()
        };
        let tx = set.complete(*pot, label, s).expect("completes");
        let r = rpc.package(&tx);
        rep.check(
            &format!(
                "{}: \"{label}\" completed by the attestation and accepted",
                pot.name()
            ),
            r.is_ok(),
            &r.err().unwrap_or_default(),
        );
    }
    rpc.mine(1);
    let paid = set.pot_outpoints.iter().flatten().all(|op| rpc.spent(op));
    rep.check("All three pots spent on-chain", paid, "");
    let got: u64 = responders
        .iter()
        .map(|s| {
            let a = Address::from_script(s, Network::Regtest)
                .unwrap()
                .to_string();
            (rpc.w(&["getreceivedbyaddress", &a, "1"]).as_f64().unwrap() * 1e8).round() as u64
        })
        .sum();
    rep.check(
        "Responders received the reward and bounty",
        got == 600_000 + 300_000,
        &format!("{got} sats"),
    );

    // ---------------------------------------------------------------- refund path on a second incident
    let fop2 = rpc.fund(&ftree.script_pubkey(), total);
    let mut inc2 = txbuild::incident(fop2, &pots, &pot_spk);
    let prev2 = [txbuild::txout(total, ftree.script_pubkey())];
    let d2 = txbuild::scriptspend_digest(&inc2, 0, &prev2, leaf);
    inc2.input[0].witness = Witness::from_slice(&[
        oracle.cosign(&d2).to_vec(),
        sign_bip340(&k, &d2).to_vec(),
        leaf.to_bytes(),
        ftree.control(funding_leaf::ACCEPT).serialize(),
    ]);
    rpc.package(&inc2).unwrap();
    rpc.mine(1);
    let case2 = format!("{case}-b");
    let terms2 = IncidentTerms {
        case: case2.clone(),
        pots,
        parties: Parties {
            caller: caller.clone(),
            responders: responders.clone(),
            merit: vec![1; 5],
            good_faith_pct: 50,
        },
        signers: signers.clone(),
        oracle: oracle.pubkey(),
        oracle_nonces: Pot::ALL.map(|p| oracle.announce(&event_id(&case2, p))),
        refund_height: rpc.height() + 5,
    };
    let mut set2 = IncidentSet::build(terms2, inc2.compute_txid());
    set2.sign_locally(&secrets);
    rpc.mine(5);
    let ok = Pot::ALL
        .iter()
        .all(|p| rpc.package(&set2.refund(*p).unwrap()).is_ok());
    rep.check(
        "Oracle never attests: each pot's refund pays the caller after its height",
        ok,
        "",
    );
    rpc.mine(1);

    // ---------------------------------------------------------------- bond
    let (kop, cold) = (random_scalar(), random_scalar());
    let btree = outputs::bond(&secp, &xo(&kop), &xo(&cold), &ox, rpc.height() + 52_560);
    let bv = 200_000u64;
    let bop = rpc.fund(&btree.script_pubkey(), bv);
    let prev_b = [txbuild::txout(bv, btree.script_pubkey())];
    let mut steal = txbuild::payout(bop, &[(bv, rpc.new_spk())]);
    let wl = &btree.scripts[bond_leaf::WITHDRAW];
    let ds = txbuild::scriptspend_digest(&steal, 0, &prev_b, wl);
    steal.input[0].witness = Witness::from_slice(&[
        sign_bip340(&cold, &ds).to_vec(),
        sign_bip340(&cold, &ds).to_vec(),
        wl.to_bytes(),
        btree.control(bond_leaf::WITHDRAW).serialize(),
    ]);
    let r = rpc.package(&steal);
    let why = reasons(&r);
    rep.check(
        "Bond: the cold key alone cannot withdraw (script check)",
        r.is_err() && why.contains("script-verify"),
        &why,
    );
    let mut forf = txbuild::payout(bop, &[(bv, responders[1].clone())]);
    let fl = &btree.scripts[bond_leaf::FORFEIT];
    let df = txbuild::scriptspend_digest(&forf, 0, &prev_b, fl);
    let pre_signed = sign_bip340(&kop, &df); // made by the operator when the exposure began
    forf.input[0].witness = Witness::from_slice(&[
        oracle.cosign(&df).to_vec(),
        pre_signed.to_vec(),
        fl.to_bytes(),
        btree.control(bond_leaf::FORFEIT).serialize(),
    ]);
    let r = rpc.package(&forf);
    rep.check(
        "Bond: the pre-signed forfeiture completes with the oracle's co-signature",
        r.is_ok(),
        &r.err().unwrap_or_default(),
    );
    rpc.mine(1);

    // ---------------------------------------------------------------- funding fallback
    let fb2 = rpc.height() + 3;
    let ftree2 = outputs::funding(&secp, &xo(&w), &xo(&k), &ox, fb2);
    let fop3 = rpc.fund(&ftree2.script_pubkey(), 50_000);
    let fbl = &ftree2.scripts[funding_leaf::FALLBACK];
    let mut back = txbuild::payout(fop3, &[(50_000, caller.clone())]);
    back.lock_time = bitcoin::absolute::LockTime::from_height(fb2).unwrap();
    let prev3 = [txbuild::txout(50_000, ftree2.script_pubkey())];
    let db = txbuild::scriptspend_digest(&back, 0, &prev3, fbl);
    back.input[0].witness = Witness::from_slice(&[
        sign_bip340(&w, &db).to_vec(),
        fbl.to_bytes(),
        ftree2.control(funding_leaf::FALLBACK).serialize(),
    ]);
    let early = rpc.package(&back);
    rpc.mine(3);
    let late = rpc.package(&back);
    rep.check(
        "Funding fallback: wallet key alone refused before its height, accepted after",
        early.is_err() && reasons(&early).contains("non-final") && late.is_ok(),
        &reasons(&early),
    );
    rpc.mine(1);

    println!("{} passed, {} failed", rep.0, rep.1);
    std::process::exit(if rep.1 == 0 { 0 } else { 1 });
}
