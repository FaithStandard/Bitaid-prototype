//! Shared helpers for the regtest examples: a bitcoin-cli wrapper, package submission with a
//! fee-paying child, and a pass/fail report.
#![allow(dead_code)]
use bitaid_core::txbuild;
use bitcoin::consensus::encode::{deserialize_hex, serialize_hex};
use bitcoin::{
    Address, Amount, Network, OutPoint, ScriptBuf, Transaction, TxIn, TxOut, Txid, XOnlyPublicKey,
};
use musig2::secp::{Scalar, G};
use serde_json::{json, Value};
use std::process::Command;
use std::str::FromStr;

pub struct Rpc(
    pub Vec<String>,
    std::cell::RefCell<std::collections::HashSet<String>>,
);
impl Rpc {
    pub fn call(&self, wallet: bool, args: &[&str]) -> Result<Value, String> {
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
    pub fn n(&self, args: &[&str]) -> Value {
        self.call(false, args)
            .unwrap_or_else(|e| panic!("{args:?}: {e}"))
    }
    pub fn w(&self, args: &[&str]) -> Value {
        self.call(true, args)
            .unwrap_or_else(|e| panic!("{args:?}: {e}"))
    }
    pub fn height(&self) -> u32 {
        self.n(&["getblockcount"]).as_u64().unwrap() as u32
    }
    pub fn mine(&self, k: u32) {
        let a = self.w(&["getnewaddress"]);
        self.n(&["generatetoaddress", &k.to_string(), a.as_str().unwrap()]);
    }
    pub fn new_spk(&self) -> ScriptBuf {
        let a = self.w(&["getnewaddress", "", "bech32m"]);
        Address::from_str(a.as_str().unwrap())
            .unwrap()
            .require_network(Network::Regtest)
            .unwrap()
            .script_pubkey()
    }
    /// Sends `sats` to `spk`, mines it, returns the outpoint.
    pub fn fund(&self, spk: &ScriptBuf, sats: u64) -> OutPoint {
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
    pub fn package(&self, parent: &Transaction) -> Result<(), String> {
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
    pub fn spent(&self, op: &OutPoint) -> bool {
        matches!(self.call(false, &["gettxout", &op.txid.to_string(), &op.vout.to_string()]), Ok(Value::String(ref s)) if s.is_empty())
    }
}

/// The node's rejection reasons from a failed package submission.
pub fn reasons(r: &Result<(), String>) -> String {
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

pub fn xo(s: &Scalar) -> XOnlyPublicKey {
    XOnlyPublicKey::from_slice(&(*s * G).serialize_xonly()).unwrap()
}

pub struct Report(pub u32, pub u32);
impl Report {
    pub fn check(&mut self, name: &str, ok: bool, detail: &str) {
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

pub fn rpc_from_env() -> Rpc {
    let cli = std::env::var("BITAID_CLI")
        .unwrap_or("bitcoin-cli -regtest -rpcuser=u -rpcpassword=p -rpcport=18543".into());
    Rpc(
        cli.split_whitespace().map(String::from).collect(),
        Default::default(),
    )
}
