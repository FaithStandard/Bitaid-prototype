//! Bitcoin Core over JSON-RPC (HTTP), so a phone can use a node on another machine.
//! `BITAID_RPC=http://user:pass@host:port` and optionally a wallet name for funding and fees.
use bitaid_core::txbuild;
use bitcoin::consensus::encode::{deserialize_hex, serialize_hex};
use bitcoin::{Address, Amount, Network, OutPoint, ScriptBuf, Transaction, TxIn, TxOut, Txid};
use serde_json::{json, Value};
use std::collections::HashSet;
use std::str::FromStr;
use std::sync::Mutex;

pub struct Rpc {
    base: String,
    auth: String,
    pub wallet: String,
    used: Mutex<HashSet<String>>,
}

impl Rpc {
    /// `url` is `http://user:pass@host:port`.
    pub fn new(url: &str, wallet: &str) -> Rpc {
        let (scheme, rest) = url.split_once("://").unwrap_or(("http", url));
        let (cred, host) = rest.rsplit_once('@').unwrap_or(("", rest));
        let auth = format!(
            "Basic {}",
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, cred)
        );
        Rpc {
            base: format!("{scheme}://{}", host.trim_end_matches('/')),
            auth,
            wallet: wallet.into(),
            used: Mutex::new(HashSet::new()),
        }
    }

    pub fn from_env() -> Rpc {
        Rpc::new(
            &std::env::var("BITAID_RPC").expect("set BITAID_RPC=http://user:pass@host:port"),
            &std::env::var("BITAID_WALLET").unwrap_or("w".into()),
        )
    }

    fn post(&self, wallet: bool, method: &str, params: Value) -> Result<Value, String> {
        let url = if wallet {
            format!("{}/wallet/{}", self.base, self.wallet)
        } else {
            self.base.clone()
        };
        let body = json!({"jsonrpc": "1.0", "id": "bitaid", "method": method, "params": params});
        let r = ureq::post(&url)
            .set("Authorization", &self.auth)
            .send_string(&body.to_string());
        let text = match r {
            Ok(resp) => resp.into_string().map_err(|e| e.to_string())?,
            Err(ureq::Error::Status(_, resp)) => resp.into_string().map_err(|e| e.to_string())?,
            Err(e) => return Err(format!("{method}: {e}")),
        };
        let v: Value = serde_json::from_str(&text).map_err(|e| format!("{method}: {e}: {text}"))?;
        if !v["error"].is_null() {
            return Err(v["error"]["message"]
                .as_str()
                .unwrap_or("rpc error")
                .to_string());
        }
        Ok(v["result"].clone())
    }

    pub fn call(&self, method: &str, params: Value) -> Result<Value, String> {
        self.post(false, method, params)
    }
    pub fn wcall(&self, method: &str, params: Value) -> Result<Value, String> {
        self.post(true, method, params)
    }

    pub fn height(&self) -> u32 {
        self.call("getblockcount", json!([]))
            .ok()
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32
    }

    pub fn network(&self) -> Network {
        match self
            .call("getblockchaininfo", json!([]))
            .ok()
            .and_then(|v| v["chain"].as_str().map(String::from))
            .as_deref()
        {
            Some("main") => Network::Bitcoin,
            Some("test") => Network::Testnet,
            Some("signet") => Network::Signet,
            _ => Network::Regtest,
        }
    }

    /// Regtest only: mines `k` blocks to the wallet.
    pub fn mine(&self, k: u32) -> Result<(), String> {
        let a = self.wcall("getnewaddress", json!([]))?;
        self.call("generatetoaddress", json!([k, a]))?;
        Ok(())
    }

    pub fn new_spk(&self) -> Result<ScriptBuf, String> {
        let a = self.wcall("getnewaddress", json!(["", "bech32m"]))?;
        Ok(Address::from_str(a.as_str().unwrap_or(""))
            .map_err(|e| e.to_string())?
            .assume_checked()
            .script_pubkey())
    }

    /// Sends `sats` to `spk` from the wallet; returns the outpoint (unconfirmed until mined).
    pub fn fund(&self, spk: &ScriptBuf, sats: u64) -> Result<OutPoint, String> {
        let addr = Address::from_script(spk, self.network()).map_err(|e| e.to_string())?;
        let txid = self.wcall(
            "sendtoaddress",
            json!([addr.to_string(), format!("{:.8}", sats as f64 / 1e8)]),
        )?;
        let txid = txid.as_str().unwrap_or("").to_string();
        let raw = self.wcall("gettransaction", json!([txid]))?;
        let tx: Transaction =
            deserialize_hex(raw["hex"].as_str().unwrap_or("")).map_err(|e| e.to_string())?;
        let vout = tx
            .output
            .iter()
            .position(|o| &o.script_pubkey == spk)
            .ok_or("output not found")? as u32;
        Ok(OutPoint {
            txid: Txid::from_str(&txid).map_err(|e| e.to_string())?,
            vout,
        })
    }

    /// The unspent output at `op`, if it exists (mempool included).
    pub fn utxo(&self, op: &OutPoint) -> Option<TxOut> {
        let v = self
            .call("gettxout", json!([op.txid.to_string(), op.vout, true]))
            .ok()?;
        if v.is_null() {
            return None;
        }
        let value = Amount::from_btc(v["value"].as_f64()?).ok()?;
        let spk = ScriptBuf::from_hex(v["scriptPubKey"]["hex"].as_str()?).ok()?;
        Some(TxOut {
            value,
            script_pubkey: spk,
        })
    }

    pub fn confirmations(&self, txid: &Txid) -> u32 {
        self.call("getrawtransaction", json!([txid.to_string(), true]))
            .ok()
            .and_then(|v| v["confirmations"].as_u64())
            .unwrap_or(0) as u32
    }

    /// Submits a zero-fee version-3 transaction with a wallet-funded child spending its anchor.
    pub fn package(&self, parent: &Transaction) -> Result<Txid, String> {
        let anchor = parent
            .output
            .iter()
            .position(|o| o.script_pubkey == bitaid_core::scripts::p2a())
            .ok_or("no anchor")? as u32;
        let utxos = self.wcall("listunspent", json!([1]))?;
        let u = {
            let mut used = self.used.lock().unwrap();
            let u = utxos
                .as_array()
                .ok_or("listunspent")?
                .iter()
                .find(|u| {
                    u["amount"].as_f64().unwrap_or(0.0) > 0.01
                        && !used.contains(&format!(
                            "{}:{}",
                            u["txid"].as_str().unwrap_or(""),
                            u["vout"]
                        ))
                })
                .ok_or("no wallet coin to pay the fee")?
                .clone();
            used.insert(format!(
                "{}:{}",
                u["txid"].as_str().unwrap_or(""),
                u["vout"]
            ));
            u
        };
        let _ = self.wcall(
            "lockunspent",
            json!([false, [{"txid": u["txid"], "vout": u["vout"]}]]),
        );
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
                script_pubkey: self.new_spk()?,
            }],
        };
        let prev = json!([{"txid": parent.compute_txid().to_string(), "vout": anchor, "scriptPubKey": "51024e73", "amount": 0}]);
        let signed = self.wcall(
            "signrawtransactionwithwallet",
            json!([serialize_hex(&child), prev]),
        )?;
        let r = self.call(
            "submitpackage",
            json!([[serialize_hex(parent), signed["hex"].as_str().unwrap_or("")]]),
        )?;
        if r["package_msg"] == "success" {
            Ok(parent.compute_txid())
        } else {
            Err(r.to_string())
        }
    }

    pub fn received(&self, spk: &ScriptBuf) -> u64 {
        let Ok(addr) = Address::from_script(spk, self.network()) else {
            return 0;
        };
        self.call("scantxoutset", json!(["start", [format!("addr({addr})")]]))
            .ok()
            .and_then(|v| v["total_amount"].as_f64())
            .map(|b| (b * 1e8).round() as u64)
            .unwrap_or(0)
    }
}
