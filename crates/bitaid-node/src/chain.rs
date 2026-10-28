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
    /// confirmed transactions and block hashes, which never change: a replay of a case asks for the
    /// same ones many times, and over Tor each call costs a second or more
    memo: Mutex<std::collections::HashMap<String, Value>>,
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
            memo: Mutex::new(std::collections::HashMap::new()),
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
        // BITAID_RPC_DELAY_MS (tests): add latency to every call, as a chain reached over Tor has
        if let Some(ms) = std::env::var("BITAID_RPC_DELAY_MS")
            .ok()
            .and_then(|v| v.parse().ok())
        {
            std::thread::sleep(std::time::Duration::from_millis(ms));
        }
        let body = json!({"jsonrpc": "1.0", "id": "bitaid", "method": method, "params": params});
        let r = crate::http_for(&url)
            .post(&url)
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

    /// A transaction (verbose), memoised once it is confirmed.
    fn tx_json(&self, txid: &str) -> Option<Value> {
        let k = format!("tx:{txid}");
        if let Some(v) = self.memo.lock().unwrap().get(&k) {
            return Some(v.clone());
        }
        let v = self.call("getrawtransaction", json!([txid, true])).ok()?;
        if v["confirmations"].as_u64().unwrap_or(0) > 0 {
            self.memo.lock().unwrap().insert(k, v.clone());
        }
        Some(v)
    }

    /// An output as its transaction created it, spent or not (for replaying cases already settled).
    pub fn output(&self, op: &OutPoint) -> Option<(u64, ScriptBuf)> {
        let v = self.tx_json(&op.txid.to_string())?;
        let o = v["vout"].as_array()?.get(op.vout as usize)?.clone();
        let value = (o["value"].as_f64()? * 1e8).round() as u64;
        let spk = ScriptBuf::from_hex(o["scriptPubKey"]["hex"].as_str()?).ok()?;
        Some((value, spk))
    }

    /// The height of the block that confirmed `txid` (memoised), if confirmed.
    pub fn tx_height(&self, txid: &str) -> Option<u32> {
        let v = self.tx_json(txid)?;
        let bh = v["blockhash"].as_str()?.to_string();
        let k = format!("bhh:{bh}");
        if let Some(h) = self.memo.lock().unwrap().get(&k) {
            return h.as_u64().map(|x| x as u32);
        }
        let h = self.call("getblockheader", json!([bh])).ok()?["height"].as_u64()? as u32;
        self.memo.lock().unwrap().insert(k, json!(h));
        Some(h)
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
/// The chain this node is on ("regtest", "signet", "test", "main"), read once.
    pub fn chain(&self) -> String {
        if let Some(c) = self.memo.lock().unwrap().get("chain") {
            return c.as_str().unwrap_or("").to_string();
        }
        let c = self
            .call("getblockchaininfo", json!([]))
            .ok()
            .and_then(|v| v["chain"].as_str().map(String::from))
            .unwrap_or_default();
        if !c.is_empty() {
            self.memo.lock().unwrap().insert("chain".into(), json!(c));
        }
        c
    }

    pub fn is_regtest(&self) -> bool {
        self.chain() == "regtest"
    }

    /// `k` more blocks: mined on demand on regtest; on any other chain, waited for — nobody mines on
    /// demand there, and a draw "from a block mined after the offers closed" is simply the next one.
    pub fn mine(&self, k: u32) -> Result<(), String> {
        if self.is_regtest() {
            let a = self.wcall("getnewaddress", json!([]))?;
            self.call("generatetoaddress", json!([k, a]))?;
            return Ok(());
        }
        let start = self.height();
        let t0 = std::time::Instant::now();
        while self.height() < start + k {
            if t0.elapsed() > std::time::Duration::from_secs(1800) {
                return Err(format!("no new block in 30 min (at {start})"));
            }
            std::thread::sleep(std::time::Duration::from_millis(1000));
        }
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

    /// A wallet transaction carrying `data` in one OP_RETURN output (tier commitments, B.2).
    pub fn op_return(&self, data: &[u8]) -> Result<Txid, String> {
        let raw = self.call(
            "createrawtransaction",
            json!([[], [{"data": hex::encode(data)}]]),
        )?;
        let funded = self.wcall("fundrawtransaction", json!([raw]))?;
        let signed = self.wcall("signrawtransactionwithwallet", json!([funded["hex"]]))?;
        let txid = self.call("sendrawtransaction", json!([signed["hex"]]))?;
        Txid::from_str(txid.as_str().unwrap_or("")).map_err(|e| e.to_string())
    }

    /// Whether transaction `txid` is confirmed and carries `data` in an OP_RETURN output.
    pub fn has_op_return(&self, txid: &str, data: &[u8]) -> bool {
        let want = format!("6a{:02x}{}", data.len(), hex::encode(data));
        self.tx_json(txid)
            .map(|v| {
                v["confirmations"].as_u64().unwrap_or(0) > 0
                    && v["vout"]
                        .as_array()
                        .map(|o| o.iter().any(|x| x["scriptPubKey"]["hex"] == want))
                        .unwrap_or(false)
            })
            .unwrap_or(false)
    }

    /// Pays several scripts in one wallet transaction (arbitration fees to each seated arbitrator).
    pub fn pay_many(&self, to: &[(ScriptBuf, u64)]) -> Result<Txid, String> {
        let net = self.network();
        let mut m = serde_json::Map::new();
        for (spk, sats) in to {
            let a = Address::from_script(spk, net).map_err(|e| e.to_string())?;
            let prev = m
                .get(&a.to_string())
                .and_then(|v| v.as_f64())
                .unwrap_or(0.0);
            m.insert(a.to_string(), json!(prev + *sats as f64 / 1e8));
        }
        let txid = self.wcall("sendmany", json!(["", m]))?;
        Txid::from_str(txid.as_str().unwrap_or("")).map_err(|e| e.to_string())
    }

    /// What `txid` paid to `spk` (0 if unknown).
    pub fn paid_to(&self, txid: &str, spk: &ScriptBuf) -> u64 {
        let h = spk.to_hex_string();
        self.tx_json(txid)
            .and_then(|v| v["vout"].as_array().cloned())
            .map(|o| {
                o.iter()
                    .filter(|x| x["scriptPubKey"]["hex"] == h)
                    .map(|x| (x["value"].as_f64().unwrap_or(0.0) * 1e8).round() as u64)
                    .sum()
            })
            .unwrap_or(0)
    }

    /// The hash of the block at `height` (memoised: regtest and the tests do not reorganise).
    pub fn block_hash(&self, height: u32) -> Option<String> {
        let k = format!("bh:{height}");
        if let Some(v) = self.memo.lock().unwrap().get(&k) {
            return v.as_str().map(String::from);
        }
        let h = self
            .call("getblockhash", json!([height]))
            .ok()
            .and_then(|v| v.as_str().map(String::from))?;
        self.memo.lock().unwrap().insert(k, json!(h));
        Some(h)
    }
}
