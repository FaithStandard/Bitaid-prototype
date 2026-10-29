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
    /// transactions of the blocks since the run began, for a node without a transaction index (a
    /// pruned node cannot keep one): next height to read, and txid → (outputs, height, block hash)
    index: Mutex<(u32, std::collections::HashMap<String, (Value, u32, String)>)>,
    tip: Mutex<(u32, Option<std::time::Instant>)>,
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
            index: Mutex::new((0, std::collections::HashMap::new())),
            tip: Mutex::new((0, None)),
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
        if std::env::var("BITAID_RPC_TRACE").is_ok() {
            let p = params.to_string();
            eprintln!("rpc {method} {}", &p[..p.len().min(90)]);
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
        let v = self.raw_tx(txid)?;
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

    /// Until every one of `txids` is in a block: one mined on demand on regtest, waited for elsewhere.
    /// A child spending a zero-fee TRUC parent must wait for it: the parent's anchor already has its
    /// one allowed unconfirmed child.
    pub fn confirm(&self, txids: &[bitcoin::Txid]) {
        if self.is_regtest() {
            self.mine(1).ok();
        }
        let t0 = std::time::Instant::now();
        while txids.iter().any(|t| self.confirmations(t) == 0)
            && t0.elapsed() < std::time::Duration::from_secs(crate::slow(900))
        {
            std::thread::sleep(std::time::Duration::from_millis(2000));
        }
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
            if t0.elapsed() > std::time::Duration::from_secs(crate::slow(1800)) {
                return Err(format!("no new block in {} s (at {start})", crate::slow(1800)));
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
        self.raw_tx(&txid.to_string())
            .and_then(|v| v["confirmations"].as_u64())
            .unwrap_or(0) as u32
    }

    /// Whether `txid` is in the mempool or a block.
    pub fn knows(&self, txid: &Txid) -> bool {
        self.raw_tx(&txid.to_string()).is_some()
    }

    /// A transaction (verbose) from the node, or, when the node keeps no transaction index and the
    /// transaction has left the mempool, from the blocks this node has read since the run began.
    fn raw_tx(&self, txid: &str) -> Option<Value> {
        // already read from a block: answered locally (over Tor each call costs a second or more)
        if let Some(v) = self.from_index(txid) {
            return Some(v);
        }
        match self.call("getrawtransaction", json!([txid, true])) {
            Ok(v) => Some(v),
            Err(e) if e.contains("txindex") || e.contains("No such mempool") => self.indexed(txid),
            Err(e) => {
                if std::env::var("BITAID_DEBUG").is_ok() {
                    eprintln!("raw_tx {txid}: {e}");
                }
                None
            }
        }
    }

    /// `txid` from the blocks already read, with its confirmations against a tip at most 5 s old.
    fn from_index(&self, txid: &str) -> Option<Value> {
        let (vout, h, bh) = self.index.lock().unwrap().1.get(txid)?.clone();
        let tip = self.tip();
        Some(json!({"txid": txid, "vout": vout, "blockhash": bh, "confirmations": tip.saturating_sub(h) + 1}))
    }

    /// The chain's height, asked at most every 5 s (lookups of unknown transactions are frequent).
    fn tip(&self) -> u32 {
        let mut t = self.tip.lock().unwrap();
        if t.1.map_or(true, |at| at.elapsed() > std::time::Duration::from_secs(5)) {
            *t = (self.height(), Some(std::time::Instant::now()));
        }
        t.0
    }

    /// Reads every block not yet read (from BITAID_INDEX_FROM, or BITAID_INDEX_BACK blocks — 36 by
    /// default — before the first lookup) and looks `txid` up among their transactions.
    fn indexed(&self, txid: &str) -> Option<Value> {
        let tip = self.tip();
        let mut ix = self.index.lock().unwrap();
        if ix.0 == 0 {
            let env = |k: &str| std::env::var(k).ok().and_then(|v| v.parse::<u32>().ok());
            ix.0 = env("BITAID_INDEX_FROM")
                .unwrap_or_else(|| tip.saturating_sub(env("BITAID_INDEX_BACK").unwrap_or(36)))
                .max(1);
        }
        while ix.0 <= tip {
            let h = ix.0;
            let Some(bh) = self.block_hash(h) else { break };
            let b = match self.call("getblock", json!([bh, 2])) {
                Ok(b) => b,
                // pruned away (or otherwise not kept): nothing of the run's can be in it
                Err(e) if e.contains("pruned") || e.contains("not found on disk") => {
                    ix.0 = h + 1;
                    continue;
                }
                Err(_) => break,
            };
            for t in b["tx"].as_array().cloned().unwrap_or_default() {
                if let Some(id) = t["txid"].as_str() {
                    ix.1.insert(id.to_string(), (t["vout"].clone(), h, bh.clone()));
                }
            }
            ix.0 = h + 1;
        }
        let (vout, h, bh) = ix.1.get(txid)?.clone();
        Some(json!({"txid": txid, "vout": vout, "blockhash": bh, "confirmations": tip.saturating_sub(h) + 1}))
    }

    /// Submits a zero-fee version-3 transaction with a wallet-funded child spending its anchor.
    pub fn package(&self, parent: &Transaction) -> Result<Txid, String> {
        let anchor = parent
            .output
            .iter()
            .position(|o| o.script_pubkey == bitaid_core::scripts::p2a())
            .ok_or("no anchor")? as u32;
        // the fee coin is claimed with lockunspent, which the wallet refuses for a coin already locked:
        // several nodes of one machine may share a wallet, and a coin two fee children both spend makes
        // the second package fail ("inputs missing or spent")
        // the child's fee: 20,000 sats, divided with every amount on a faucet-funded chain but at
        // least 1,000 (a package of a few hundred vbytes at a few sat/vB); BITAID_CHILD_FEE overrides
        let fee: u64 = std::env::var("BITAID_CHILD_FEE")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or_else(|| crate::sats(20_000).max(1_000));
        let utxos = self.wcall("listunspent", json!([1]))?;
        let u = {
            let mut used = self.used.lock().unwrap();
            let mut got = None;
            for u in utxos.as_array().ok_or("listunspent")? {
                let key = format!("{}:{}", u["txid"].as_str().unwrap_or(""), u["vout"]);
                if ((u["amount"].as_f64().unwrap_or(0.0) * 1e8).round() as u64) < fee + 1_000
                    || used.contains(&key)
                {
                    continue;
                }
                used.insert(key);
                if self
                    .wcall(
                        "lockunspent",
                        json!([false, [{"txid": u["txid"], "vout": u["vout"]}]]),
                    )
                    .is_ok()
                {
                    got = Some(u.clone());
                    break;
                }
            }
            got.ok_or("no wallet coin to pay the fee")?
        };
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
                value: Amount::from_sat(uval - fee),
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
