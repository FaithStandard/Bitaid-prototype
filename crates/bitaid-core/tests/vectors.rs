//! Cross-implementation check: the Rust core must reproduce, byte for byte, what the Python reference
//! implementation (used for every regtest/signet/Liquid test so far) computes from the same secrets
//! and nonces: output scripts, control blocks, transactions, digests, attestation points, MuSig2
//! adaptor partial signatures and completed signatures. Vectors: tests/vectors.json, made by
//! bitaid-tests/make_vectors.py.
use bitaid_core::{hashes::outcome_msg, musig, oracle, outputs, txbuild};
use bitcoin::consensus::encode::serialize_hex;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{OutPoint, ScriptBuf, Txid, XOnlyPublicKey};
use musig2::secp::{Point, Scalar, G};
use musig2::{AggNonce, PartialSignature, PubNonce, SecNonce};
use serde_json::Value;
use std::convert::TryInto;
use std::str::FromStr;

fn sc(h: &Value) -> Scalar {
    Scalar::from_slice(&hex::decode(h.as_str().unwrap()).unwrap()).unwrap()
}
fn xo(s: &Scalar) -> XOnlyPublicKey {
    XOnlyPublicKey::from_slice(&(*s * G).serialize_xonly()).unwrap()
}
fn spk(h: &Value) -> ScriptBuf {
    ScriptBuf::from_bytes(hex::decode(h.as_str().unwrap()).unwrap())
}

#[test]
fn matches_python_reference() {
    let v: Value = serde_json::from_str(include_str!("vectors.json")).unwrap();
    let secp = Secp256k1::new();
    let s = &v["secrets"];
    let (w, k, ins, cold, x) = (
        sc(&s["wallet"]),
        sc(&s["scoped"]),
        sc(&s["insurer"]),
        sc(&s["cold"]),
        sc(&s["oracle"]),
    );
    let h = v["fallback_height"].as_u64().unwrap() as u32;
    let trees = [
        (
            "funding",
            outputs::funding(&secp, &xo(&w), &xo(&k), &xo(&x), h),
        ),
        (
            "bond",
            outputs::bond(&secp, &xo(&k), &xo(&cold), &xo(&x), h),
        ),
        (
            "buffer",
            outputs::buffer(&secp, &xo(&k), &xo(&ins), &xo(&x), h),
        ),
    ];
    for (name, t) in &trees {
        let o = &v["outputs"][name];
        assert_eq!(
            hex::encode(t.script_pubkey().as_bytes()),
            o["spk"].as_str().unwrap(),
            "{name} spk"
        );
        for i in 0..3 {
            assert_eq!(
                hex::encode(t.control(i).serialize()),
                o["controls"][i].as_str().unwrap(),
                "{name} control {i}"
            );
        }
    }
    // pots
    let mut secrets = vec![k];
    secrets.extend(v["responders"].as_array().unwrap().iter().map(sc));
    let pubs: Vec<Point> = secrets.iter().map(|s| *s * G).collect();
    let ctx = musig::taproot_ctx(&pubs);
    let pot_spk = musig::pot_script_pubkey(&ctx);
    assert_eq!(
        hex::encode(pot_spk.as_bytes()),
        v["pot_spk"].as_str().unwrap(),
        "pot spk"
    );
    // incident transaction
    let inc_v = &v["incident"];
    let pots: Vec<u64> = inc_v["pots"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x.as_u64().unwrap())
        .collect();
    let fop = OutPoint {
        txid: Txid::from_str(inc_v["funding_txid"].as_str().unwrap()).unwrap(),
        vout: 0,
    };
    let inc = txbuild::incident(fop, &pots, &pot_spk);
    assert_eq!(
        serialize_hex(&inc),
        inc_v["tx"].as_str().unwrap(),
        "incident tx"
    );
    assert_eq!(
        inc.compute_txid().to_string(),
        inc_v["txid"].as_str().unwrap(),
        "incident txid"
    );
    let total: u64 = pots.iter().sum();
    let ftree = &trees[0].1;
    let d = txbuild::scriptspend_digest(
        &inc,
        0,
        &[txbuild::txout(total, ftree.script_pubkey())],
        &ftree.scripts[1],
    );
    assert_eq!(
        hex::encode(d),
        inc_v["digest_accept_leaf"].as_str().unwrap(),
        "acceptance digest"
    );
    // payouts
    let xp = x * G;
    let case_id: [u8; 32] = hex::decode(v["case_id"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    for p in v["payouts"].as_array().unwrap() {
        let label = p["label"].as_str().unwrap();
        let pot = p["pot"].as_str().unwrap();
        let vout = p["vout"].as_u64().unwrap() as u32;
        let outs: Vec<(u64, ScriptBuf)> = p["outputs"]
            .as_array()
            .unwrap()
            .iter()
            .map(|o| (o[0].as_u64().unwrap(), spk(&o[1])))
            .collect();
        let tx = txbuild::payout(
            OutPoint {
                txid: inc.compute_txid(),
                vout,
            },
            &outs,
        );
        assert_eq!(serialize_hex(&tx), p["tx"].as_str().unwrap(), "{label} tx");
        let digest = txbuild::keyspend_digest(
            &tx,
            0,
            &[txbuild::txout(pots[vout as usize], pot_spk.clone())],
        );
        assert_eq!(
            hex::encode(digest),
            p["digest"].as_str().unwrap(),
            "{label} digest"
        );
        let split: Vec<u8> = p["split"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_u64().unwrap() as u8)
            .collect();
        let m = outcome_msg(
            &case_id,
            0,
            vout as u8,
            p["class"].as_u64().unwrap() as u8,
            &split,
        );
        let ending = bitaid_core::endings::endings(5)
            .into_iter()
            .find(|e| e.pot.name() == pot && e.label == label)
            .expect("ending exists");
        assert_eq!(
            ending.message(&case_id, 0),
            m,
            "{label}: ending encodes the same message"
        );
        assert_eq!(
            hex::encode(m),
            p["outcome_msg"].as_str().unwrap(),
            "{label} outcome message"
        );
        let r = sc(&p["oracle_nonce"]) * G;
        let t = oracle::attestation_point(&r, &xp, &m);
        assert_eq!(
            hex::encode(t.serialize()),
            p["point"].as_str().unwrap(),
            "{label} attestation point"
        );
        let att = sc(&p["attestation"]);
        assert_eq!(att * G, t, "{label} attestation scalar matches point");
        // MuSig2 adaptor session with the reference's nonces
        let secnonces: Vec<SecNonce> = p["nonces"]
            .as_array()
            .unwrap()
            .iter()
            .zip(&secrets)
            .map(|(n, sk)| SecNonce::new(sc(&n[0]), sc(&n[1]), *sk * G))
            .collect();
        let pubnonces: Vec<PubNonce> = secnonces.iter().map(|s| s.public_nonce()).collect();
        let agg: AggNonce = pubnonces.iter().sum();
        let parts: Vec<PartialSignature> = secrets
            .iter()
            .zip(secnonces)
            .map(|(sk, sn)| musig::partial(&ctx, sk, sn, &agg, Some(t), &digest))
            .collect();
        for (i, ps) in parts.iter().enumerate() {
            assert_eq!(
                hex::encode(ps.serialize()),
                p["partials"][i].as_str().unwrap(),
                "{label} partial {i}"
            );
        }
        let pre =
            musig2::adaptor::aggregate_partial_signatures(&ctx, &agg, t, parts, digest).unwrap();
        let fin = musig::complete(&pre, att).unwrap();
        assert_eq!(
            hex::encode(fin),
            p["final_sig"].as_str().unwrap(),
            "{label} completed signature"
        );
    }
}
