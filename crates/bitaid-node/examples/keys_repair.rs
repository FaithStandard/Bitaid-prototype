//! Rebuilds a key file whose lines were interleaved by processes appending at once: every pair of the
//! secrets found in it, as (scoped, cold) of a bond under the oracle key and fallback height given,
//! matched against the bond addresses the wallets sent to; prints the repaired JSON lines.
//!   keys_repair <garbled file> <oracle hex> <fallback> <addresses file>
use bitaid_core::outputs;
use bitaid_node::node::xo;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{Address, Network};
use musig2::secp::Scalar;
use std::collections::HashSet;

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let text = std::fs::read_to_string(&a[1]).unwrap();
    let oracle = bitaid_node::wire::xonly(&a[2]).unwrap();
    let bf: u32 = a[3].parse().unwrap();
    let addrs: HashSet<String> = std::fs::read_to_string(&a[4])
        .unwrap()
        .lines()
        .filter_map(|l| l.split_whitespace().nth(1).map(String::from))
        .collect();
    let re: Vec<String> = text
        .as_bytes()
        .windows(64)
        .enumerate()
        .filter(|(i, w)| {
            w.iter().all(|c| c.is_ascii_hexdigit())
                && (*i == 0 || !text.as_bytes()[i - 1].is_ascii_hexdigit())
                && text.as_bytes().get(i + 64).is_none_or(|c| !c.is_ascii_hexdigit())
        })
        .map(|(_, w)| String::from_utf8(w.to_vec()).unwrap())
        .collect::<HashSet<_>>()
        .into_iter()
        .filter(|h| *h != a[2])
        .collect();
    let secs: Vec<Scalar> = re
        .iter()
        .filter_map(|h| Scalar::from_slice(&hex::decode(h).ok()?).ok())
        .collect();
    eprintln!("{} secrets", secs.len());
    let secp = Secp256k1::new();
    let mut found = 0;
    for s in &secs {
        for c in &secs {
            if s == c {
                continue;
            }
            let t = outputs::bond(&secp, &xo(s), &xo(c), &oracle, bf);
            let ad = Address::from_script(&t.script_pubkey(), Network::Signet).unwrap();
            if addrs.contains(&ad.to_string()) {
                found += 1;
                println!(
                    "{}",
                    serde_json::json!({"kind":"bond","who":format!("repaired-{found}"),"a":hex::encode(s.serialize()),"b":hex::encode(c.serialize()),"oracle":a[2],"fallback":bf})
                );
            }
        }
    }
    eprintln!("{found} bonds matched");
}
