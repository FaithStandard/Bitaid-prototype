//! Prints the signet address of every bond and funding output in a key file (test chains only), so
//! what happened to their coins can be looked up on a block explorer.
//!   cargo run --release --example keyaddrs -- FILE...
use bitaid_core::outputs;
use bitaid_node::node::xo;
use bitcoin::secp256k1::Secp256k1;
use musig2::secp::Scalar;

fn main() {
    let secp = Secp256k1::new();
    for path in std::env::args().skip(1) {
        let text = std::fs::read_to_string(&path).unwrap_or_default();
        for line in text.lines() {
            let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else { continue };
            let sc = |k: &str| {
                hex::decode(v[k].as_str().unwrap_or("")).ok().and_then(|b| Scalar::from_slice(&b).ok())
            };
            let (Some(a), Some(b), Some(o)) =
                (sc("a"), sc("b"), v["oracle"].as_str().and_then(bitaid_node::wire::xonly))
            else { continue };
            let bf = v["fallback"].as_u64().unwrap_or(0) as u32;
            let tree = if v["kind"] == "funding" {
                outputs::funding(&secp, &xo(&b), &xo(&a), &o, bf)
            } else {
                outputs::bond(&secp, &xo(&a), &xo(&b), &o, bf)
            };
            let addr = bitcoin::Address::from_script(&tree.script_pubkey(), bitcoin::Network::Signet).unwrap();
            println!("{} {} {} {}", v["who"].as_str().unwrap_or("?"), v["kind"].as_str().unwrap_or("?"), bf, addr);
        }
    }
}
