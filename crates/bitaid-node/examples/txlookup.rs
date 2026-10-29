use std::str::FromStr;
fn main() {
    let rpc = bitaid_node::chain::Rpc::from_env();
    let t = std::env::args().nth(1).unwrap();
    let id = bitcoin::Txid::from_str(&t).unwrap();
    println!("knows {} confs {}", rpc.knows(&id), rpc.confirmations(&id));
}
