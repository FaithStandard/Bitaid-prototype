//! Checks that a chain call made while the node cannot be reached is asked again, and answered once
//! the node is up: run with BITAID_RPC pointing at a port that opens a few seconds later.
fn main() {
    let rpc = bitaid_node::chain::Rpc::from_env();
    let t = std::time::Instant::now();
    match rpc.call("getblockcount", serde_json::json!([])) {
        Ok(h) => println!("answered {h} after {:.1} s", t.elapsed().as_secs_f64()),
        Err(e) => println!("failed after {:.1} s: {e}", t.elapsed().as_secs_f64()),
    }
}
