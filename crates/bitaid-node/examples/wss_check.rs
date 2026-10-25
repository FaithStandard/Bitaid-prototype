//! Connects to one relay and reports the result: `cargo run --example wss_check -- wss://relay.example`
fn main() {
    let url = std::env::args().nth(1).unwrap_or("wss://nos.lol".into());
    let mut c = bitaid_node::nostr::Client::new();
    match c.add_relay(&url) {
        Ok(()) => println!("connected to {url}"),
        Err(e) => println!("could not connect: {e}"),
    }
}
