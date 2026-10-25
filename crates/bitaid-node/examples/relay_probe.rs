//! For each relay: publishes one event of each kind Bitaid uses, then reads it back, and reports
//! whether the relay accepted it (OK), stored it (returned to a later subscription) or forwarded it
//! live. `cargo run --example relay_probe -- wss://relay.a wss://relay.b`
use bitaid_node::nostr::{kind, Client, Event, Filter, RelayMsg};
use bitcoin::secp256k1::{Keypair, Secp256k1};
use std::time::Duration;

fn main() {
    let urls: Vec<String> = std::env::args().skip(1).collect();
    let keys = Keypair::new(&Secp256k1::new(), &mut rand::thread_rng());
    for url in &urls {
        println!("== {url}");
        for (k, label, size) in [
            (kind::ANNOUNCE, "announce (stored)", 200),
            (kind::ANNOUNCE, "announce 20 KiB", 20_000),
            (kind::ALERT, "alert (ephemeral)", 200),
            (kind::CASE, "case 12 KiB (ephemeral)", 12_000),
        ] {
            let mut live = Client::new();
            if let Err(e) = live.add_relay(url) {
                println!("  cannot connect: {e}");
                break;
            }
            let tag = format!("probe{}", rand::random::<u32>());
            live.subscribe(
                "live",
                vec![Filter::kinds(&[k]).tag('c', std::slice::from_ref(&tag))],
            );
            std::thread::sleep(Duration::from_millis(800));
            let mut pubc = Client::new();
            pubc.add_relay(url).ok();
            let e = Event::new(
                &keys,
                k,
                vec![vec!["c".into(), tag.clone()]],
                "x".repeat(size),
            );
            pubc.publish(&e);
            let ok = pubc.raw_ok(&e.id, Duration::from_secs(8));
            let got_live = live
                .next_event(Duration::from_secs(5))
                .map(|(_, x)| x.id == e.id)
                .unwrap_or(false);
            let mut later = Client::new();
            later.add_relay(url).ok();
            later.subscribe(
                "later",
                vec![Filter::kinds(&[k]).tag('c', std::slice::from_ref(&tag))],
            );
            let stored = later
                .next_event(Duration::from_secs(5))
                .map(|(_, x)| x.id == e.id)
                .unwrap_or(false);
            println!("  {label:<26} OK: {ok:<40} live: {got_live:<5} stored: {stored}");
        }
    }
    let _ = RelayMsg::Eose(String::new());
}
