use bitaid_node::nostr::{kind, Client, Event, Filter};
use bitcoin::secp256k1::{Keypair, Secp256k1};
use std::time::Duration;

fn keys() -> Keypair {
    Keypair::new(&Secp256k1::new(), &mut rand::thread_rng())
}

#[test]
fn event_signature_and_tamper() {
    let k = keys();
    let e = Event::new(
        &k,
        kind::ALERT,
        vec![vec!["g".into(), "882a100d63fffff".into()]],
        "hello".into(),
    );
    assert!(e.verify());
    let mut t = e.clone();
    t.content = "hellp".into();
    assert!(!t.verify(), "content change detected");
    let mut t = e.clone();
    t.tags[0][1] = "882a100d65fffff".into();
    assert!(!t.verify(), "tag change detected");
}

/// NIP-01 id computed independently: sha256 of the compact JSON serialisation.
#[test]
fn nip01_id_known_vector() {
    use sha2::{Digest, Sha256};
    let k = keys();
    let e = Event::new_at(
        &k,
        1,
        vec![vec!["p".into(), "ab".into()]],
        "a \"quoted\"\nline".into(),
        1_700_000_000,
    );
    let ser = format!(
        "[0,\"{}\",1700000000,1,[[\"p\",\"ab\"]],\"a \\\"quoted\\\"\\nline\"]",
        e.pubkey
    );
    assert_eq!(hex::encode(Sha256::digest(ser.as_bytes())), e.id);
}

#[test]
fn relay_routes_by_tag_and_rejects_forgeries() {
    let (_h, addr) = bitaid_node::relay::spawn("127.0.0.1:0").unwrap();
    let url = format!("ws://{addr}");
    let (a, b) = (keys(), keys());
    let mut sub = Client::new();
    sub.add_relay(&url).unwrap();
    sub.subscribe(
        "cells",
        vec![Filter::kinds(&[kind::ALERT]).tag('g', &["cellA".into()])],
    );
    let mut pubc = Client::new();
    pubc.add_relay(&url).unwrap();
    std::thread::sleep(Duration::from_millis(200));
    let e1 = Event::new(
        &a,
        kind::ALERT,
        vec![vec!["g".into(), "cellA".into()]],
        "in".into(),
    );
    let e2 = Event::new(
        &a,
        kind::ALERT,
        vec![vec!["g".into(), "cellB".into()]],
        "out".into(),
    );
    let mut forged = Event::new(
        &b,
        kind::ALERT,
        vec![vec!["g".into(), "cellA".into()]],
        "x".into(),
    );
    forged.content = "tampered".into();
    pubc.publish(&e2);
    pubc.publish(&forged);
    pubc.publish(&e1);
    assert_eq!(pubc.wait_ok(&e1.id, Duration::from_secs(3)), 1);
    let (sid, got) = sub.next_event(Duration::from_secs(3)).expect("routed");
    assert_eq!((sid.as_str(), got.content.as_str()), ("cells", "in"));
    assert!(
        sub.next_event(Duration::from_millis(300)).is_none(),
        "other cell and forgery not delivered"
    );
}
