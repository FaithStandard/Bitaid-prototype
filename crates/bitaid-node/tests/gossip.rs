use bitaid_node::gossip::{dial, Gossip};
use bitaid_node::nostr::{kind, Event, Filter};
use bitcoin::secp256k1::{Keypair, Secp256k1};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::time::Duration;

fn kp() -> Keypair {
    Keypair::new(&Secp256k1::new(), &mut rand::thread_rng())
}
fn free() -> String {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().to_string()
}

/// A Core in the middle, a phone app on each side: a message from one app reaches the other through
/// the Core; a late app catches up from the Core's log; a forged message goes nowhere.
#[test]
fn flood_replay_and_forgery() {
    let core_addr = free();
    let core = Gossip::start(Some(&core_addr), &[], None).unwrap();
    let mut a = Gossip::start(None, &[core_addr.clone()], None).unwrap();
    let mut b = Gossip::start(None, &[core_addr.clone()], None).unwrap();
    assert_eq!(a.wait_links(1, Duration::from_secs(5)), 1);
    assert_eq!(b.wait_links(1, Duration::from_secs(5)), 1);
    assert_eq!(core.wait_links(2, Duration::from_secs(5)), 2);
    a.subscribe("x", vec![Filter::kinds(&[kind::CASE])]);
    b.subscribe("x", vec![Filter::kinds(&[kind::CASE])]);
    let k = kp();
    let e = Event::new(
        &k,
        kind::CASE,
        vec![vec!["c".into(), "case1".into()]],
        "hello".into(),
    );
    a.publish(&e);
    let (_, got) = b
        .next_event(Duration::from_secs(5))
        .expect("delivered through the core");
    assert_eq!(got.id, e.id);
    assert_eq!(
        a.next_event(Duration::from_secs(1)).map(|x| x.1.id),
        Some(e.id.clone()),
        "own event echoed once"
    );
    assert!(
        a.next_event(Duration::from_millis(300)).is_none(),
        "no duplicate"
    );
    // a forged event (content changed after signing) is dropped at the first hop
    let mut f = Event::new(&k, kind::CASE, vec![], "x".into());
    f.content = "y".into();
    let mut raw = std::net::TcpStream::connect(&core_addr).unwrap();
    raw.write_all(format!("{}\n", serde_json::to_string(&f).unwrap()).as_bytes())
        .unwrap();
    assert!(
        b.next_event(Duration::from_millis(800)).is_none(),
        "forgery not forwarded"
    );
    // a late joiner gets the log replayed
    let mut late = Gossip::start(None, &[core_addr.clone()], None).unwrap();
    late.wait_links(1, Duration::from_secs(5));
    late.subscribe("x", vec![Filter::kinds(&[kind::CASE])]);
    let (_, r) = late.next_event(Duration::from_secs(5)).expect("replayed");
    assert_eq!(r.id, e.id);
}

/// Dialling through a SOCKS5 proxy, as through Tor: the proxy receives the host name unresolved
/// (so .onion names work) and the link carries data.
#[test]
fn socks5_dial_passes_the_name_unresolved() {
    let target = TcpListener::bind("127.0.0.1:0").unwrap();
    let tport = target.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let (mut s, _) = target.accept().unwrap();
        let mut b = [0u8; 4];
        s.read_exact(&mut b).unwrap();
        s.write_all(&b).unwrap();
    });
    let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
    let paddr = proxy.local_addr().unwrap().to_string();
    let seen = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
    let seen2 = seen.clone();
    std::thread::spawn(move || {
        let (mut c, _) = proxy.accept().unwrap();
        let mut g = [0u8; 3];
        c.read_exact(&mut g).unwrap();
        c.write_all(&[5, 0]).unwrap();
        let mut h = [0u8; 5];
        c.read_exact(&mut h).unwrap();
        let mut name = vec![0u8; h[4] as usize];
        c.read_exact(&mut name).unwrap();
        let mut port = [0u8; 2];
        c.read_exact(&mut port).unwrap();
        *seen2.lock().unwrap() = String::from_utf8(name).unwrap();
        // a stand-in Tor: whatever the name, connect to the local target
        let mut t = std::net::TcpStream::connect(("127.0.0.1", tport)).unwrap();
        c.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0]).unwrap();
        let mut b = [0u8; 4];
        c.read_exact(&mut b).unwrap();
        t.write_all(&b).unwrap();
        t.read_exact(&mut b).unwrap();
        c.write_all(&b).unwrap();
    });
    let onion = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion:7700";
    let mut s = dial(onion, Some(&paddr)).unwrap();
    s.write_all(b"ping").unwrap();
    let mut b = [0u8; 4];
    s.read_exact(&mut b).unwrap();
    assert_eq!(&b, b"ping");
    assert!(seen.lock().unwrap().ends_with(".onion"));
    assert!(
        dial(onion, None).is_err(),
        "an onion address is never dialled without Tor"
    );
}
