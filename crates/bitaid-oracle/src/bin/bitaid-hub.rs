//! Relay for the oracle prototype: rebroadcasts every line it receives to every other client and replays
//! its history to clients that join late. Usage: bitaid-hub [listen address, default 0.0.0.0:7400]
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};

fn main() {
    let addr = std::env::args().nth(1).unwrap_or("0.0.0.0:7400".into());
    let listener = TcpListener::bind(&addr).expect("bind");
    eprintln!("bitaid-hub listening on {addr}");
    let clients: Arc<Mutex<Vec<(usize, TcpStream)>>> = Arc::new(Mutex::new(Vec::new()));
    let history: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    for (n, stream) in listener.incoming().flatten().enumerate() {
        let _ = stream.set_nodelay(true);
        let mut w = stream.try_clone().unwrap();
        {
            let h = history.lock().unwrap();
            for line in h.iter() {
                let _ = w.write_all(line.as_bytes());
            }
            clients.lock().unwrap().push((n, w));
        }
        let (clients, history) = (clients.clone(), history.clone());
        std::thread::spawn(move || {
            for line in BufReader::new(stream).lines().map_while(Result::ok) {
                let line = format!("{line}\n");
                let mut h = history.lock().unwrap();
                h.push(line.clone());
                let mut cs = clients.lock().unwrap();
                cs.retain_mut(|(id, s)| *id == n || s.write_all(line.as_bytes()).is_ok());
            }
            clients.lock().unwrap().retain(|(id, _)| *id != n);
        });
    }
}
