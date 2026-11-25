//! Tor inside the Bitaid app (M4 step 2, `design/m4_android.md`).
//!
//! Arti (`arti-client`) runs in this process, behind a small SOCKS5 listener on an ephemeral loopback
//! port. The node's networking is unchanged: it reaches the listener as it reaches any Tor SOCKS port
//! (`BITAID_SOCKS`). Two things this listener adds that a stock Tor SOCKS port lacks, both from the
//! review of M4 (Neon, 2026-11-25):
//!
//! - **Access control.** Loopback is shared with every app on an Android device, and Tor's own SOCKS
//!   credentials isolate streams but authenticate nothing. This listener accepts only RFC 1929
//!   username/password auth whose password is a secret drawn when it starts, and refuses no-auth and
//!   any wrong password before anything reaches Tor.
//! - **Isolation by username.** Each username gets its own Arti isolation token, so streams under
//!   different names never share a circuit. Ordinary traffic uses one name (`main`); the caller's
//!   light path (Specification §7.2) uses a fresh name per worker query.
//!
//! The listener's front end (`serve`) is independent of Arti: it takes any connector, so its auth and
//! its isolation are tested without the Tor network.

use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// A stream to the far side, whatever carries it.
pub trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}

/// Opens a stream to `host:port` for the given isolation name. Arti in the app; a plain TCP connect
/// in the tests.
pub type Connector = Arc<
    dyn Fn(String, u16, String) -> Pin<Box<dyn Future<Output = std::io::Result<Box<dyn Stream>>> + Send>>
        + Send
        + Sync,
>;

/// A running listener: where it is and the secret it wants.
#[derive(Clone)]
pub struct Listener {
    pub addr: SocketAddr,
    pub secret: String,
}

impl Listener {
    /// The value for `BITAID_SOCKS`: `name:secret@127.0.0.1:port`. The node passes the name as the
    /// SOCKS username, which picks the circuit isolation.
    pub fn socks(&self, name: &str) -> String {
        format!("{name}:{}@{}", self.secret, self.addr)
    }
}

/// Binds an ephemeral loopback port and serves SOCKS5 CONNECT on it through `connect`, for clients
/// that give the secret. Returns once bound; serving runs on the current tokio runtime.
pub async fn serve(connect: Connector) -> std::io::Result<Listener> {
    let tcp = TcpListener::bind("127.0.0.1:0").await?;
    let addr = tcp.local_addr()?;
    let secret = hex::encode(rand::random::<[u8; 16]>());
    let want = secret.clone();
    tokio::spawn(async move {
        loop {
            let Ok((s, _)) = tcp.accept().await else { continue };
            let (connect, want) = (connect.clone(), want.clone());
            tokio::spawn(async move {
                let _ = handle(s, &want, connect).await;
            });
        }
    });
    Ok(Listener { addr, secret })
}

fn refuse<T>(why: &str) -> std::io::Result<T> {
    Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, why.to_string()))
}

/// One client: the greeting, RFC 1929 auth checked against the secret (anything else refused), one
/// CONNECT, then bytes both ways.
async fn handle(mut s: TcpStream, secret: &str, connect: Connector) -> std::io::Result<()> {
    // greeting: version 5, methods offered; only 2 (username/password) is accepted
    let mut h = [0u8; 2];
    s.read_exact(&mut h).await?;
    if h[0] != 5 {
        return refuse("not SOCKS5");
    }
    let mut methods = vec![0u8; h[1] as usize];
    s.read_exact(&mut methods).await?;
    if !methods.contains(&2) {
        s.write_all(&[5, 0xff]).await?;
        return refuse("no username/password offered");
    }
    s.write_all(&[5, 2]).await?;
    // RFC 1929: version 1, username, password
    let mut v = [0u8; 2];
    s.read_exact(&mut v).await?;
    let mut user = vec![0u8; v[1] as usize];
    s.read_exact(&mut user).await?;
    let mut pl = [0u8; 1];
    s.read_exact(&mut pl).await?;
    let mut pass = vec![0u8; pl[0] as usize];
    s.read_exact(&mut pass).await?;
    // compared without stopping at the first differing byte
    let ok = v[0] == 1
        && pass.len() == secret.len()
        && pass.iter().zip(secret.as_bytes()).fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0;
    if !ok {
        s.write_all(&[1, 1]).await?;
        return refuse("wrong secret");
    }
    s.write_all(&[1, 0]).await?;
    let name = String::from_utf8_lossy(&user).to_string();
    // CONNECT request: only domain names (Tor resolves them) and literal addresses
    let mut r = [0u8; 4];
    s.read_exact(&mut r).await?;
    if r[0] != 5 || r[1] != 1 {
        s.write_all(&[5, 7, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
        return refuse("only CONNECT");
    }
    let host = match r[3] {
        3 => {
            let mut l = [0u8; 1];
            s.read_exact(&mut l).await?;
            let mut d = vec![0u8; l[0] as usize];
            s.read_exact(&mut d).await?;
            String::from_utf8_lossy(&d).to_string()
        }
        1 => {
            let mut a = [0u8; 4];
            s.read_exact(&mut a).await?;
            std::net::Ipv4Addr::from(a).to_string()
        }
        _ => {
            s.write_all(&[5, 8, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
            return refuse("address type");
        }
    };
    let mut p = [0u8; 2];
    s.read_exact(&mut p).await?;
    let port = u16::from_be_bytes(p);
    match connect(host, port, name).await {
        Ok(mut far) => {
            s.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
            let _ = tokio::io::copy_bidirectional(&mut s, &mut far).await;
            Ok(())
        }
        Err(e) => {
            s.write_all(&[5, 4, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
            Err(e)
        }
    }
}

/// Tor in this process: Arti bootstrapped with its state and cache in the given folders (they must
/// survive restarts: a wiped cache cost a cold start about 6 s, and once in ten failed outright,
/// in the 2026-11-25 measurement), behind the listener. One isolation token per username.
pub struct Tor {
    pub listener: Listener,
    _runtime: tokio::runtime::Runtime,
}

impl Tor {
    /// Starts Arti and the listener on their own runtime and threads; returns once Tor has
    /// bootstrapped.
    pub fn start(state_dir: &str, cache_dir: &str) -> Result<Tor, String> {
        // rustls needs one process-wide crypto provider; another part of the app may have set it
        let _ = rustls::crypto::ring::default_provider().install_default();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("bitaid-tor")
            .enable_all()
            .build()
            .map_err(|e| e.to_string())?;
        let (state, cache) = (state_dir.to_string(), cache_dir.to_string());
        let listener = runtime.block_on(async move {
            let config = arti_client::config::TorClientConfigBuilder::from_directories(&state, &cache)
                .build()
                .map_err(|e| e.to_string())?;
            let client = arti_client::TorClient::create_bootstrapped(config).await.map_err(|e| e.to_string())?;
            let tokens: Arc<Mutex<HashMap<String, arti_client::IsolationToken>>> = Default::default();
            let connect: Connector = Arc::new(move |host: String, port: u16, name: String| {
                let client = client.clone();
                let token = *tokens
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .entry(name)
                    .or_insert_with(arti_client::IsolationToken::new);
                Box::pin(async move {
                    let mut prefs = arti_client::StreamPrefs::new();
                    prefs.set_isolation(token);
                    let s = client
                        .connect_with_prefs((host.as_str(), port), &prefs)
                        .await
                        .map_err(|e| std::io::Error::other(e.to_string()))?;
                    Ok(Box::new(s) as Box<dyn Stream>)
                })
            });
            serve(connect).await.map_err(|e| e.to_string())
        })?;
        Ok(Tor { listener, _runtime: runtime })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A connector that dials the far side directly and records which name each stream used.
    fn direct(seen: Arc<Mutex<Vec<String>>>) -> Connector {
        Arc::new(move |host: String, port: u16, name: String| {
            seen.lock().unwrap().push(name);
            Box::pin(async move {
                let s = TcpStream::connect((host.as_str(), port)).await?;
                Ok(Box::new(s) as Box<dyn Stream>)
            })
        })
    }

    async fn echo() -> u16 {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = l.accept().await.unwrap();
                tokio::spawn(async move {
                    let (mut r, mut w) = s.split();
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                });
            }
        });
        port
    }

    async fn socks(l: &Listener, auth: Option<(&str, &str)>, port: u16) -> std::io::Result<TcpStream> {
        let mut s = TcpStream::connect(l.addr).await?;
        match auth {
            None => s.write_all(&[5, 1, 0]).await?,
            Some(_) => s.write_all(&[5, 1, 2]).await?,
        }
        let mut m = [0u8; 2];
        s.read_exact(&mut m).await?;
        if m[1] != 2 {
            return refuse("method refused");
        }
        let (u, p) = auth.unwrap();
        let mut a = vec![1, u.len() as u8];
        a.extend_from_slice(u.as_bytes());
        a.push(p.len() as u8);
        a.extend_from_slice(p.as_bytes());
        s.write_all(&a).await?;
        let mut st = [0u8; 2];
        s.read_exact(&mut st).await?;
        if st[1] != 0 {
            return refuse("auth refused");
        }
        let host = b"127.0.0.1";
        let mut req = vec![5, 1, 0, 3, host.len() as u8];
        req.extend_from_slice(host);
        req.extend_from_slice(&port.to_be_bytes());
        s.write_all(&req).await?;
        let mut rep = [0u8; 10];
        s.read_exact(&mut rep).await?;
        if rep[1] != 0 {
            return refuse("connect refused");
        }
        Ok(s)
    }

    #[tokio::test]
    async fn only_the_secret_gets_through_and_names_reach_the_connector() {
        let seen = Arc::new(Mutex::new(vec![]));
        let l = serve(direct(seen.clone())).await.unwrap();
        let port = echo().await;
        // no auth: refused at the greeting
        assert!(socks(&l, None, port).await.is_err());
        // a wrong secret: refused before anything is dialled
        assert!(socks(&l, Some(("main", "not-the-secret")), port).await.is_err());
        assert!(seen.lock().unwrap().is_empty());
        // the secret: through, and the stream works
        let mut s = socks(&l, Some(("main", &l.secret)), port).await.unwrap();
        s.write_all(b"ping").await.unwrap();
        let mut b = [0u8; 4];
        s.read_exact(&mut b).await.unwrap();
        assert_eq!(&b, b"ping");
        // a second name: the connector sees it, so it can isolate it
        let _q = socks(&l, Some(("q-1", &l.secret)), port).await.unwrap();
        assert_eq!(*seen.lock().unwrap(), vec!["main".to_string(), "q-1".to_string()]);
        // the value the node is given
        assert!(l.socks("main").starts_with(&format!("main:{}@127.0.0.1:", l.secret)));
    }

    /// The node's two ways out through the listener: gossip's SOCKS client and the HTTP agent
    /// (`ureq`), each with the secret in the proxy address.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_node_connects_with_the_secret() {
        let seen = Arc::new(Mutex::new(vec![]));
        let l = serve(direct(seen.clone())).await.unwrap();
        let port = echo().await;
        let proxy = l.socks("main");
        let bad = format!("main:wrong@{}", l.addr);
        let http = {
            let h = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let hp = h.local_addr().unwrap().port();
            tokio::spawn(async move {
                let (mut s, _) = h.accept().await.unwrap();
                let mut b = [0u8; 1024];
                let _ = s.read(&mut b).await;
                let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").await;
            });
            hp
        };
        let (p2, b2) = (proxy.clone(), bad.clone());
        let r = tokio::task::spawn_blocking(move || {
            // gossip: through with the secret, refused without it
            use std::io::{Read, Write};
            let mut s = bitaid_node::gossip::socks5_connect(&p2, "127.0.0.1", port)?;
            s.write_all(b"hi")?;
            let mut b = [0u8; 2];
            s.read_exact(&mut b)?;
            assert_eq!(&b, b"hi");
            assert!(bitaid_node::gossip::socks5_connect(&b2, "127.0.0.1", port).is_err());
            // ureq, as http_for builds it
            let agent = ureq::AgentBuilder::new().proxy(ureq::Proxy::new(format!("socks5://{p2}")).unwrap()).build();
            let body = agent.get(&format!("http://127.0.0.1:{http}/")).call().map_err(|e| std::io::Error::other(e.to_string()))?.into_string()?;
            assert_eq!(body, "ok");
            Ok::<_, std::io::Error>(())
        })
        .await
        .unwrap();
        r.unwrap();
        assert!(seen.lock().unwrap().iter().all(|n| n == "main"));
    }
}
