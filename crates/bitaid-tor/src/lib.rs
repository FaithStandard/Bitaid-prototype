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
//!   light path (Specification §7.2) uses names starting `q-`, which get a fresh circuit for every
//!   stream and are never stored (`Isolation`).
//! - **Bounds.** A handshake must finish in 5 s, at most 16 connections may be unauthenticated and
//!   128 open at once, and a stream ends when one side has ended and the other has drained, or when
//!   nothing moves for 10 minutes (`Limits`). `Tor::network_changed` closes every open stream.
//!
//! The listener's front end (`serve`) is independent of Arti: it takes any connector, so its auth and
//! its isolation are tested without the Tor network.

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{watch, Semaphore};
use tokio::time::timeout;

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

/// The listener's bounds (review of bitaid-tor, Neon, 2026-11-25). Any app on the device can open
/// the loopback port, so nothing a client does before it has given the secret may hold resources for
/// long or in number; and a stream whose far side has gone silent (a dead circuit after a network
/// switch) must end rather than hold a task and a Tor stream for ever.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Connections at once, authenticated or not.
    pub total: usize,
    /// Connections at once that have not yet given the secret: a local flood fills these and is
    /// refused, while authenticated streams keep the rest of `total`.
    pub unauthenticated: usize,
    /// The whole SOCKS handshake (greeting, auth, CONNECT request) must arrive within this.
    pub handshake: Duration,
    /// Opening the stream through Tor: an onion's rendezvous on a cold start took up to 27 s in the
    /// 2026-11-25 measurement; this is the outer bound, Arti's own timeouts act first.
    pub connect: Duration,
    /// A stream with no byte either way for this long is closed (well above gossip's keepalive).
    pub idle: Duration,
    /// Once one side has ended, how long the other may still deliver what it has.
    pub drain: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            total: 128,
            unauthenticated: 16,
            handshake: Duration::from_secs(5),
            connect: Duration::from_secs(180),
            idle: Duration::from_secs(600),
            drain: Duration::from_secs(30),
        }
    }
}

/// A running listener: where it is and the secret it wants.
#[derive(Clone)]
pub struct Listener {
    pub addr: SocketAddr,
    pub secret: String,
    /// Bumped to close every open stream (a network change: they all ride the old network's
    /// channels).
    close: watch::Sender<u64>,
}

impl Listener {
    /// The value for `BITAID_SOCKS`: `name:secret@127.0.0.1:port`. The node passes the name as the
    /// SOCKS username, which picks the circuit isolation. It carries the secret: the app must never
    /// log it (logcat, `Event::Log`).
    pub fn socks(&self, name: &str) -> String {
        format!("{name}:{}@{}", self.secret, self.addr)
    }

    /// Closes every stream open now; new ones are unaffected.
    pub fn close_streams(&self) {
        self.close.send_modify(|g| *g += 1);
    }
}

/// Binds an ephemeral loopback port and serves SOCKS5 CONNECT on it through `connect`, for clients
/// that give the secret, within the default `Limits`. Returns once bound; serving runs on the
/// current tokio runtime.
pub async fn serve(connect: Connector) -> std::io::Result<Listener> {
    serve_with(connect, Limits::default()).await
}

pub async fn serve_with(connect: Connector, limits: Limits) -> std::io::Result<Listener> {
    let tcp = TcpListener::bind("127.0.0.1:0").await?;
    let addr = tcp.local_addr()?;
    let secret = hex::encode(rand::random::<[u8; 16]>());
    let (close, _) = watch::channel(0u64);
    let listener = Listener { addr, secret: secret.clone(), close: close.clone() };
    let total = Arc::new(Semaphore::new(limits.total));
    let unauth = Arc::new(Semaphore::new(limits.unauthenticated));
    tokio::spawn(async move {
        loop {
            let s = match tcp.accept().await {
                Ok((s, _)) => s,
                // out of descriptors, most likely: wait rather than spin
                Err(_) => {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            };
            // over either cap: closed at once, before a byte is read
            let Ok(all) = total.clone().try_acquire_owned() else { continue };
            let Ok(pre) = unauth.clone().try_acquire_owned() else { continue };
            let (connect, secret, closed) = (connect.clone(), secret.clone(), close.subscribe());
            tokio::spawn(async move {
                let _all = all;
                let _ = handle(s, &secret, connect, limits, pre, closed).await;
            });
        }
    });
    Ok(listener)
}

static DEBUG: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Logs each stream's target, outcome and timing on stderr (the test tool's `--debug`). Never the
/// secret; the app leaves it off.
pub fn set_debug(on: bool) {
    DEBUG.store(on, std::sync::atomic::Ordering::Relaxed);
}

fn note(f: impl FnOnce() -> String) {
    if DEBUG.load(std::sync::atomic::Ordering::Relaxed) {
        eprintln!("[bitaid-tor] {}", f());
    }
}

fn refuse<T>(why: &str) -> std::io::Result<T> {
    Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, why.to_string()))
}

fn timed_out<T>(what: &str) -> std::io::Result<T> {
    Err(std::io::Error::new(std::io::ErrorKind::TimedOut, what.to_string()))
}

/// The SOCKS handshake up to a CONNECT target: the greeting, RFC 1929 auth checked against the
/// secret (anything else refused), the request. Returns the name, host and port.
async fn handshake(s: &mut TcpStream, secret: &str) -> std::io::Result<(String, String, u16)> {
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
    // compared without stopping at the first differing byte; an empty name is refused too, so no
    // client falls into a shared "" isolation by mistake
    let ok = v[0] == 1
        && !user.is_empty()
        && pass.len() == secret.len()
        && pass.iter().zip(secret.as_bytes()).fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0;
    if !ok {
        s.write_all(&[1, 1]).await?;
        return refuse("wrong secret or no name");
    }
    s.write_all(&[1, 0]).await?;
    let name = String::from_utf8_lossy(&user).to_string();
    // CONNECT request: domain names (Tor resolves them) and literal IPv4 or IPv6 addresses
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
        4 => {
            let mut a = [0u8; 16];
            s.read_exact(&mut a).await?;
            std::net::Ipv6Addr::from(a).to_string()
        }
        _ => {
            s.write_all(&[5, 8, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
            return refuse("address type");
        }
    };
    let mut p = [0u8; 2];
    s.read_exact(&mut p).await?;
    Ok((name, host, u16::from_be_bytes(p)))
}

/// One client: the handshake within `limits.handshake` (holding one of the unauthenticated permits
/// until then), one CONNECT, then bytes both ways until either side ends, the stream idles or the
/// streams are closed.
async fn handle(
    mut s: TcpStream,
    secret: &str,
    connect: Connector,
    limits: Limits,
    pre: tokio::sync::OwnedSemaphorePermit,
    mut closed: watch::Receiver<u64>,
) -> std::io::Result<()> {
    let (name, host, port) = match timeout(limits.handshake, handshake(&mut s, secret)).await {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => {
            note(|| format!("refused: {e}"));
            return Err(e);
        }
        Err(_) => {
            note(|| "handshake timed out".into());
            return timed_out("handshake");
        }
    };
    drop(pre);
    let t0 = Instant::now();
    let what = format!("{host}:{port} as {name}");
    note(|| format!("connecting {what}"));
    let far = match timeout(limits.connect, connect(host, port, name)).await {
        Ok(Ok(far)) => far,
        Ok(Err(e)) => {
            note(|| format!("connect {what} failed after {:.1} s: {e}", t0.elapsed().as_secs_f64()));
            let _ = s.write_all(&[5, 4, 0, 1, 0, 0, 0, 0, 0, 0]).await;
            return Err(e);
        }
        Err(_) => {
            note(|| format!("connect {what} timed out after {:.1} s", t0.elapsed().as_secs_f64()));
            let _ = s.write_all(&[5, 6, 0, 1, 0, 0, 0, 0, 0, 0]).await;
            return timed_out("connect");
        }
    };
    note(|| format!("connected {what} in {:.1} s", t0.elapsed().as_secs_f64()));
    s.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
    closed.mark_unchanged();
    let r = tokio::select! {
        r = relay(s, far, limits) => r,
        _ = closed.changed() => Ok(()),
    };
    note(|| format!("closed {what} after {:.1} s: {r:?}", t0.elapsed().as_secs_f64()));
    r
}

/// Bytes both ways. Unlike `copy_bidirectional`, which waits for both directions to end, this ends
/// when one side ends and the other has had `limits.drain` to finish (a client that gave up and
/// closed must not leave the task waiting on a dead circuit), or when nothing has moved either way
/// for `limits.idle`.
async fn relay(client: TcpStream, far: Box<dyn Stream>, limits: Limits) -> std::io::Result<()> {
    let (cr, cw) = tokio::io::split(client);
    let (fr, fw) = tokio::io::split(far);
    let last = Mutex::new(Instant::now());
    let up = pump(cr, fw, &last, limits.idle);
    let down = pump(fr, cw, &last, limits.idle);
    tokio::pin!(up, down);
    tokio::select! {
        r = &mut up => { r?; let _ = timeout(limits.drain, down).await; }
        r = &mut down => { r?; let _ = timeout(limits.drain, up).await; }
    }
    Ok(())
}

/// One direction: reads and writes until end of stream (then shuts the writer, passing the half
/// close on) or until both directions together have been idle for `idle`.
async fn pump<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    mut r: R,
    mut w: W,
    last: &Mutex<Instant>,
    idle: Duration,
) -> std::io::Result<()> {
    let tick = (idle / 4).max(Duration::from_millis(10));
    let quiet = || last.lock().unwrap_or_else(|e| e.into_inner()).elapsed() >= idle;
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        let n = match timeout(tick, r.read(&mut buf)).await {
            Ok(n) => n?,
            Err(_) if quiet() => return timed_out("idle"),
            Err(_) => continue,
        };
        if n == 0 {
            let _ = w.shutdown().await;
            return Ok(());
        }
        // a write that cannot drain (the other side stopped reading) is bounded the same way
        match timeout(idle, w.write_all(&buf[..n])).await {
            Ok(r) => r?,
            Err(_) => return timed_out("write"),
        }
        *last.lock().unwrap_or_else(|e| e.into_inner()) = Instant::now();
    }
}

/// Which Arti isolation token each SOCKS name gets (review of bitaid-tor, Neon, Q1). A name
/// starting `q-` is one-shot (the caller's light path, one per worker query, §7.2): a fresh token
/// every stream, never stored. Other names are kept, at most `CAP` of them, the oldest dropped
/// first, except `main`, which is never dropped (sequential requests reuse its circuits).
pub struct Isolation {
    names: HashMap<String, arti_client::IsolationToken>,
    order: VecDeque<String>,
}

impl Isolation {
    pub const CAP: usize = 64;

    pub fn new() -> Self {
        Isolation { names: HashMap::new(), order: VecDeque::new() }
    }

    pub fn token(&mut self, name: &str) -> arti_client::IsolationToken {
        if name.starts_with("q-") {
            return arti_client::IsolationToken::new();
        }
        if let Some(t) = self.names.get(name) {
            return *t;
        }
        while self.names.len() >= Self::CAP {
            let Some(i) = self.order.iter().position(|n| n != "main") else { break };
            let old = self.order.remove(i).unwrap();
            self.names.remove(&old);
        }
        let t = arti_client::IsolationToken::new();
        self.names.insert(name.to_string(), t);
        self.order.push_back(name.to_string());
        t
    }

    /// Every kept name gets a new token, so its next stream builds a new circuit.
    pub fn renew(&mut self) {
        for t in self.names.values_mut() {
            *t = arti_client::IsolationToken::new();
        }
    }

    pub fn len(&self) -> usize {
        self.names.len()
    }
}

impl Default for Isolation {
    fn default() -> Self {
        Self::new()
    }
}

/// Makes a folder for Arti's state or cache, readable by this user only: Arti's permission check
/// (fs-mistrust) refuses a folder others can write, which a phone's shared storage or a careless
/// umask would give. The check itself is kept (review of bitaid-tor, Neon, Q3).
fn private_dir(dir: &str) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("{dir}: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).map_err(|e| format!("{dir}: {e}"))?;
    }
    Ok(())
}

/// Tor in this process: Arti bootstrapped with its state and cache in the given folders (they must
/// survive restarts: a wiped cache cost a cold start about 6 s, and once in ten failed outright,
/// in the 2026-11-25 measurement), behind the listener.
pub struct Tor {
    pub listener: Listener,
    client: Arc<arti_client::TorClient<tor_rtcompat::PreferredRuntime>>,
    isolation: Arc<Mutex<Isolation>>,
    runtime: Option<tokio::runtime::Runtime>,
}

impl Tor {
    /// Starts Arti and the listener on their own runtime and threads; returns once Tor has
    /// bootstrapped.
    pub fn start(state_dir: &str, cache_dir: &str) -> Result<Tor, String> {
        // rustls needs one process-wide crypto provider; another part of the app may have set it
        let _ = rustls::crypto::ring::default_provider().install_default();
        private_dir(state_dir)?;
        private_dir(cache_dir)?;
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("bitaid-tor")
            .enable_all()
            .build()
            .map_err(|e| e.to_string())?;
        let (state, cache) = (state_dir.to_string(), cache_dir.to_string());
        let isolation: Arc<Mutex<Isolation>> = Default::default();
        let iso = isolation.clone();
        let (listener, client) = runtime.block_on(async move {
            let mut b = arti_client::config::TorClientConfigBuilder::from_directories(&state, &cache);
            // said, not left to defaults: onions yes; nothing on this device or its LAN
            b.address_filter().allow_onion_addrs(true).allow_local_addrs(false);
            let config = b.build().map_err(|e| e.to_string())?;
            let client = arti_client::TorClient::create_bootstrapped(config).await.map_err(|e| e.to_string())?;
            let c = client.clone();
            let connect: Connector = Arc::new(move |host: String, port: u16, name: String| {
                let client = c.clone();
                let token = iso.lock().unwrap_or_else(|e| e.into_inner()).token(&name);
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
            let listener = serve(connect).await.map_err(|e| e.to_string())?;
            Ok::<_, String>((listener, client))
        })?;
        Ok(Tor { listener, client, isolation, runtime: Some(runtime) })
    }

    /// Off duty: Arti's background work sleeps (battery), and wakes by itself if a stream is asked
    /// for. On duty: normal.
    pub fn set_dormant(&self, soft: bool) {
        self.client.set_dormant(if soft { arti_client::DormantMode::Soft } else { arti_client::DormantMode::Normal });
    }

    /// For the app's network-change callback (Wi-Fi to cellular and back): every open stream is
    /// closed, since it rides a channel bound to the old network, and every name's next stream
    /// builds a fresh circuit, rather than each waiting out a stalled socket. The node's callers
    /// reconnect as after any dropped stream.
    pub fn network_changed(&self) {
        self.client.set_dormant(arti_client::DormantMode::Normal);
        self.isolation.lock().unwrap_or_else(|e| e.into_inner()).renew();
        self.listener.close_streams();
    }
}

impl Drop for Tor {
    /// Stops the listener and Arti's tasks without waiting on them for long (the app's service
    /// stopping must not hang); from inside an async context, where a blocking shutdown would panic,
    /// it leaves them to end in the background.
    fn drop(&mut self) {
        if let Some(rt) = self.runtime.take() {
            if tokio::runtime::Handle::try_current().is_ok() {
                rt.shutdown_background();
            } else {
                rt.shutdown_timeout(Duration::from_secs(2));
            }
        }
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

    fn quick() -> Limits {
        Limits {
            total: 6,
            unauthenticated: 2,
            handshake: Duration::from_millis(300),
            connect: Duration::from_secs(2),
            idle: Duration::from_millis(400),
            drain: Duration::from_millis(300),
        }
    }

    /// A far side that accepts and then never sends nor closes (a dead circuit).
    async fn silent() -> u16 {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            let mut held = vec![];
            loop {
                held.push(l.accept().await.unwrap().0);
            }
        });
        port
    }

    /// A far stream that counts itself while the listener holds it.
    struct Counted(TcpStream, Arc<std::sync::atomic::AtomicUsize>);
    impl Drop for Counted {
        fn drop(&mut self) {
            self.1.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
        }
    }
    impl AsyncRead for Counted {
        fn poll_read(mut self: Pin<&mut Self>, cx: &mut std::task::Context<'_>, b: &mut tokio::io::ReadBuf<'_>) -> std::task::Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_read(cx, b)
        }
    }
    impl AsyncWrite for Counted {
        fn poll_write(mut self: Pin<&mut Self>, cx: &mut std::task::Context<'_>, b: &[u8]) -> std::task::Poll<std::io::Result<usize>> {
            Pin::new(&mut self.0).poll_write(cx, b)
        }
        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_flush(cx)
        }
        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_shutdown(cx)
        }
    }

    fn counted(open: Arc<std::sync::atomic::AtomicUsize>) -> Connector {
        Arc::new(move |host: String, port: u16, _name: String| {
            let open = open.clone();
            Box::pin(async move {
                let s = TcpStream::connect((host.as_str(), port)).await?;
                open.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok(Box::new(Counted(s, open)) as Box<dyn Stream>)
            })
        })
    }

    #[tokio::test]
    async fn a_stalled_or_flooding_client_holds_nothing_for_long() {
        let l = serve_with(direct(Default::default()), quick()).await.unwrap();
        let port = echo().await;
        // two silent connections fill the unauthenticated permits: a third is closed at once
        let _a = TcpStream::connect(l.addr).await.unwrap();
        let _b = TcpStream::connect(l.addr).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        let mut c = TcpStream::connect(l.addr).await.unwrap();
        let mut b = [0u8; 1];
        assert!(matches!(timeout(Duration::from_millis(200), c.read(&mut b)).await, Ok(Ok(0)) | Ok(Err(_))));
        // once the handshake time is up they are dropped, and an authenticated client gets in
        tokio::time::sleep(Duration::from_millis(400)).await;
        let mut s = socks(&l, Some(("main", &l.secret)), port).await.unwrap();
        s.write_all(b"ok").await.unwrap();
        let mut r = [0u8; 2];
        s.read_exact(&mut r).await.unwrap();
        // the stalled ones were closed by the listener
        let mut a = _a;
        assert!(matches!(a.read(&mut b).await, Ok(0) | Err(_)));
    }

    #[tokio::test]
    async fn an_empty_name_is_refused_and_ipv6_is_understood() {
        let seen = Arc::new(Mutex::new(vec![]));
        let l = serve(direct(seen.clone())).await.unwrap();
        let port = echo().await;
        assert!(socks(&l, Some(("", &l.secret)), port).await.is_err());
        assert!(seen.lock().unwrap().is_empty());
        // an IPv6 literal reaches the connector as an address (::1 may be absent here: only the
        // parsing is checked, through the name the connector saw)
        let mut s = TcpStream::connect(l.addr).await.unwrap();
        s.write_all(&[5, 1, 2]).await.unwrap();
        let mut m = [0u8; 2];
        s.read_exact(&mut m).await.unwrap();
        let mut a = vec![1, 4];
        a.extend_from_slice(b"main");
        a.push(l.secret.len() as u8);
        a.extend_from_slice(l.secret.as_bytes());
        s.write_all(&a).await.unwrap();
        s.read_exact(&mut m).await.unwrap();
        assert_eq!(m, [1, 0]);
        let mut req = vec![5, 1, 0, 4];
        req.extend_from_slice(&std::net::Ipv6Addr::LOCALHOST.octets());
        req.extend_from_slice(&port.to_be_bytes());
        s.write_all(&req).await.unwrap();
        let mut rep = [0u8; 10];
        s.read_exact(&mut rep).await.unwrap();
        assert_eq!(rep[0], 5);
        assert_eq!(*seen.lock().unwrap(), vec!["main".to_string()]);
    }

    /// The client gives up (closes) while the far side never answers: the stream ends after the
    /// drain time instead of waiting on the dead side for ever. And a stream silent both ways ends
    /// after the idle time.
    #[tokio::test]
    async fn a_dead_far_side_is_let_go() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let open = Arc::new(AtomicUsize::new(0));
        let port = silent().await;
        let l = serve_with(counted(open.clone()), quick()).await.unwrap();
        // half close by the client
        let mut s = socks(&l, Some(("main", &l.secret)), port).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(open.load(Ordering::SeqCst), 1);
        s.shutdown().await.unwrap();
        drop(s);
        tokio::time::sleep(Duration::from_millis(800)).await;
        assert_eq!(open.load(Ordering::SeqCst), 0, "the far stream outlived the client");
        // idle both ways, client still there
        let mut s = socks(&l, Some(("main", &l.secret)), port).await.unwrap();
        tokio::time::sleep(Duration::from_millis(1000)).await;
        assert_eq!(open.load(Ordering::SeqCst), 0, "an idle stream was kept");
        let mut b = [0u8; 1];
        assert!(matches!(s.read(&mut b).await, Ok(0) | Err(_)));
    }

    #[tokio::test]
    async fn a_network_change_closes_open_streams() {
        let l = serve(direct(Default::default())).await.unwrap();
        let port = echo().await;
        let mut s = socks(&l, Some(("main", &l.secret)), port).await.unwrap();
        l.close_streams();
        let mut b = [0u8; 1];
        assert!(matches!(timeout(Duration::from_secs(2), s.read(&mut b)).await, Ok(Ok(0)) | Ok(Err(_))));
        // new streams are unaffected
        let mut s = socks(&l, Some(("main", &l.secret)), port).await.unwrap();
        s.write_all(b"x").await.unwrap();
        s.read_exact(&mut b).await.unwrap();
    }

    #[test]
    fn isolation_is_bounded_and_one_shot_names_are_not_kept() {
        let mut i = Isolation::new();
        let main = i.token("main");
        assert_eq!(i.token("main"), main);
        // one-shot: always fresh, never kept
        assert_ne!(i.token("q-1"), i.token("q-1"));
        assert_eq!(i.len(), 1);
        for k in 0..200 {
            i.token(&format!("g{k}"));
        }
        assert_eq!(i.len(), Isolation::CAP);
        assert_eq!(i.token("main"), main, "main was dropped");
        assert_eq!(i.token("g199"), i.token("g199"));
        i.renew();
        assert_ne!(i.token("main"), main);
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
