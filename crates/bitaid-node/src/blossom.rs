//! Evidence storage on Blossom-compatible servers (Specification §8.1; Blossom BUD-01/BUD-02).
//!
//! Blobs are addressed by their SHA-256 and served over plain HTTP, with range requests for slices.
//! An upload carries a Nostr authorisation event (kind 24242, `t=upload`, the blob's hash in `x`, an
//! expiration). A Bitaid archivist accepts an upload only if it also names a live case (`c`) and the
//! uploader is a party to it: BCAEN stores only evidence tied to a bonded, live incident. Footage is
//! encrypted before upload, so the archivist holds ciphertext it cannot read.
use crate::nostr::{kind, now, Event};
use crate::wire::{b64, unb64};
use bitaid_core::hashes::sha256;
use bitcoin::secp256k1::Keypair;
use serde_json::json;
use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

pub const SLICE: usize = 4096;

/// Merkle root over the SHA-256 of each 4 KiB slice (§8.1): lets a prober check one slice against
/// the anchored root without fetching the blob.
pub fn slice_root(blob: &[u8]) -> [u8; 32] {
    let mut level: Vec<[u8; 32]> = blob.chunks(SLICE).map(sha256).collect();
    if level.is_empty() {
        return sha256(b"");
    }
    while level.len() > 1 {
        level = level
            .chunks(2)
            .map(|p| {
                let mut b = p[0].to_vec();
                b.extend_from_slice(p.get(1).unwrap_or(&p[0]));
                sha256(&b)
            })
            .collect();
    }
    level[0]
}

/// Which uploaders may store evidence for which case. The archivist fills it from the alerts and
/// rosters it sees on the relays.
#[derive(Clone, Default)]
pub struct Policy(Arc<Mutex<HashMap<String, HashSet<String>>>>);

impl Policy {
    pub fn allow(&self, case_id: &str, uploader: &str) {
        self.0
            .lock()
            .unwrap()
            .entry(case_id.into())
            .or_default()
            .insert(uploader.into());
    }
    pub fn permits(&self, case_id: &str, uploader: &str) -> bool {
        self.0
            .lock()
            .unwrap()
            .get(case_id)
            .map(|s| s.contains(uploader))
            .unwrap_or(false)
    }
}

pub struct Server {
    pub url: String,
    pub policy: Policy,
    pub stored: Arc<Mutex<u64>>,
    pub refused: Arc<Mutex<u64>>,
}

fn header(req: &tiny_http::Request, name: &str) -> Option<String> {
    req.headers()
        .iter()
        .find(|h| h.field.as_str().as_str().eq_ignore_ascii_case(name))
        .map(|h| h.value.as_str().to_string())
}

fn check_auth(auth: Option<String>, hash: &str, policy: &Policy) -> Result<String, String> {
    let a = auth.ok_or("missing authorization")?;
    let ev = a
        .strip_prefix("Nostr ")
        .ok_or("authorization is not Nostr")?;
    let ev: Event =
        serde_json::from_slice(&unb64(ev.trim()).ok_or("bad base64")?).map_err(|_| "bad event")?;
    if !ev.verify() || ev.kind != kind::BLOSSOM_AUTH {
        return Err("invalid authorization event".into());
    }
    if ev.tag("t") != Some("upload") {
        return Err("not an upload authorization".into());
    }
    if !ev.tag_values("x").any(|x| x == hash) {
        return Err("authorization does not name this blob".into());
    }
    let exp: u64 = ev
        .tag("expiration")
        .and_then(|s| s.parse().ok())
        .ok_or("no expiration")?;
    if exp < now() {
        return Err("authorization expired".into());
    }
    let case = ev.tag("c").ok_or("no case named")?;
    if !policy.permits(case, &ev.pubkey) {
        return Err("uploader is not a party to a live case".into());
    }
    Ok(ev.pubkey)
}

/// Serves blobs from `dir` on `addr` in a background thread.
pub fn spawn(addr: &str, dir: PathBuf, policy: Policy) -> std::io::Result<Server> {
    std::fs::create_dir_all(&dir)?;
    let srv = tiny_http::Server::http(addr).map_err(|e| std::io::Error::other(e.to_string()))?;
    let url = format!("http://{}", srv.server_addr().to_ip().unwrap());
    let (stored, refused) = (Arc::new(Mutex::new(0u64)), Arc::new(Mutex::new(0u64)));
    let (s2, r2, p2) = (stored.clone(), refused.clone(), policy.clone());
    std::thread::spawn(move || {
        for req in srv.incoming_requests() {
            // one thread per request, so a slow client never holds up the others
            let (dir, s2, r2, p2) = (dir.clone(), s2.clone(), r2.clone(), p2.clone());
            std::thread::spawn(move || serve(req, &dir, &s2, &r2, &p2));
        }
    });
    Ok(Server {
        url,
        policy,
        stored,
        refused,
    })
}

fn serve(
    mut req: tiny_http::Request,
    dir: &std::path::Path,
    s2: &Arc<Mutex<u64>>,
    r2: &Arc<Mutex<u64>>,
    p2: &Policy,
) {
    {
        {
            let path = req.url().trim_start_matches('/').to_string();
            let resp = match req.method() {
                tiny_http::Method::Put if path == "upload" => {
                    let mut body = Vec::new();
                    let _ = req.as_reader().read_to_end(&mut body);
                    let hash = hex::encode(sha256(&body));
                    match check_auth(header(&req, "authorization"), &hash, p2) {
                        Ok(_) => {
                            let _ = std::fs::write(dir.join(&hash), &body);
                            *s2.lock().unwrap() += 1;
                            let d = json!({"sha256": hash, "size": body.len(), "type": "application/octet-stream", "uploaded": now()});
                            tiny_http::Response::from_string(d.to_string()).with_status_code(200)
                        }
                        Err(e) => {
                            *r2.lock().unwrap() += 1;
                            tiny_http::Response::from_string(e).with_status_code(401)
                        }
                    }
                }
                tiny_http::Method::Get | tiny_http::Method::Head => {
                    let h: String = path.chars().take(64).collect();
                    if h.len() != 64 || !h.chars().all(|c| c.is_ascii_hexdigit()) {
                        tiny_http::Response::from_string("not found").with_status_code(404)
                    } else {
                        match std::fs::read(dir.join(&h)) {
                            Ok(b) => {
                                let (lo, hi) = header(&req, "range")
                                    .and_then(|r| {
                                        let r = r.strip_prefix("bytes=")?;
                                        let (a, b) = r.split_once('-')?;
                                        Some((a.parse::<usize>().ok()?, b.parse::<usize>().ok()?))
                                    })
                                    .map(|(a, z)| (a.min(b.len()), (z + 1).min(b.len())))
                                    .unwrap_or((0, b.len()));
                                let code = if (lo, hi) == (0, b.len()) { 200 } else { 206 };
                                tiny_http::Response::from_data(b[lo..hi].to_vec())
                                    .with_status_code(code)
                            }
                            Err(_) => {
                                tiny_http::Response::from_string("not found").with_status_code(404)
                            }
                        }
                    }
                }
                _ => tiny_http::Response::from_string("not supported").with_status_code(405),
            };
            // one request per connection: no client ever waits behind a kept-alive connection
            let resp = resp.with_header(
                tiny_http::Header::from_bytes(&b"Connection"[..], &b"close"[..]).unwrap(),
            );
            let _ = req.respond(resp);
        }
    }
}

/// The BUD-02 authorisation header for uploading `blob` as evidence of `case_id`.
pub fn auth_header(keys: &Keypair, case_id: &str, blob_hash: &str) -> String {
    let ev = Event::new(
        keys,
        kind::BLOSSOM_AUTH,
        vec![
            vec!["t".into(), "upload".into()],
            vec!["x".into(), blob_hash.into()],
            vec!["expiration".into(), (now() + 300).to_string()],
            vec!["c".into(), case_id.into()],
        ],
        "Bitaid evidence upload".into(),
    );
    format!(
        "Nostr {}",
        b64(serde_json::to_string(&ev).unwrap().as_bytes())
    )
}

/// Uploads; returns the blob hash the server confirmed.
pub fn upload(server: &str, keys: &Keypair, case_id: &str, blob: &[u8]) -> Result<String, String> {
    let server = &crate::local_url(server);
    let hash = hex::encode(sha256(blob));
    let r = crate::http_for(server)
        .put(&format!("{server}/upload"))
        .set("Authorization", &auth_header(keys, case_id, &hash))
        .send_bytes(blob);
    match r {
        Ok(resp) => {
            let v: serde_json::Value =
                serde_json::from_str(&resp.into_string().map_err(|e| e.to_string())?)
                    .map_err(|e| e.to_string())?;
            if v["sha256"] == hash {
                Ok(hash)
            } else {
                Err("server stored a different hash".into())
            }
        }
        Err(ureq::Error::Status(code, resp)) => Err(format!(
            "{code}: {}",
            resp.into_string().unwrap_or_default()
        )),
        Err(e) => Err(e.to_string()),
    }
}

/// Fetches a blob and checks it against its hash.
pub fn fetch(server: &str, hash: &str) -> Result<Vec<u8>, String> {
    let server = &crate::local_url(server);
    let resp = crate::http_for(server)
        .get(&format!("{server}/{hash}"))
        .timeout(std::time::Duration::from_secs(
            if server.contains(".onion") { 90 } else { 20 },
        ))
        .call()
        .map_err(|e| e.to_string())?;
    let mut b = Vec::new();
    resp.into_reader()
        .read_to_end(&mut b)
        .map_err(|e| e.to_string())?;
    if hex::encode(sha256(&b)) != hash {
        return Err("blob does not match its hash".into());
    }
    Ok(b)
}

/// Fetches one 4 KiB slice by range request.
pub fn fetch_slice(server: &str, hash: &str, i: usize) -> Result<Vec<u8>, String> {
    let server = &crate::local_url(server);
    let resp = crate::http_for(server)
        .get(&format!("{server}/{hash}"))
        .set(
            "Range",
            &format!("bytes={}-{}", i * SLICE, (i + 1) * SLICE - 1),
        )
        .call()
        .map_err(|e| e.to_string())?;
    let mut b = Vec::new();
    resp.into_reader()
        .read_to_end(&mut b)
        .map_err(|e| e.to_string())?;
    Ok(b)
}

/// Encrypts footage with the case's evidence key and cuts it into blobs of `chunk` bytes.
pub fn seal_footage(
    evidence_key: &[u8; 32],
    case_id: &str,
    footage: &[u8],
    chunk: usize,
) -> Vec<Vec<u8>> {
    footage
        .chunks(chunk)
        .enumerate()
        .map(|(i, c)| crate::wire::encrypt(evidence_key, format!("{case_id}/{i}").as_bytes(), c))
        .collect()
}

pub fn open_footage(evidence_key: &[u8; 32], case_id: &str, blobs: &[Vec<u8>]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    for (i, b) in blobs.iter().enumerate() {
        out.extend(crate::wire::decrypt(
            evidence_key,
            format!("{case_id}/{i}").as_bytes(),
            b,
        )?);
    }
    Some(out)
}
