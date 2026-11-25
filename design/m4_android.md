# Design note: M4, a minimal Android app over the same core

Status: proposal (2026-11-25), reviewed by Neon the same day (prototype #3, handoff note
`2026-11-25-m4-review.md`); its findings are adopted in the last section. Milestone M4 of the README.

## What M4 must prove

That a caller and a responder can run Bitaid on an ordinary Android phone, without Termux and without a
separate Tor app. The protocol work runs in the same Rust code that passed the public signet runs, and the
phone behaves like an emergency device:
- an alert raised in seconds;
- a responder reachable while on duty, screen off;
- keys that never sit in plain files.

Signet only, like everything before M6. Out of scope: polish, translations and app-store packaging.

## What the prototype does today on a phone (the baseline)

Termux runs `bitaid-node` as a binary. It reaches everything through its own `tor` process (C Tor) over
SOCKS, and keeps keys in JSON files under `$HOME`. The phone is a full participant in the runs: caller or
responder, and an oracle-pool member. It trusts the PC's bitcoind, over Tor RPC, for everything on chain.

Measured failures that M4 must fix:
- **Android stopping Termux with the screen off** (Nov 22). Battery settings were the workaround.
- **Tor dropping links** (every run). The node survives this now, but each drop costs minutes.
- **Callers with no warm circuit.** The cold start was unmeasured; `scripts/cold_start.sh` measures it now (prototype issue #2).

## Architecture

```
┌──────────── Android app (Kotlin) ─────────────────────────────┐
│ Screens: on-duty switch · alert button · accept/attend/vote   │
│ Foreground service (persistent notification, while on duty)  │
│ Keystore: wraps the node's key file with a hardware key       │
└───────────────┬───────────────────────────────────────────────┘
                │ JNI (a thin, hand-written layer, or UniFFI)
┌───────────────▼───────────────────────────────────────────────┐
│ libbitaid (Rust, cdylib): bitaid-node as a library             │
│   role loop on its own threads, as today                      │
│   events out to Kotlin: alert, location, case state, checks   │
│   commands in: raise alert, accept, vote, go on/off duty      │
│ Arti (arti-client) in-process: a SOCKS listener on 127.0.0.1  │
│   that the node's existing SOCKS path (ureq, gossip) uses     │
└───────────────────────────────────────────────────────────────┘
```

### Decisions proposed

1. **The node as a library, not rewritten.** `bitaid-node`'s roles already run as loops over a `Node`.
   M4 adds a `lib` entry point that starts a role on its own thread and exposes the events Kotlin needs.
   No async rewrite: the node is synchronous, and Arti's async runtime lives on its own threads behind a
   SOCKS port, so the node's code path is the one the signet runs tested.
2. **Arti, in-process, behind a local SOCKS port.** C Tor in a second process is what Android kills.
   Arti embeds as a Rust crate, and the Tor Project's own Android VPN is built on it (sources below).
   Exposing Arti's SOCKS proxy inside the app keeps the node's networking unchanged
   (`BITAID_SOCKS=127.0.0.1:<port>`). Calling `arti-client` streams directly would be tighter, but
   would touch every network call. That is for later, if the SOCKS hop measures as a cost.
   - What is needed is only an onion-service client: phones dial Cores and never host an onion.
   - Arti's integration guide states that there is no stable Rust API and no official Android
     bindings, so the JNI layer is ours. It names `cargo-ndk`, the `static` features, `catch_unwind`
     at the boundary, and logging to logcat.
   - Neon's research (prototype issue #2) adds a warning: Arti's "ready" status does not drop when the
     network changes, so the app runs its own health probe.
3. **A foreground service while on duty**, with the battery-optimisation exemption that a safety app
   can justify:
   - It keeps the node, Arti and one warm circuit to each Core alive.
   - The Core's descriptor is refreshed every 15–30 minutes, and at once on every network change from
     Android's `ConnectivityManager`.
   - Off duty, the app may sleep. A caller pressing the alert then pays the cold start, so the app
     pre-connects when the alert screen opens (Neon's suggestion).
4. **Keys.** The node's key file stays the format it is. Its contents are encrypted with a key held
   in the Android Keystore (hardware-backed where available), so it is never readable in plain form on
   disk.
   - Test chains only, as now. The pool-member role keeps its FROST shares the same way.
   - Moving signing itself into secure hardware is not possible for BIP340, Keystore has no secp256k1
     Schnorr, and is not attempted.
5. **Two roles in the app:** caller and responder. The oracle-pool member and the arbitrator stay on
   PCs: they need long uptime and run larger replays, and a phone pool member was a test convenience.
   The prototype's three-device runs keep their PC side unchanged.
6. **Build:**
   - `cargo-ndk` for `aarch64-linux-android` (and `x86_64` for the emulator);
   - Gradle with the `.so` in `jniLibs`;
   - a debug APK installed by `adb` or side-loaded.

   The PC's WSL builds it. The tablet and phone install the APK; no Termux build is needed.

## The phone's view of the chain: the goal, and the prototype's shortcut

The prototype's phones read everything on chain from the PC's bitcoind over Tor. That is a test
compromise for the hardware at hand, not the design. The design (Specification §7, parameters: "Anchor
verification default: local full node") is:

- **Worker roles** (responders, arbitrators, archivists, pool members, Cores) run their own Bitcoin node.
  It is part of the job, as the bond is.
- **Callers** may run one, or use a node they trust. If they do neither, the app follows the chain the
  way a light wallet does, without trusting anyone in particular:
  - It keeps Bitcoin's block headers (about 4 MB a year) and checks the proof of work itself.
  - For each record of its own case, it asks for the transaction and its Merkle proof against those
    headers. It asks several independent nodes of other Bitaid participants (workers' nodes behind
    their onion services), reached over Tor like everything else. The case log already names every
    record, so the caller never has to search blocks blindly.
  - A node can only lie by leaving something out, never by inventing it (proof of work and the Merkle
    proof stop that). Asking several unrelated nodes means one honest node is enough.
  - Over Tor, the nodes learn which transactions were asked about, never who asked. Those are the
    case's own records, which the case's parties and workers already see.

So the OP_RETURN gap of BIP158 filters (Specification issue #42) matters only for discovering records
without a case log, which a caller does not need. The question for the Specification narrows to how a
caller picks its sample of nodes (from the registry of bonded workers, at random, with a cap per
operator), and how many it asks.

M4 ships the configurable trusted node first, as the prototype does, and then the headers-and-proofs
path as its own step.

## Measurement M4 adds

- **The cold start.** `scripts/cold_start.sh` measures it under Termux with C Tor. The app measures it
  again with in-process Arti, for the same marks T0–T4.
- **Delivery to a screen-off phone.** The time from an alert to its display on a responder's screen
  that has been off for an hour, under the foreground service, compared with the Nov 22 failure.
- **Battery.** The drain per day on duty, against Neon's estimate of 1–2%.

## Order of work

1. A `bitaid-node` library target, with an event channel and a command entry. The binary keeps working,
   since the suites run it.
2. An Arti SOCKS listener in-process, measured against C Tor with `cold_start.sh`'s marks.
3. A Kotlin shell: on-duty switch, alert button, the accept screen with the location, and the case's
   checks streamed as the node logs them.
4. The foreground service and network-change handling, then the screen-off test.
5. Keys under the Keystore.
6. A signet run with the tablet and phone on the app and the PC as today.
7. The caller's light path: headers plus Merkle proofs from several workers' nodes over Tor.

## Adopted from review (Neon, 2026-11-25)

All checked against the code at `1d76d99`.

**The local SOCKS port stays, behind our own small listener.**
- Every Tor connection the node makes goes through two places: `http_for` (`lib.rs`, `ureq`) and
  `gossip::socks5_connect`. The loopback hop costs nothing against Tor's seconds.
- Loopback is shared with every app on the device, and Tor's SOCKS credentials are not access control.
  Arti, like C Tor, accepts any username and password, and no-auth too, and uses them only to isolate
  streams (Neon, handoff `2026-11-25-arti-socks-isolation.md`).
- So `libbitaid` embeds `arti-client`, not the `arti` binary. In front of the `TorClient` it runs its
  own SOCKS5 listener (a few dozen lines, or `tor-socksproto`) on an ephemeral port. It accepts only
  RFC 1929 auth whose password is a random secret drawn when the process starts, and rejects no-auth
  and any wrong password before touching Tor.
- `gossip.rs` sends only no-auth today (`[5, 1, 0]`), so it gains the auth exchange; `ureq` passes the
  credentials in the proxy URL.

**Separate circuits through the username.** The listener maps the SOCKS username to an Arti isolation
token (`StreamPrefs::set_isolation` on `connect_with_prefs`):
- one fixed name (`main`) for ordinary traffic: gossip, RPC, the archive;
- a fresh name per worker query on the caller's light path (§7.2), each mapped to a new
  `IsolationToken`, so each query gets its own circuit.

**The proxy setting can change.** `http_for` caches its Tor agent in a `OnceLock` built from
`BITAID_SOCKS` for the life of the process. If Arti restarts on a new port, that agent stays bound to
the dead one. The proxy becomes a value held by the node and swappable at run time.

**No environment variables in the library.** Setting the environment in a multi-threaded process is
unsound, so `libbitaid` takes a configuration struct across JNI. `BITAID_RPC`, `BITAID_SOCKS`,
`BITAID_KEYFILE` and the rest stay for the CLI binary only.

**Step 1 is a real refactor.**
- `caller()` and `responder()` live in the 8,000-line binary and run to completion from command-line
  flags. Turning them into loops driven by commands (raise alert, accept, vote, go on or off duty) is
  the bulk of step 1.
- Every role thread is wrapped in `catch_unwind` and reports a fatal event to the app, so that a dead
  thread never leaves the screen showing "on duty". Arti's own threads are watched by the health
  probe.

**The foreground service declares its type.** Android 14 and later refuse a foreground service
without a type. It declares `specialUse` while on duty, and `location` while responding, and keeps
the battery-optimisation exemption, since deep Doze still throttles a foreground service's network.

**No key in a plain file.** The CLI's `keep_keys` appends keys to `BITAID_KEYFILE` as plain JSON lines,
a test-chain convenience. In the app, keys live in memory and persist only as the Keystore-encrypted
blob; the key-file path does not exist there.

**A responder's phone reads its own node.** A responder is a worker, so the trusted node configured
on its phone is the responder's own full node, at home and reached over Tor. The light path of §7.2 is
for callers only.

## Sources

- Arti 2.6.0 (September 2026): https://blog.torproject.org/arti_2_6_0_released/
- Arti on Android, the integration guide: https://arti.torproject.org/integrating-arti/custom-wrappers/android
- Tor VPN for Android, built on Arti: https://blog.torproject.org/tor-vpn-beta/
- Guardian Project, Arti on mobile: https://tordev.guardianproject.info/tor-on-android/arti-mobile-on-android
