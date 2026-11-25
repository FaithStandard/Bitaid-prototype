# Design note: M4, a minimal Android app over the same core

Status: proposal (2026-11-25), for review before any code. Milestone M4 of the README.

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

## Sources

- Arti 2.6.0 (September 2026): https://blog.torproject.org/arti_2_6_0_released/
- Arti on Android, the integration guide: https://arti.torproject.org/integrating-arti/custom-wrappers/android
- Tor VPN for Android, built on Arti: https://blog.torproject.org/tor-vpn-beta/
- Guardian Project, Arti on mobile: https://tordev.guardianproject.info/tor-on-android/arti-mobile-on-android
