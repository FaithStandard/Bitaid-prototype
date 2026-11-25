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

## The open question M4 cannot dodge: the phone's view of the chain

Every phone in the runs trusts the PC's bitcoind, over Tor RPC, for heights, UTXOs, the anchored records
(OP_RETURN), postings and the fee market. For the prototype that was a deliberate shortcut. For M4 there
are three paths:

| Path | Trust | Cost on a phone | Problem |
|---|---|---|---|
| A node the user chooses (own node, a friend's), over Tor RPC | that node | none | today's model: fine for operators, not for everyone |
| A BIP157/158 light client in-app (compact block filters) | none beyond proof of work | filters, plus the blocks that match | **BIP158 filters leave out OP_RETURN outputs**, and Bitaid's anchors and postings are OP_RETURN records, so every block would have to be fetched |
| An Electrum-protocol server over Tor | the server, partly | small | the same problem for OP_RETURN, unless records move to scripts |

The cleanest fix is in the protocol rather than the app: make every record a phone must find also
create an output script the filters include. For example, give each case's records a small output
under a key derived from the case, so a phone watching its case's scripts sees them through BIP158.
This is a Specification question (§7, anchoring). M4 ships path 1, with the node configurable, and
opens the question as an issue.

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

## Sources

- Arti 2.6.0 (September 2026): https://blog.torproject.org/arti_2_6_0_released/
- Arti on Android, the integration guide: https://arti.torproject.org/integrating-arti/custom-wrappers/android
- Tor VPN for Android, built on Arti: https://blog.torproject.org/tor-vpn-beta/
- Guardian Project, Arti on mobile: https://tordev.guardianproject.info/tor-on-android/arti-mobile-on-android
