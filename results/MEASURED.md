# What the prototype has measured

Facts from runs on Bitcoin's public signet, over Tor, with the caller on a phone, a responder on a tablet and
the other roles on a PC. Test coins only; amounts divided by 100; long protocol deadlines stretched 30× so
that Tor's worst delays fit (the times below are not stretched: they are what the network took). Each figure
links to the run's published log. Every node is still run by us.

## The emergency path

| What | Measured | Runs |
| --- | --- | --- |
| Alert to first responder accepted, bond checked on chain | 2.0 to 7.2 s | Nov 18, 19, 20, 23 |
| Alert to three responders accepted | 10 to 44 s | Nov 18, 19, 20, 23 |
| Exact location, sealed to an accepted responder, received | 1.2 to 4.8 s on the PC; 4.2 and 55.9 s on the tablet over Tor; 0.8 to 3.2 s under simulated Tor lag | Nov 20, 22, 23; local |
| Evidence, 512 KiB encrypted, pinned on the archivist | 2 to 19 s | Nov 18, 19, 20 |

## The money

| What | Measured | Runs |
| --- | --- | --- |
| Every payout the case can end in (39 payouts and 3 refunds) signed across three machines | 2 to 7 s; once 10 min with the phone as a slow signer | Nov 18, 19, 20 |
| A signer sending a bad signature caught, dropped, the set re-signed | every run | Nov 18, 19, 20 |
| Alert to a funded incident with every payout pre-signed (pool co-signature included) | 16 to 55 min | Nov 18, 19, 20, 22, 23 |
| All three pots settled on chain by the attested outcome | every run but Nov 22 (fixed, below) | Nov 18, 19, 20, 23 |
| A pool member attesting a different outcome caught, its shares kept as evidence, honest shares still combined | every run | Nov 18, 19, 20 |

## Disputes

| What | Measured | Runs |
| --- | --- | --- |
| Tier 1 panel drawn from a block, disclosed only to the drawn | 37 to 83 min after escalating | Nov 18, 19, 20 |
| Tier 1 verdict | 99 to 134 min after escalating | Nov 18, 19, 20 |
| Tier 2 (7 seats) verdict | 93 to 178 min after escalating | Nov 18, 19, 20, 22, 23 |
| A party following a tier it did not open reads its verdict from the commitment on chain | the tablet, tier 2 decided 5 of 7 | Nov 23 |
| A pool member whose link dropped reads what it missed from the archive before attesting; three honest shares combined | the tablet's member | Nov 23 |
| Fines into the seizure output, paid out to the vindicated dissenter (5,278 sats) | every run since the fix | Nov 19, 20 |
| Each seat staked before it was paid | 3 of 3, 7 of 7 | Nov 19, 20 |
| Naive forgeries by an outsider with no stake (postings, incidents, tier records the chain does not back) ignored | every run | Nov 18, 19, 20 |
| A node that saw nothing reads the same record from the chain and the archive alone | AUDIT_PASS | Nov 19 |

## Not yet shown

- Independent operators: every node is ours, and the cheaters cheat because a script tells them to.
- Real funds, outside review of the cryptography and the incentives.
- Attacks from inside on the public network: a party stalling the appeal it opened, a finality stall by
  unanchored escalations, a staked eclipse of a Core. The first two are fixed, the first tested locally; the
  third is a design note (design/connection_storms.md).
- The tablet received its location 4.2 s after accepting on Nov 22 but 55.9 s on Nov 23, against 1 to 5 s on
  the PC: Tor's delay to a phone-class device varies widely; to be measured over more runs.
- On Nov 22 the tablet, its link dropping, read a 7-of-7 tier as hung and its pool member attested the
  tier-1 ruling, so the reward and bounty were not attested; both fixed (above) and confirmed on Nov 23.

## Logs

- [Nov 18-19](public_signet_anchored_2026-11-19.txt)
- [Nov 19](public_signet_anchored_audit_2026-11-19.txt)
- [Nov 20](public_signet_stake_location_2026-11-20.txt)
- [Nov 23](public_signet_followers_2026-11-23.txt)

## Public signet, 2026-11-23 (second run, INDEX_FROM 332149): stopped, incident never broadcast

- Location sealed to the responders 2.1 s after accepting (on the link and in the node alike).
- Signer 2's invalid partial signature caught, its seat given up, set v1 re-signed in 2.57 s; pool
  co-signed the incident 3 of 4 with member 2 stalling (3 sessions).
- The caller's one `listunspent` to the PC's bitcoind over Tor timed out connecting (30 s) while the
  gossip link was also dropping, and the caller gave up: the incident was signed but never sent, so
  the case had no pot and the arbitration could not seat anyone. A signet reorg from block 332158
  was handled (one re-read). Fixed: chain calls that never reached the node are asked again, 5 to
  80 s apart, about 4 minutes in all (`examples/rpc_retry.rs`).

## Public signet, 2026-11-24 (INDEX_FROM 332208): tier 1 lapsed, the pool never followed tier 2

- Incident on chain (the retried RPC held through Tor drops), location 2.1-4.2 s, signer 2 caught,
  pool co-signed 3 of 4 with member 2 stalling.
- Tier 1: exactly 3 offers; every seat's stake deadline ran from the draw block, and the draw reached
  the seats 4,639 s after the escalation, so all three were late before they knew. No offer was left
  to replace them and the tier lapsed. The party carried the case to tier 2 (7 of 7 staked and paid,
  6 of 7 for I,D, committed on chain), but the replay opened tier 2 only from a committed tier 1, and
  the pool members had lapsed tier 1 by the wall clock, so none attested.
- Fixed (issue #1, reviewed): the stake deadline runs from the block anchoring the draw; a lapse the
  seats cause (unstaked, no offer left) opens the next tier within the escalation window from it, one
  the carrier causes opens nothing; non-stakers are never drawn again for the case; the pool decides
  lapses by the replay. Regtest `CAPTURE=1 LAPSE=1 AUDIT=1`: all checks pass, the pool attests tier 2.

## Public signet, 2026-11-24/25 (INDEX_FROM 332329): full case, all checks pass

First complete case on public signet after the issue #1 fix. Tablet 17/0, phone 13/0, PC r3 10/0,
arb1 14/0, hostile 5/0, audit `AUDIT_PASS` (2 tiers, archive record equals links record).
Log: `results/public_signet_2026-11-25.txt`.

- Alert to a funded, fully pre-signed incident: 840 s. Location sealed 4.2 s after accepting.
- Attending vote unsettled; tier 1 (3 of 3 offers) drawn, every seat staked in time (the Nov 24
  failure), paid 3 × 330 sats; two corrupt seats outvoted arb1 2 to 1 (D,I).
- No party appealed; arb1 bought the dissenter's re-roll; tier 2 (7 seats) overturned, 6 of 7 for I,D.
- Pool attested 3 of 4; the lying member's three shares for a different outcome caught as evidence;
  all three pots settled on chain.
- Forfeitures by pre-signed scripts and pool co-signature: each corrupt tier-1 seat 4 × fee, the
  tier-2 dissenter 4 × fee, the losing attendee one tier-1 panel fee; seizure output (5,278 sats)
  distributed to the vindicated dissenter after the archivist's own replay. Review draw (40%, split
  final panel) passed over; units released.
- Time from escalation: tier 1 verdict 9,694 s, tier 2 verdict 10,967 s after its escalation; the
  whole case about 12 hours (signet blocks, `COMMIT_BLOCKS=8`, `DISPUTE_BLOCKS=8`).

## Caller cold start over Tor, phone (Redmi, mobile data), 2026-11-25 (prototype issue #2)

`scripts/cold_start.sh`, 10 trials per mode, against the PC's onion (archive port), C Tor in Termux.
T1 = Tor bootstrapped; T4 = the PC's first byte back, both from T0 (alert pressed). (T3 as first
written measured only the local SOCKS connect and equals T1; T4 - T1 is the onion connection plus reply.)

| Mode | T1 median | T4 median | T4 worst | Failures |
| --- | --- | --- | --- | --- |
| restart (Tor killed, cache kept) | 4.2 s | 9.8 s | 15.8 s | 0/10 |
| wipe (cache deleted) | 10.2 s | 14.7 s | 17.2 s (of 9) | 1/10 never bootstrapped within 3 min |
| warm, Wi-Fi flicked off and on quickly during the 5 s pause | 0 | 2.6 s | 27.0 s | 2/10 refused at once (no network at that instant) |

- Once Tor is up, reaching the Core takes 4-11 s from cold and 1-5 s warm.
- A wiped cache costs about 6 s more and, once in ten, fails to bootstrap at all: an app must never
  lose Tor's state.
- The warm trials toggled Wi-Fi quickly, so some ran while the phone had no network or was still
  reconnecting: a rough picture, not a clean handoff. Then a request either fails at once (retry
  immediately) or waits out the reconnection (27 s once). The app's health probe must act on Android's
  network-change callback, not on a timeout. A clean handoff (one switch, then a trial once the new
  network is up) is still to be measured.

## In-process Tor (Arti, `bitaid-tor`) on the same phone, 2026-11-26 (M4 step 2)

`scripts/arti_check.sh 10` against the same onion. Arti restarted for every trial, its state and
cache kept (the restart mode above). T1 = Arti bootstrapped; T4 = the archive's first byte through
the authenticated listener, both measured from the start. The network type was not recorded.

| Build | T1 median | T4 median | T4 worst | Failures |
| --- | --- | --- | --- | --- |
| first, relay never flushed (bug) | 1.8 s | none | none | 10/10: stream opened in 11.3 s, request never left |
| flush fixed, no retry | 1.8 s | 6.0 s | 66.1 s | 3/10 gave up in 3-4 s |
| flush and retry (`ef4e942`) | 1.8 s | 9.2 s | 21.2 s | 0/10 |

- Arti bootstraps from its kept state in under 2 s; C Tor took 4.2 s.
- The three quick failures were all the same. Each of the six descriptor fetches was cut by Arti's
  learned circuit-build timeout ("circuit took too long to build"), and Arti gave up within 3-4 s;
  the next connection usually worked. The listener now retries within its 180 s bound, waiting
  0.5 s at first and doubling up to 8 s. It does not retry an error another attempt cannot fix:
  a wrong target, wrong client auth, or a shutdown.
- The listener refused a client without the secret in all 30 trials.
- With the retry, reaching the Core from a cold app takes about the same as C Tor (median 9.2 s
  against 9.8 s), worst 21 s.

## The Android app, end to end, 2026-11-26 (M4)

APK `628ea73`, built by the GitHub workflow, on the Redmi. The PC ran `PC_20_APP_RUN.bat`
(`APP=1 CHAIN=signet BLOCK=20`: a custom signet with a block every 20 s, the whole oracle pool, the
archivist and three arbitrators, no responder of its own) and then `PC_21_APP_ALERT.bat`, a caller at
the position the app was set to.

- The app's responder: in-process Arti, its link to the PC's Core over Tor, its bond posted, then
  listening. Wi-Fi was switched off and on while it listened; it stayed on duty.
- The alert came up as a notification. Albert accepted it in the app, and the **acceptance reached
  the caller 7.57 s after the alert**. The verified location opened in Maps.
- **The caller passed all 11 checks, 0 failed:** the pool found and checked; registration; the app's
  acceptance with its bond checked on chain; the pre-signed set complete across the PC and the phone
  (8 payouts and 3 refunds, 2 signers); the FROST co-signature (3 of 4); the incident transaction;
  the evidence pinned; the deposit returned, the reward paid and the bounty split, all three settled
  on chain.
- Found on the way and fixed:
  - the pool name the app was not given;
  - an empty log, because the node's progress went to stderr;
  - "on duty" shown before the node listened;
  - the responder's 10-minute exit and a new bond on each relaunch (fix in the app pending).

## The app's location after accepting: 226 s → 0.6 s (2026-11-27)

The same end-to-end test (`PC_20_APP_RUN.bat`, then `PC_21_APP_ALERT.bat`) was run four times on the Redmi. The exact location always reached the phone's link about 0.6 s after accepting; what changed between runs was when the node read it:

| APK | Location read after accepting | Pre-signed set | Cause found and fixed |
| --- | --- | --- | --- |
| `628ea73` (26 Nov) | 228.8 s | 90.9 s | the node's progress was invisible on Android (`say!`) |
| `5b45d46` | 226.4 s | 110.5 s | a tick (chain refresh over Tor, 12–24 s) after every message: `drain-first` |
| `3fb9c44` | 105.8 s | 1.23 s | one 87 s tick on the message thread: `chain-follower` |
| `af254ad` | **0.6 s** (the app: 2.1 s from the tap) | **1.20 s** | — |

The fix (`chain-follower`): in an app the chain is read by a thread of its own every 2 s, without holding a lock across a call to the chain node, and the archives are asked at most once a minute. On a phone each chain call crosses Tor, so the message thread must never wait on one. The local suites did not show any of this: there a chain call takes milliseconds.

The last run passed all 9 checks on the phone (the shares, 900,000 sats, arrived at its payout address). One `no message read for 34.1 s` remained, after the evidence step, while the role was busy; it does not touch the response.
