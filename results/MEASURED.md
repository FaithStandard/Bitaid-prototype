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
