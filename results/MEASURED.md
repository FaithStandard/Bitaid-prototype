# What the prototype has measured

Facts from runs on Bitcoin's public signet, over Tor, with the caller on a phone, a responder on a tablet and
the other roles on a PC. Test coins only; amounts divided by 100; long protocol deadlines stretched 30× so
that Tor's worst delays fit (the times below are not stretched: they are what the network took). Each figure
links to the run's published log. Every node is still run by us.

## The emergency path

| What | Measured | Runs |
| --- | --- | --- |
| Alert to first responder accepted, bond checked on chain | 2.0 to 6.2 s | Nov 18, 19, 20 |
| Alert to three responders accepted | 10 to 44 s | Nov 18, 19, 20 |
| Exact location, sealed to an accepted responder, received | 1.2 s (PC responder); 0.8 to 3.2 s under simulated Tor lag after the fix below | Nov 20; local |
| Evidence, 512 KiB encrypted, pinned on the archivist | 2 to 19 s | Nov 18, 19, 20 |

## The money

| What | Measured | Runs |
| --- | --- | --- |
| Every payout the case can end in (39 payouts and 3 refunds) signed across three machines | 2 to 7 s; once 10 min with the phone as a slow signer | Nov 18, 19, 20 |
| A signer sending a bad signature caught, dropped, the set re-signed | every run | Nov 18, 19, 20 |
| Alert to a funded incident with every payout pre-signed (pool co-signature included) | 27 to 55 min | Nov 18, 19, 20 |
| All three pots settled on chain by the attested outcome | every run | Nov 18, 19, 20 |
| A pool member attesting a different outcome caught, its shares kept as evidence, honest shares still combined | every run | Nov 18, 19, 20 |

## Disputes

| What | Measured | Runs |
| --- | --- | --- |
| Tier 1 panel drawn from a block, disclosed only to the drawn | 37 to 83 min after escalating | Nov 18, 19, 20 |
| Tier 1 verdict | 99 to 134 min after escalating | Nov 18, 19, 20 |
| Tier 2 (7 seats) verdict | 93 to 135 min after escalating | Nov 18, 19, 20 |
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
- A location received late on the tablet (Nov 20) was a responder that read it late, fixed and tested
  locally; to be confirmed on the next public run.

## Logs

- [Nov 18-19](public_signet_anchored_2026-11-19.txt)
- [Nov 19](public_signet_anchored_audit_2026-11-19.txt)
- [Nov 20](public_signet_stake_location_2026-11-20.txt)
