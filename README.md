# Bitaid prototype

Working code for the [Bitaid protocol](https://github.com/FaithStandard/BitAid-whitepaper): a
Bitcoin-native, trust-minimised emergency-response and arbitration protocol. The whitepaper,
Specification and Foundations describe the design; this repository is where it is built, tested
and handed to reviewers. **Prototype only: it runs on regtest, signet and Liquid testnet and must
never hold real funds.**

## Milestones

| | Milestone | Status |
|---|---|---|
| M1 | `bitaid-core`: outputs, endings, pre-signed adaptor payouts, oracle attestation, event-log replay | **done** — see below |
| M2 | Oracle node: FROST key generation, nonce batches, attestation, ROAST co-signing across machines | **done** — across two machines on a LAN, see below |
| M3 | Node daemon: caller, responder, archivist and oracle-pool roles; Core-to-Core gossip over Tor (the Specification's transport); evidence on Blossom | **done** — a full disputed case and the staged review on Bitcoin's public signet over Tor across three devices, a hostile peer, the escrows on Liquid testnet; see below |
| M4 | Minimal Android app over the same core | |
| M5 | Testnet pilot with independent operators, Tor, attack scripts | |
| M6 | Review package: frozen spec, test vectors, threat model, external review | |

The protocol's **economic simulations** (Specification Appendix B.10) are in [`sim/`](sim/): each
experiment writes the rules as code and runs them against honest, lazy, random, colluding and
staging agents over thousands of cases; `sh sim/run_all.sh` reproduces every published number
(Python 3, standard library, seeded).

## M1 — `crates/bitaid-core`

| Module | Specification |
|---|---|
| `outputs`, `scripts`, `tree` | Funding, bond and insurer-buffer outputs (Appendix B.1): no key path, two keys on every leaf that can move funds early, single-key fallback after a height |
| `endings`, `payouts` | Every ending of each pot (§11.11): 7 / 253 / 127 = 387 at five signing responders; deterministic amounts (remainder and dust to the largest share) |
| `musig`, `presign` | Incident outputs as MuSig2 (BIP327) key-path outputs; the whole set pre-signed as adaptor signatures to the oracle's attestation points; one refund per pot (§3.2) |
| `oracle` | Attestation points `S = R + e·X` and BIP340 attestations; a nonce never signs two outcomes (§3.3, B.3). Single key in M1; the pool's FROST key in M2 |
| `txbuild` | Version-3 zero-fee transactions with pay-to-anchor outputs; BIP341/342 digests |
| `eventlog` | Deterministic replay of the anchored event log (§7.2) |

Built on [`rust-bitcoin`](https://github.com/rust-bitcoin/rust-bitcoin) and
[`musig2`](https://github.com/conduition/musig2) (BIP327 with adaptor signatures).

### Tests

```sh
cargo test --release
```

* `tests/vectors.rs` — **cross-implementation check**: from the same secrets and nonces, the Rust core
  reproduces byte for byte what the Python reference (`tools/btc.py`, used for every regtest, signet and
  Liquid test so far) computes: output scripts, control blocks, transactions, digests, attestation
  points, MuSig2 adaptor partial signatures and completed signatures. Regenerate with
  `python3 tools/make_vectors.py`.
* `tests/set.rs` — the full set for six signers: 387 payouts + 3 refunds signed with every partial
  verified (about 1.3 s), the attested payout completes, every other ending's payout does not, and the
  oracle refuses a second outcome under one nonce.
* `tests/eventlog.rs` — the same events in 2,000 random arrival orders give the same state digest;
  same-height races resolve the safe way.
* `src/*` unit tests — published counts, label formats, every ending paying the whole pot.

```sh
# against a regtest bitcoind (Bitcoin Core 28+ for package relay) with a funded wallet "w"
BITAID_CLI="bitcoin-cli -regtest -rpcuser=u -rpcpassword=p -rpcport=18443" \
  cargo run --release --example regtest_incident
```

`examples/regtest_incident.rs` runs a whole incident on Bitcoin Core 31.1 regtest (15/15): funding
output; the scoped key alone refused by the script check; the incident transaction with the oracle's
co-signature confirmed as a zero-fee package; the 387-payout set; the refund refused before its
height; three payouts completed by attestations and confirmed; the refund path when the oracle never
attests; a bond the cold key alone cannot move and whose pre-signed forfeiture completes with the
oracle's co-signature; the funding fallback refused before its height and accepted after.

`examples/regtest_two_devices.rs` (8/8): scoped keys held on several devices (`scripts::KeyPolicy`,
Specification B.4). An arbitrator's 2-of-2 bond (node and phone): forfeiture refused with either device
alone or without the oracle, completed with both and the oracle. A caller's 2-of-3 funding output
(phone, node, delegate): with the phone lost, node + delegate + oracle accept the incident; one device
is refused.

`examples/regtest_seizure.rs` (8/8): where seized money goes (Specification §12, B.1). A pre-signed
bond forfeiture pays restitution directly and the rest to the case's seizure output; only the oracle
pool together with a majority of the case's archivists can distribute it (the pool alone, archivists
alone, or too few archivists are refused); the harmed party's key alone takes it after the relative
timelock.

### Found while building

* **Event ordering within a block height** (§7.2). The Specification orders events that end something
  before events that start or rely on it, but not starts before reliances: an acceptance and the alert
  it accepts, at the same height, were ordered by hash, so the acceptance could be dropped. `eventlog`
  orders by kind in dependency order (endings, postings, alerts, acceptances and seats, commitments,
  reveals); the Specification is updated to match.
* **Seized money with no destination** (§12). Pre-signed forfeitures can only pay keys known when the
  exposure begins, so reviewers, panels, dissenters and the old "subsidy pool" could not be paid on
  chain. The seizure output (`outputs::seizure`) fixes it; the Specification now describes it.
* **Liquid's one-year relative timelock** does not fit BIP68's 65,535-block limit at one-minute blocks;
  it must be time-based (`scripts::after_relative` takes a raw BIP68 value).

## M2 — `crates/bitaid-oracle`

The oracle pool of Specification §3.3 and Appendix B.3.

| Module | What it does |
|---|---|
| `keygen` | Pool key by distributed key generation (Zcash Foundation FROST DKG: verifiable shares, proofs of knowledge), BIP86-tweaked |
| `nonces` | Batches of one-time nonces generated jointly in advance (Feldman-verified); a dealer whose share fails is disqualified |
| `attest` | Public attestation shares `s_i = k_{j,i} + e·x_i`, verifiable by anyone against the member's public shares; any t combine to the scalar that completes one pre-signed payout; a nonce never attests two outcomes |
| `cosign` | FROST co-signatures for the scoped-key leaves, with a ROAST-style coordinator that replaces members who stall |
| `net` + binaries | `bitaid-hub` (relay, stand-in for Nostr in M3), `bitaid-oracle-node` (one member per process; `--stall`, `--liar` for tests), `bitaid-oracle-client` (coordinator and requester); shares to one member are encrypted to it (ECDH + ChaCha20-Poly1305) |

Tests:

* `tests/pool.rs` — 7 members, threshold 4: one DKG, a nonce batch with a cheating dealer disqualified,
  attestation with three members offline completing a real pre-signed payout from `bitaid-core` and no
  other, a member caught attesting a different outcome, a forged share rejected, co-signing with two
  offline and one stalling (replaced in a second session), and nothing signed below threshold.
* `examples/regtest_pool.rs` — the same pool on Bitcoin Core regtest: acceptance co-signed and confirmed,
  three payouts completed by four members' attestation shares and confirmed (7/7).
* `scripts/pool_local.sh` — 7 members as **separate processes** over the relay (member 5 stalls,
  member 6 lies, members 1 and 2 go offline after setup); with `BITAID_CLI` set, a whole incident on
  regtest with the networked pool as its oracle (6/6): acceptance co-signed over the network in two
  sessions (the staller replaced after a 3 s timeout), each payout attested over the network in 2–3 ms
  and confirmed, the liar's share recognised as signed evidence against it. At 21 members, threshold 11,
  50 nonces per batch: setup (DKG + batch) 4 s, co-signing 18 ms without a staller, attestation 14 ms.
* **Two machines** (`scripts/lan_build.sh`, `lan_pi.sh`, `lan_phone.sh`): members 1–4 and the relay on
  a Raspberry Pi (32-bit ARM), members 5–7 on an Android phone in Termux, over a home network. Member 1
  goes offline after setup, member 4 stalls, member 6 lies. Result 3/3 (`results/lan_2026-10-24.txt`):
  all seven agree the pool key and qualified dealers, 20 nonces ready in 0.6 s; two co-signing sessions
  in 3.2 s (the staller replaced); attestation in 110 ms, member 6's share valid for a different outcome
  and kept as signed evidence. Both devices build natively (Pi 10 min, phone 15 min; Termux needs
  `CARGO_BUILD_JOBS=1`, now the default). A firewall on the relay machine must allow port 7400 from the LAN.

## M3 — `crates/bitaid-node`

One daemon, four roles (`--role caller|responder|oracle|archivist`), exchanging the messages of
Specification B.2 over Nostr relays, with evidence on Blossom-compatible servers.

| Module | What it does |
|---|---|
| `gossip` | The Specification's transport (§7): Cores keep direct links, forward each message they have not seen to every other link, replay their recent log to a peer that connects late; links run over Tor onion services (SOCKS5 to each device's own Tor, onion names resolved by Tor), so no router is opened and no peer learns another's IP. A phone app is a thin client with one outbound link to its Core. Not yet: the DHT (peers come from a bootstrap list) and geofenced forwarding |
| `nostr`, `relay` | Signed event container (also the Blossom upload authorisation); the Nostr-relay transport is kept only as the stand-in of the earlier tests | NIP-01 events signed with the identity key (BIP340); a client over several relays (ws/wss) deduplicating by id; a minimal in-memory relay (`bitaid-relay`) that checks every signature and forwards ephemeral kinds without storing them |
| `wire` | The B.2 messages as signed CBOR (`tagged_hash("Bitaid/msg", body)`), carried in events signed by the same key; case traffic encrypted with a case key sealed to each signer (ECDH + ChaCha20-Poly1305) |
| `case` | Every party rebuilds the incident from the alert (which carries the signed registration) and the roster, and checks the funding output on chain |
| `presign` (core) | `round1`/`round2`/`finish`: the whole set signed in two rounds across machines, every partial verified, a bad signer named |
| `blossom` | BUD-01/02 server and client: uploads only with a Nostr authorisation naming the blob and a live case, from a party to it; range requests; slice roots |
| `pool` | The M2 oracle pool behind the node: FROST key generation and a Feldman-verified nonce batch over the relays (stored events, so late nodes check the setup themselves); nonce indices reserved by t members per case; ROAST-style FROST co-signing of the incident, each member checking the transaction first; members attest from the ballots on their own and anyone combines t public shares |
| `settle` | Deemed consent from blind ballots (commit, reveal): class per seat by 80%, the 70/30 split into buckets, the reward following the bounty; misuse or no supermajority escalates |
| `arb` | Arbitration (§10): panel sizes and fees per tier, the seat draw from a block hash, two-thirds verdicts, the asymmetric penalty, the tier commitment; the daemon adds seat offers with bonds checked on chain, the case key sealed to the seats, commit-reveal verdicts, appeals by any party, and hung tiers that decide nothing. Penalties are taken from bonds: each seat pre-signs its forfeitures (2× to 4× the fee in half steps) into the case's seizure output when it takes the seat; after the final ruling the pool co-signs only the ones its replay of the log calls for (`Replay`), and the pool and the case's archivists co-sign the distribution of §12 (vindicated dissenters, the appeal subsidy, the excess). Each seat's penalties come from a seat stake of its own (4× the fee), so seats held at once never pre-sign the same coin. A dissenting arbitrator may buy the re-roll itself on a party's terms (`--challenge`): it opens the next tier and pays its fees, refunded as the appeal subsidy only if the larger panel agrees. An escalation never seated lapses. A seat with no committed vote by the template's deadline is forfeit: its pre-signed seat forfeiture (signed with its stake's penalties) refunds the fee, the pool co-signing only once its own record shows the deadline passed, and a replacement is drawn from the offers left (`Reseated`; test arbitrators: `--no-vote`). Not yet: momentum, the reveal deadline, review sampling |
| `chain` | Bitcoin Core JSON-RPC over HTTP, so a phone can use a node elsewhere; zero-fee version-3 packages with a fee-paying child |

Runs:

* `scripts/m3_local.sh` — all roles as separate processes on one machine (28/28, `results/m3_local_2026-10-24.txt`).
* Three devices (`scripts/m3_pi.sh`, `m3_device.sh`, `m3_chain.sh`, `tcp_forward.py`): caller on an
  Android phone that also hosts the regtest node; responder and archivist on an Android tablet; relay,
  oracle, archivist, an honest and a cheating responder on a Raspberry Pi 4. 27/28
  (`results/m3_devices_2026-10-25.txt`): the cheater dropped and the set re-signed, incident at zero fee,
  three payouts confirmed, 630,000 / 270,000 sats to the intervener and the documenter. The failure: the
  phone could not reach the tablet's archivist (router isolates Wi-Fi clients). Needs Bitcoin Core 29+ (zero-value anchors, ephemeral dust).
* With the oracle pool (4 members, threshold 3) split across the Pi (two, one stalling), the tablet and the
  phone (one lying): phone 13/13, tablet 9/9 (`results/m3_pool_devices_2026-10-25.txt`). The pool co-signed the
  incident in 0.41 s; the lying member's shares were caught by every party and three honest shares settled the case.
  Local run with the pool: 33/33.
* **Over the Internet, over Tor** (`scripts/net_pc.sh`, `net_device.sh`, `tor_up.sh`, `wsl_setup.sh`): a Windows PC
  (WSL1) at home with the chain, the gossip Core, two pool members, the archivist and two responders; a phone on its
  own mobile data (caller, lying pool member); a tablet on another phone's data (responder, pool member). Every link
  an onion service. 32/33 (`results/m3_tor_internet_2026-10-26.txt`): stalling co-signer replaced, cheater dropped,
  liar caught, three payouts confirmed; alert to funded incident 67 s, to settled 148 s. The failure: the PC's own
  responder could not reach the PC's archive through its onion address.
* **Arbitration over Tor** (same scripts; nine arbitrators on the PC, two corrupt): the liar on the tablet escalates;
  tier 1 (3 drawn from a block) was captured 2-1 by the corrupt pair; the honest intervener appealed and tier 2 (7 seats)
  reversed it 7-0; the pool attested the final verdict. 43/43 (`results/m3_arb_tor_2026-10-26.txt`). Local: `scripts/m3_arb_local.sh`.
* **Penalties over Tor** (`CAPTURE=1`, the default of `net_pc.sh`): the captured tier 1 reversed on appeal; arb4 and arb8
  forfeit 4x the fee from their bonds by their own pre-signed forfeitures and the pool's co-signature; the pool and the
  archivist distribute the seizure output: half to the vindicated dissenter, half refunding the appellant's re-roll fees;
  both refuse what the log does not call for. 51/51 (`results/m3_penalties_tor_2026-10-26.txt`).
* **The dissenter's re-roll** (local: `CAPTURE=1 CHALLENGE=1` and `CHALLENGE=bad sh scripts/m3_arb_local.sh`; devices: the defaults of `net_pc.sh`): no party appeals the captured tier 1; arb1, the honest dissenter, buys the re-roll and opens tier 2, which agrees with it; the wrong majority's stakes pay arb1 its vindication and its fees back. In the `bad` run a corrupt dissenter re-rolls an honest verdict and loses its fees and its stake's penalty. Over Tor on the three devices: 53/53 (`results/m3_dissent_tor_2026-10-27.txt`).
* **Missed commit deadline** (`STALL=1`, default in `net_pc.sh`; local `CAPTURE=1 CHALLENGE=1 STALL=1 sh scripts/m3_arb_local.sh`): arb9 and arb10 serve tier 2 but never vote; each one seated misses the deadline, its seat forfeiture refunds the fee to the payer and a replacement is drawn from the offers left. Over Tor: 57/57 (`results/m3_deadline_tor_2026-10-27.txt`).
* **Momentum over many cases** (`CASES=20 sh scripts/m3_multi.sh`, one machine): 13 arbitrators kept across 20 cases (honest, sloppy, corrupt, never-revealing); 878 checks, 0 failed; the never-revealing and corrupt arbitrators' momentum climbed to 5–6.5 and their penalties to the 128× cap, honest ones stayed near 0 (`results/m3_multi_2026-10-27.txt`).
* **The staged review** (§10.3; `REVIEW=1`): a sample of final verdicts is drawn and re-judged by three fresh panels in turn; a confirmed overturn seizes the wrong arbitrators' units and pays the wronged. Local regtest (`results/m3_review_local_2026-10-27.txt`, `m3_entry_local_2026-10-28.txt`, `m3_flag_local_2026-10-28.txt`, `m3_overturn_rules_local_2026-10-28.txt`); over Tor on the three devices, 78/78 (`results/m3_review2_tor_2026-10-28.txt`); the holding output with an archivist committee (`results/m3_holding_committee_2026-10-30.txt`).
* **Signet, real proof of work** (a custom signet, nodes never mine): local and over Tor, 84/0 (`results/m3_signet_tor_2026-10-29.txt`).
* **Bitcoin's public signet, over Tor** (Albert's pruned signet node; ten-minute blocks mined by others; transactions relayed by public peers). Timers stretched to fit ten-minute blocks and phones on Tor (`TIME_SCALE`); the Specification's deadlines are in blocks, which is the next step. The first runs passed every step of the case but lost the end to fee coins and slow phone co-signing (`results/m3_public_signet_2026-10-30.txt`, `-11-02.txt`, both 75/7); fixed, the fifth run was clean: a full disputed case, 71/0 (`results/m3_public_signet_2026-11-06.txt`). The staged review on the public chain, 74/0 (`results/m3_public_signet_review_2026-11-07.txt`).
* **A hostile peer** (`examples/rogue.rs`; `ROGUE=1 sh scripts/net_pc.sh` during a run, `sh scripts/net_pc.sh attack` alone): oversized and garbage lines, stale, future-dated and replayed messages, a fake block height, a flood of validly signed junk and a connection storm. During the public review run the case finished undisturbed and every node refused the fake height; alone, every attack ran: 18/0 over two rounds (`results/m3_liquid_testnet_2026-11-08.txt`). The limits are in `gossip` and `node` (line, store, seen-set, link and rate caps; envelopes more than 6 blocks ahead refused).
* **The escrows on Liquid testnet** (`tools/liquid/`, `scripts/liquid_pc.sh`; Elements in WSL, faucet coins): funding output, the FROST-co-signed incident, the pre-signed set with Liquid's explicit fee outputs, a wrong attestation rejected by the node, slices, a bond forfeiture and the timelocked fallback, 15/0 (`results/m3_liquid_testnet_2026-11-08.txt`). The daemon itself on Liquid goes with M5.
* **Protocol deadlines in blocks** (after M3): the case template's commit, reveal and dispute deadlines are block counts (`commit_blocks`, `reveal_blocks`, `dispute_blocks`; production 1,008, 144 and 288), judged by each node's chain tip. A seat's commit deadline runs from the block that confirmed its fee, and a tier's appeal window from the block that confirmed its commitment, so every member computes the same height whenever it saw the payment; a commit seen after its seat's deadline is not counted. Deemed consent and the reveal deadline run from the height at which a member saw the last ballot or commit (one block either way between members; the Specification's checkpoints, §7.2, make that height common too). Local runs make a block every 2 s on regtest beside the blocks nodes mine on demand (`BLOCK`): `results/deadlines_local_2026-11-09.txt`. On Bitcoin's public signet, with 3-block deadlines, the staged review overturned a captured verdict and seized the wrong arbitrators' units: 81 passed, 1 failed (a fee coin, fixed) (`results/m3_public_signet_blocks_2026-11-09.txt`). `TIME_SCALE` now only stretches the prototype's own waits (how long a node stays up, retries), not the protocol's deadlines.
* **Bonded links** (`gossip`, `node::link_credential`): no free tier on the transport. A Core opens every incoming link with a fresh challenge; within 30 s the peer must sign it, with the address it dialled, by a link key whose stake is an unspent, confirmed output paying at least the link stake (100,000 sats before `SAT_SCALE`) to that key alone. Until then it is sent nothing and what it sends is dropped. A key cut for flooding, junk or oversized messages is banned for an hour; one key holds at most two links; a stranger can only take the slot of another stranger still without a proof after 10 s, never a staked peer's. Each node locks its stake once and reuses it while unspent (`BITAID_LINK_DIR`, default `~/.bitaid`). The stake is a fidelity bond for now: costly to multiply, not yet forfeitable (that needs the pool-co-signed path the role bonds have). The hostile peer tests the handshake too: no stake, a wrong signature, another key's stake, a proof signed for another Core, a banned key returning, one key opening eight links.

## Licence

Apache License 2.0 (see `LICENSE`). Every contributor grants a patent licence for their contribution, and anyone who sues claiming the code infringes a patent loses that licence. The licence grants no rights to the Bitaid name.
