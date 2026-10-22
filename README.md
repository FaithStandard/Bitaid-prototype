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
| M2 | Oracle node: FROST key generation, nonce batches, attestation, ROAST co-signing across machines | **in progress** — works across processes; next: across machines |
| M3 | Node daemon: caller, responder and archivist flows; messages over Nostr; evidence on Blossom | |
| M4 | Minimal Android app over the same core | |
| M5 | Testnet pilot with independent operators, Tor, attack scripts | |
| M6 | Review package: frozen spec, test vectors, threat model, external review | |

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

## Licence

Apache License 2.0 (see `LICENSE`). Every contributor grants a patent licence for their contribution, and anyone who sues claiming the code infringes a patent loses that licence. The licence grants no rights to the Bitaid name.
