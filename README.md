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
| M2 | Oracle node: FROST key generation, nonce batches, attestation, ROAST co-signing across machines | next |
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

### Found while building

* **Event ordering within a block height** (§7.2). The Specification orders events that end something
  before events that start or rely on it, but not starts before reliances: an acceptance and the alert
  it accepts, at the same height, were ordered by hash, so the acceptance could be dropped. `eventlog`
  orders by kind in dependency order (endings, postings, alerts, acceptances and seats, commitments,
  reveals); the Specification is updated to match.

## Licence

Apache License 2.0 (see `LICENSE`). Every contributor grants a patent licence for their contribution, and anyone who sues claiming the code infringes a patent loses that licence. The licence grants no rights to the Bitaid name.
