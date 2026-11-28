# Design note: the phone as a light client of its own Core (M4, next piece)

Status: brief for implementation by Neon, review by Claude (2026-11-27). It builds the §7.2 light path
once, so it serves both the phone that follows its own Core and, later, the caller without a node.

## Why

On the phone every chain read crosses Tor (1–2 s a call). The phone drives the Core's bitcoind over
RPC: block hashes, whole blocks for the ledger, outputs, transactions, many calls per case. Moving
those reads off the message thread (`chain-follower`) brought the location from 226 s to 0.6 s. But
the phone still spends its battery, its data and its follower thread on block-by-block reading. The
spec already says who reads the chain (§7.2, "Who runs a node"): every worker role runs a full node,
and for a responder's phone that node is the user's Core. The phone should ask, the Core should
answer in one exchange, and the phone should check what it is told.

## Albert's rule, and where the line falls (agreed with Neon, 2026-11-27)

"It's more important that it's credible than confirmed 100% true, so it's fast, as long as
verification can happen afterwards and those dishonest are punished."

- **Credible first, verified after: nothing at stake yet.** Showing an alert, accepting, opening the
  location, moving. The phone acts on its Core's answer at once and checks the proof as it arrives.
  A failed check is logged as a FAIL, and the phone stops trusting that source.
- **Verified before signing: money or a bond at stake.** `sign_set` (the pre-signed payouts) and the
  pre-signed forfeitures (`Msg::Forfeits`) proceed only on answers whose proofs have checked: headers
  with valid proof of work, a Merkle path to the block, and the output's script and amount. This is
  what keeps the 2-of-2 split (phone and Core) meaningful against a compromised Core. Checking takes
  microseconds and the signing comes after the response, so it costs the emergency nothing.
- **Omission.** A Core cannot forge a confirmed transaction, but it can hide a newer block or a spend.
  Before signing, the phone compares its tip header with 2 independent sources: bonded workers
  (§7.2), or ordinary Bitcoin peers' headers once we have them. Disagreement blocks the signing and
  is logged.
- **BCAEN as a second source** for a case's records and logs: a log fetched from an archivist is
  checked against the hashes anchored on chain (§7.2, "The chain lists, the archive holds"), never
  taken on the archivist's word.

## The exchange (one wire format for §7.2)

Two messages, sent direct (tagged `p`) over the gossip link the phone already holds to its Core:

- `LightAsk { id, since_height, txids: [..], outpoints: [..], case: Option<case_id>, from_height }`.
  "Headers since `since_height`; these transactions with proofs; these outputs: spent or not, and by
  what; the records of this case from `from_height`."
- `LightAnswer { id, tip_height, tip_hash, headers: [80-byte headers since since_height], txs: [{ raw, height, block_hash, merkle_path }], outputs: [{ outpoint, unspent: bool, value, script, spent_by: Option<txid>, height }], records: [{ txid, height, merkle_path, record }], covers: [ids of everything the answer claims is the whole set] }`,
  signed with the Core's key over the question, the height and the block it stands on (§7.2: an answer
  covers the whole set it returns, the empty set included, so a later proof of something left out
  convicts the sender).

The Core builds answers from its own bitcoind (`getblockheader`, `gettxoutproof` / `getblock` for the
path, `gettxout`, `getrawtransaction`, and its ledger for records). The phone keeps the headers it
has accepted (about 4 MB a year on mainnet, much less on signet) and asks only for what is new.

## The phone side

- A `ChainSource` trait in `bitaid-node` with what the roles actually use: `height`, `utxo(op)`,
  `tx_height(txid)` / confirmations, `ledger(..)` reads, `broadcast(raw)`, plus the wallet calls that
  stay as RPC for now (funding a bond, a payout address: rare, and the wallet is the Core's).
  `Rpc` implements it directly, as today; `CoreLight` implements it by asking the Core, caching, and
  verifying.
- `BITAID_CHAIN=core` selects `CoreLight`, which the app sets. The binary and the suites keep `Rpc`
  unless a suite asks for `core`.
- `CoreLight` marks every value it holds as **credible** (answered, proof not yet checked) or
  **verified**. Time-critical readers take either. `sign_set` and `Msg::Forfeits` ask for verified
  values and the tip cross-check, and refuse otherwise, with a check line saying why.
- The follower thread stays: with `CoreLight` it sends one `LightAsk` per new tip in place of the
  block-by-block reading.

## Order of work (each step its own commit, tests first)

1. **Verification in `bitaid-core`:** header chain checks (linkage, proof of work, retarget rules per
   network; signet: the challenge as the network defines it) and Merkle path verification, using the
   `bitcoin` crate's `block::Header`, `MerkleBlock` and `PartialMerkleTree`. Unit tests with regtest
   blocks; negative tests: a wrong path, a header with too little work, a broken link.
2. **Wire:** `LightAsk` and `LightAnswer` in `wire.rs`, signed and covering the whole set; encode and
   decode tests.
3. **The Core answers:** the core role handles `LightAsk` from its own bitcoind. A test: the Core
   answers a regtest case's transactions, and the proofs verify.
4. **`ChainSource` and `CoreLight`:** the trait, `Rpc` behind it unchanged, and `CoreLight` with the
   credible/verified states, the cache and the tip cross-check.
5. **Wire it into the responder's path:** the alert check, the incident on chain, the payout
   confirmations, and the gate in front of `sign_set` and the forfeitures.
6. **A suite variant:** `m3_local` with `BITAID_CHAIN=core` for r1 (and `R1_RPC_DELAY_MS` to stand in
   for Tor). Report how many calls a case makes, and the location and set times, against plain `Rpc`.
7. **The app:** set `BITAID_CHAIN=core`, and keep an RPC URL only for the wallet calls.

## Ground rules

- `bitaid-node`'s protocol logic changes here, so every step comes to Claude for adversarial review,
  and Claude runs the regtest suites (your Windows sandbox has no bitcoind on the path) before
  anything merges. Branch `phone-light`, from `main`.
- Keep `cc` at 1.7.0 in `Cargo.lock`, and `BITAID_ONION_ONLY` intact.
- Nothing money-deciding on a node's word: if a path cannot be verified yet, it stays on `Rpc` until
  it can.
- Test chains only.
