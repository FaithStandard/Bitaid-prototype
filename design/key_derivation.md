# Design note: one seed for a user's hot keys, a branch per device

Status: proposal (2026-11-26), for review by Neon before any code. It covers M4 step 5's setup screen
and the node's key handling. The `SecretStore` hook (`bitaid_node::secrets`) does not change.

## Why

Today the node makes every hot key at random: link keys, per-case pot and seat keys, the reclaim key
lines. A lost phone loses them, including the per-case keys that the seizure output's fallback needs
(review N10). Each would also need its own backup. Bitcoin wallets solve this with one seed from which
every key is derived, so one written backup recovers everything. This note borrows that approach and
adapts it to Bitaid's device model.

## What the specification already fixes (§"Key policies", §"Operational security", §16)

- A user's **scoped key is a policy over device keys**: one device key, or k of n, each on a different
  device (phone, Core, delegate). Devices never share a key.
- The **persistent identity is the Core's keypair** (§16, "Responder identity").
- The **cold wallet key** (a hardware wallet or an offline signer) registers, tops up, withdraws and
  re-locks about once a year. Nothing an online device holds can spend alone.
- Scoped keys are **encrypted at rest** under a key held by the phone's secure hardware, which wraps
  them, and are **replaced with every re-lock**.
- Incident pot keys (MuSig2) are **fresh single-device keys for each case**.

## The scheme

**The Bitaid seed** is BIP39, 24 words, generated on the first device at setup and shown once. Two
optional protections:
- a BIP39 passphrase (the "25th word"), kept apart from the words;
- or a SLIP-39 Shamir backup (for example any 2 of 3 shares) instead of plain words, for users who
  want to survive losing one piece.

**The seed is never stored on any device.** A device keeps only its own branch, below, in its
`SecretStore` (Tink under a Keystore key on Android). The seed is entered again only to add or recover
a device.

**The cold key is not derived from this seed.** It stays in the user's own hardware wallet, whose seed
is separate. If someone steals the Bitaid seed backup, they get hot keys, which the oracle's
co-signature and the templates bound; they never get the cold key that withdraws. One stolen backup
must not give both.

**Paths** (BIP32, every level hardened). The purpose is `1111574852'` (0x42414944, "BAID"), so no
wallet that scans the standard purposes (44, 49, 84, 86) ever shows these keys; `net'` is `0'` for
mainnet and `1'` for every test chain, so test and real keys never coincide:

| Path | Key | Held by |
| --- | --- | --- |
| `m/1111574852'/net'/0'` | identity (the Core keypair) | the Core only |
| `m/1111574852'/net'/1'/d'` | **branch of device `d`** | device `d` only |
| `…/1'/d'/0'/e'` | device `d`'s scoped key for re-lock epoch `e` | device `d` |
| `…/1'/d'/1'/i'` | device `d`'s `i`-th link credential (a new one when its stake is spent) | device `d` |
| `…/1'/d'/2'` | case secret of device `d` | device `d` |

**Per-case keys** come from the case secret by a tagged hash, not by a path, because a case id is 32
bytes: `k = H_tag("Bitaid/case-key", case_secret ‖ case_id ‖ role ‖ n) mod order`, where `role` is
`pot` or `seat`, `n` counts up from 0, and a zero result moves to the next `n`. Recovering them needs
the device's case ids, which the anchored log holds, listed by the device's keys.

**MuSig2 nonces stay random** for each session (`bitaid_core::musig::nonce` does this already). With
deterministic keys, a deterministic nonce would reveal the key the second time a message was signed.

## Devices

- **First device.** It generates the seed, shows it, checks one or two words back, takes device
  index `d = 0` (or the next free one, below), stores its branch, and forgets the seed.
- **Another device.** The user enters the seed (and passphrase) once. The device reads the user's
  registered policy, picks the lowest `d` whose key is not already in it, stores that branch, and
  forgets the seed. It refuses an index whose key already appears, so two devices never hold the same
  key.
- **A lost or stolen device is retired, never restored to its index.** Its branch may be in a thief's
  hands. The replacement takes a new `d`; the old key leaves the policy at the next re-lock, or at once
  by withdrawing to a new funding output (spec, "Key policies"). To finish that device's open cases
  (the seizure fallback's per-case keys), a recovery step derives the old branch from the seed, signs
  what is needed and discards it.
- **The Core** also takes a device index for its own scoped key; it alone holds the identity path.

## What this does not protect, stated plainly

- Re-lock rotation (`e`) protects against a key exposed without the device being taken: a leaked file
  of one epoch, or a weak signature implementation. It does **not** protect against a stolen device:
  that device's branch derives all its future epochs. Device theft is handled by retiring the device,
  as above, which the policy already supports.
- A device's `SecretStore` holds its branch. Anyone who can decrypt that store (a rooted phone, a
  Keystore flaw) gets that device's hot keys; the cold key and the other devices' branches stay safe,
  because every derivation is hardened.
- Losing the seed and every device loses the hot keys. Funds still return to the cold wallet through
  the fallback leaves after their timelocks, as today.

## What changes in the prototype (after review)

- `BITAID_BRANCH`, or a `branch` entry in the store, makes the node derive its keys from the branch.
  Without it, keys stay random as today, so the suites run unchanged; a second suite run uses a
  branch.
- `link_credential(s)` derives `i` by scanning upward from 0 and taking the first key whose stake is
  unspent, or the first unused key (a gap limit, as in wallets).
- `keep_case_key` derives in place of drawing at random; the file or store copy becomes a cache.
- `keep_keys`: the scoped half is derivable; the cold half is never on a device outside the test
  chains (the prototype's reclaim stays as it is on test chains).

## Questions for review

1. ~~Does the phone need the identity key?~~ **Settled (Albert, 2026-11-26): no.** The phone signs
   with its own device key. The identity stays on the Core, where it binds the user's registered
   device keys. Anything that puts something at stake (acceptances, seats, votes, money) carries k
   device signatures under the policy (2-of-2 phone and Core for a responder, required 2-of-2 for an
   arbitrator, 2-of-3 recommended for a caller). One device alone can send only what costs nothing,
   such as an alert. The identity is not a MuSig2 2-of-2: every routine message would then need an
   interactive round with the Core, and a phone cut off from its Core could not even raise an alert.
   The spec's sentence "signed with the sender's identity key" (§"Messages") is to be read, or
   reworded, as "the identity key or a device key registered under it".
2. Is SLIP-39 worth offering in the app, or are a BIP39 passphrase and plain words enough for M4?
3. The purpose number `1111574852'`: any reason to register a BIP43 purpose instead?
