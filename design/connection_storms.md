# Open design note: connection storms before a stake is proven

Status: gap identified 2026-11-20, not designed or built. To be designed.

## The gap

A Core opens every incoming link with a challenge; the peer must prove a stake on chain (an unspent
output committing its link key) before it is sent anything. That prices every identity once it is
connected. It does not price the moment before: a stranger that has not yet shown a stake.

What a stranger can already do (and not do) before its proof:

- it receives nothing, and what it sends is dropped;
- after 10 s without a proof its slot can go to the next newcomer;
- it can never push out a link that has proved its stake, not even one that only listens.

So a storm cannot cut off peers that are already connected. What it can still do:

- keep the Core's free incoming slots (64) filled with unproven strangers, recycling every 10 s;
- make the Core pay for every attempt: handshakes, challenges, and over Tor the onion service's
  circuit work for each connection, the most expensive part.

The cost falls on honest nodes connecting during the storm: a new phone joining, or a responder whose
link dropped and is reconnecting (both devices dropped and rejoined links in the 2026-11-19 runs). In
an emergency, being locked out for the length of an attack is a real cost, and no stake can prevent
it, because no stake has been shown yet.

## Proposed direction

Proof of work at the connection attempt, adaptive, only under load. Not per message: the honest
sender is often a phone on battery in an emergency while an attacker can rent hardware, so per-message
work handicaps the weakest honest device most and adds latency when it matters.

Tor already offers this for onion services (since 0.4.8): a proof-of-work defense at the introduction
step, before the connection reaches the node's program. Off until the service is under load; then
clients solve a small puzzle, and those that did more work are served first. One line in the Core's
torrc: `HiddenServicePoWDefensesEnabled 1`. No protocol change.

Resulting layers:

1. Tor's adaptive puzzle on connection attempts, under attack only.
2. The coin stake per identity once connected.
3. Cut and ban for abuse, which makes an abuser start over at both layers.

## Questions for the design

- Is Tor's defense enough, or should the Core's own handshake also carry a puzzle (for Cores reached
  outside Tor, or for clients whose Tor lacks the feature)?
- Effort parameters and how a phone on battery fares under an attack (measure).
- Whether the 64-slot cap and the 10 s proof window should adapt under load too.

## Related: the size of the link stake

The specification's figures (20,000 sats for a link that receives, 1,000,000 for a relaying Core)
may be more than spam deterrence needs, and any fixed number of sats drifts with bitcoin's price over
decades. Not indexed to dollars (that needs a price oracle, a trusted party). Options:

- each Core sets its own price: the specification gives a default, a Core that asks too much gets no
  peers, one that asks too little gets spammed and raises it; the protocol fixes only the floor (a
  coin worth spending, a chain fact);
- or a default tied to the fee market: a multiple of what it costs to create and spend a coin at
  recent fee rates, since the cost of minting identities is what deters a swarm.

Most users already hold a protocol output (a caller's escrow, a responder's or arbitrator's bond)
that counts as their stake, so the link stake mostly falls on strangers and observers.
