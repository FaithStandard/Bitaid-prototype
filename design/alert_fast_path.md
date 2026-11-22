# Design note: the emergency path, fast and never blocked

Status: direction agreed 2026-11-21, not designed or built beyond the first item.

The emergency path is: alert, acceptance, exact location. In every public run so far the first responder
accepted 2 to 6 seconds after the alert. What comes after it (signing the payout set, the pool co-signing
the incident: 27 to 55 minutes in public runs) settles the money and must never hold up the people.
Responders set out on acceptance and location; the money settles behind them.

## 1. Handled on arrival (done for the location)

Alerts, acceptances and the location are handled the moment they arrive, whatever else the node is doing,
never queued behind bookkeeping. In the 2026-11-20 run the tablet read its location 15 minutes late: it had
arrived in seconds, but the responder was confirming the roster with the pool. Fixed: the node notes the
sealed location on arrival. A real app has a dedicated listener for the emergency path that shows the alert
and the address at once, apart from the signing and settlement work.

## 2. Several links at all times

An alert reaches responders over links that already exist; nobody connects during the emergency. Callers and
responders keep links to two or three Cores, not one (the tests used one), so an alert never depends on
opening a connection at the worst moment, and one Core going down silences no one.

## 3. A funded alert proves its own stake

A caller's escrowed offer already counts as its link stake. A Core under a connection storm can let a link
prove itself with the alert's own funded offer in the same message, so a caller whose links are down is not
held behind a separate handshake. A free, unfunded alert stays impossible: the alert carries the payment, and
a free alert is what a spammer would send. (The emergency-number analogy: a funded caller always gets through.)
See also design/connection_storms.md.

Review note (2026-11-22): the alert-as-proof must sign the Core's fresh challenge with the offer's
scoped key in the same frame (no replay of an alert seen elsewhere), and unproven alert handshakes need
their own rate limit, since each costs the Core a chain lookup.

## 4. Priority lanes in the relay

A Core forwards in arrival order. Alerts, acceptances and locations should go ahead of bulk traffic (evidence
uploads, signing rounds, checkpoints) on every link. Matters most under load.

## 5. Auto-accept rules (optional, the responder's)

A responder's preferences decide acceptance with no tap: an on-duty switch; the cells or distance covered; the
minimum reward and bounty; optionally a minimum caller deposit. An alert inside them is accepted and the
location shown at once. Off by default: accepting puts the bond at stake for a no-show (the fault
forfeitures), so auto-dispatch is for people actually on duty. The prototype's responder already accepts
automatically once an alert passes its checks.

## Questions for the design

- How the dedicated listener and the settlement work share a phone's battery and network.
- How many Cores a phone should hold links to, against the stake each link needs.
- The exact form of an alert that doubles as a link's proof, and its replay protection.
