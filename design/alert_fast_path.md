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

## 6. Burst relay of the emergency path (Albert, 2026-11-23)

Measured on Nov 23: the location reached the PC's responder in 4.8 s and the tablet in 55.9 s (whether
on the tablet's link or in its node is being measured). Still faster than a dispatcher's call, but
the tail matters. The idea: the first Cores holding an alert or a location push it harder than
ordinary gossip, past their usual links.

What holds up:
- **Only for what proves itself.** A Core enters burst mode only for an alert whose escrowed offer it
  has checked on chain, and for a location signed by that alert's caller. A fake emergency cannot
  trigger it, so the burst cannot be turned into an amplifier against the network.
- **Warm links, not new ones.** A new Tor circuit to an onion the Core has not reached before takes 5
  to 30 s, plus the stake proof, about the delay being fought. So each Core keeps a few standby links
  to other Cores open and idle at all times (cheap), and the burst goes out on every regular and
  standby link at once, ahead of bulk traffic (§4). New links are opened only to refill the standby
  set afterwards.
- **Several paths to the responder.** A location is sealed to one responder and is useful only on a
  link it holds; a wider burst helps only because that responder keeps links to two or three Cores
  (§2). Breadth multiplies the paths to those Cores; the responder's own links decide the last hop.

Notes:
- Messages are already flooded on every link of a Core; what the burst adds is the standby links, the
  priority, and duplicates sent on purpose over independent paths (the first copy wins, the rest are
  dropped as already seen).
- Proof of work is not per message here: Tor's onion-service proof of work at the connection attempt,
  only under load, is in design/connection_storms.md (not built). Core-to-Core standby links are
  proven by the Cores' relay stakes, so they do not pay it.
- A second transport (I2P) for some standby links makes a Tor-wide outage survivable; optional on
  phones, for battery.

## 7. Faster paths outside Tor, weighed (2026-11-23)

Weighed and dropped:
- **A messenger lane** (Telegram, even with anonymous +888 numbers): it makes the emergency path
  depend on one company and on a token bought on its own platform, and that company sees who
  contacted whom, when and from where.
- **Phone-platform push** (Google's or Apple's): the same kind of dependency and leak, in a milder
  form (the platform learns when a Core woke a phone). Kept only as a last resort for phones that
  cannot run a foreground service; off by default.

Kept:
- **A foreground service for responders on duty** (Android keeps it running with a permanent
  notification): always linked, no third party, at the cost of battery. Off duty, the app may sleep.
- **Clear-net links, opt-in, where running Bitaid is lawful** (Albert): Cores, and devices whose
  owners choose it, also link over ordinary TLS to Cores they name, besides Tor. Every message is
  signed and the location sealed, so nothing about the content or its integrity depends on the path;
  the cost is only that a named Core learns the device's IP address. Cores are public infrastructure
  like Bitcoin nodes, so Core-to-Core links can be clear-net by default where lawful; for callers and
  responders it is their choice. Each message goes on every path at once and the first copy wins, so
  Tor still delivers if the clear net is blocked. Tor stays the default everywhere.

Before building it (review, 2026-11-23, checked against the code):
- **A transport of its own.** Gossip links are plain TCP today (`gossip.rs`); over Tor the onion
  service encrypts and authenticates them, and Tor's onion proof of work is the storm defense
  (design/connection_storms.md). On the clear net that would expose the stake handshake, cell tags,
  case ids and keys to any observer. Clear-net links need Noise (IK or XX, the Core's key known in
  advance) or TLS, and their own handshake puzzle under load.
- **The caller's cold start.** A caller's phone may sit asleep for months; at the alert, starting
  Tor and building a circuit can take 15 to 30 s, a delay none of the runs measured (the caller
  there was already linked). An opt-in clear-net link to the caller's own Core or its insurer's is
  worth more there than for a responder already on duty. To measure: an alert from a cold start.
- **Reliability, not privacy.** Sending on both paths means the named Core, and any observer of the
  clear-net hop, sees the IP; Tor beside it is only a fallback against blocking or outage. The app
  must never show "Tor on" as if the address were hidden while the clear-net path is on.
- I2P stays off phones (battery); between Cores it is the backup if Tor as a whole fails (§6).

## Questions for the design## Questions for the design

- How the dedicated listener and the settlement work share a phone's battery and network.
- How many Cores a phone should hold links to, against the stake each link needs.
- The exact form of an alert that doubles as a link's proof, and its replay protection.
