"""Experiment 6 — staged incidents and the one-bond fraud history (Specification §10.3, §11.3 Q5, §16 item 10).

A ring (a caller plus k responders, all bonded) stages incidents among themselves. Money the ring
moves from its own caller to its own responders nets to zero, so staging pays only where money from
OUTSIDE the ring reaches the payout: an insurer's payment-default draw (the ring's caller "cannot pay"),
a third party's top-up of the offer, or co-responder liability cover for a staged injury. phi is the
share of each offer that is outside money (1 = the whole offer drawn from an insurer layer).

Per staged case: in-case catch probability c (an honest joiner, footage that contradicts itself), else
review with probability R. A confirmed staging cascades: every case of the ring within the lookback is
reopened and confirmed with probability 0.9, and restitution of the outside money is paid from what is
seized — which is the ring's bonds and nothing more. The ring chooses how many cases n to stage
(it stops at the best n for itself), knowing the rules.

Rules compared:
  as written   each responder's bond meets the acceptance gate, 2 x the offer, and is reused case after case
  accumulate   outside money a bond has received on cases still inside the lookback counts against it in the
               gate: free stake = bond - 2 x (that outside money); the bond must be topped up to keep accepting
  draw review  bonds as written, but any case in which outside money paid out is reviewed at least 50% of the time
Money in units of one offer V.
"""
import random, json, statistics

def ring_profit(n, k=3, phi=1.0, R=0.05, c=0.1, rule='as written', lookback=10**9, sims=4000, seed=0, fee=0.02, hold_drawn=False, floor=0.5):
    rng = random.Random(seed + n)
    tot = []
    for _ in range(sims):
        received = []                  # outside money per case, in order
        caught_at = None
        for i in range(n):
            received.append(phi)
            Rr = max(R, floor) if rule == 'draw review' and phi > 0 else R
            if rng.random() < c or rng.random() < Rr: caught_at = i; break
        if hold_drawn and caught_at is not None: received[caught_at] = 0.0   # a drawn case's outside money waits for the review
        gain = sum(received) - fee * len(received)
        if rule != 'accumulate': bonds = 2.0 * k          # k responders x 2V; the caller's deposit is small
        else:                                             # the ring had to top up to keep accepting
            peak = 0.0
            for j in range(len(received)):
                window = sum(received[max(0, j - lookback + 1): j + 1])
                peak = max(peak, 2.0 + 2.0 * window)     # per-responder stake needed at case j (split k ways, each needs the share)
            bonds = 2.0 * (k - 1) + peak                  # base gates, plus the accumulated cover on the bonds that received the money
        if caught_at is None: loss = 0.0
        else:
            reopened = [r for idx, r in enumerate(received) if idx >= caught_at - lookback + 1]
            owed = sum(r for r in reopened if rng.random() < 0.9)
            loss = bonds                                   # bannable: every ring bond is seized whole; restitution comes out of it
            gain -= 0                                      # restitution is paid from the seizure, not on top of it
        tot.append(gain - loss)
    return statistics.mean(tot)

def best(**kw):
    rs = [(n, ring_profit(n, **kw)) for n in [1, 2, 3, 5, 8, 12, 20, 30, 50, 80, 120]]
    n, p = max(rs, key=lambda x: x[1])
    return n, round(p, 2)

out = {}
print('ring best n and expected profit (offers), k=3 responders')
for rule, lb in [('as written', 10**9), ('accumulate', 10**9), ('draw review', 10**9)]:
    for R in [0.05, 0.10, 0.20, 0.40]:
        for phi in [0.1, 0.25, 0.5, 1.0]:
            for c in [0.0]:
                key = f'{rule}{"" if lb > 10**6 else f" lookback {lb}"} | R {R} | outside share {phi} | in-case catch {c}'
                out[key] = best(phi=phi, R=R, c=c, rule=rule, lookback=lb)
                print(f'  {key:75s} n*={out[key][0]:4d}  profit {out[key][1]:7.2f}')

print('\nlone-responder ring (k=1), outside share 1, R 0.05')
for label, kw in [('as written', dict(rule='as written')), ('draw review 50%', dict(rule='draw review')),
                  ('draw review 50%, drawn case held', dict(rule='draw review', hold_drawn=True)),
                  ('draw review 33%, drawn case held', dict(rule='draw review', hold_drawn=True, floor=1/3)),
                  ('draw review 25%, drawn case held', dict(rule='draw review', hold_drawn=True, floor=0.25))]:
    out['k=1 | ' + label] = best(k=1, phi=1.0, R=0.05, c=0.0, **kw); print(f'  {label:40s} n*={out["k=1 | " + label][0]:4d}  profit {out["k=1 | " + label][1]:7.2f}')

# what accumulation costs an honest responder: stake tied up by outside money inside the lookback
honest = {}
for per_year, outside_share, lookback_days in [(20, 0.1, 180), (50, 0.25, 180), (100, 0.25, 365), (100, 1.0, 365)]:
    in_window = per_year * lookback_days / 365 * outside_share
    honest[f'{per_year} cases/yr, {int(outside_share*100)}% outside money, lookback {lookback_days} d'] = round(2 + 2 * in_window, 1)
print('\nhonest responder stake needed under "accumulate", in offers:'); [print('  ', k, v) for k, v in honest.items()]
json.dump({'ring': out, 'honest_stake': honest}, open('e6_results.json', 'w'), indent=1)
