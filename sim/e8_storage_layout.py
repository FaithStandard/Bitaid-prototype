"""Experiment 8 — BCAEN storage layout: full copies against erasure-coded shards (§16 item 18).

One case's evidence is stored by one of these layouts, each piece on a different labor-gated node, each
node in a different jurisdiction where possible:
  copies r      r full copies (as specified today: 3 base slots minimum, up to 5)
  RS(k, n)      n shards, any k rebuild it (Storj/Sia/Tahoe-style; Carbonado's container is 4-of-8)
Measured, per layout:
  storage       bytes stored per byte of evidence
  suppress      pieces an attacker must destroy or withhold to make the evidence unrecoverable
                (copies: all r; shards: n - k + 1), and the cost if each costs one bribe or one court order
  retrieval     pieces a reader must reach (copies: 1; shards: k) and the chance a retrieval succeeds at
                once when each node is online with probability a
  loss/year     chance the evidence is lost within a year when nodes leave independently (5% a month)
                and lost pieces are re-made by repair once a month (lazy repair), simulated
  repair        bytes moved per lost piece repaired (copies: one piece; shards: k pieces to rebuild one)
"""
import random, json
from math import comb

def p_at_least(k, n, a): return sum(comb(n, j) * a ** j * (1 - a) ** (n - j) for j in range(k, n + 1))
def loss_year(k, n, leave=0.05, months=12, sims=200000, seed=1):
    rng = random.Random(seed); lost = 0
    for _ in range(sims):
        alive = n
        for _m in range(months):
            alive -= sum(1 for _ in range(alive) if rng.random() < leave)
            if alive < k: lost += 1; break
            alive = n                                      # monthly repair restores every piece
    return lost / sims
def loss_year_burst(k, n, burst=0.4, sims=200000, seed=2):
    """A correlated shock: one month in which each piece's node fails with probability `burst` (an outage,
    a coordinated raid in one region), before repair can act."""
    rng = random.Random(seed)
    return sum(1 for _ in range(sims) if sum(1 for _ in range(n) if rng.random() > burst) < k) / sims

layouts = [('3 full copies', 1, 3), ('5 full copies', 1, 5), ('RS 4-of-8', 4, 8), ('RS 10-of-20', 10, 20), ('RS 10-of-30', 10, 30), ('RS 6-of-12', 6, 12)]
out = {}
print(f"{'layout':16s} {'storage':>8s} {'suppress':>9s} {'read k':>7s} {'read ok a=.9':>13s} {'a=.7':>7s} {'loss/yr':>9s} {'40% burst':>10s} {'repair':>7s}")
for name, k, n in layouts:
    row = {'storage x': round(n / k, 2), 'pieces to suppress': n - k + 1, 'pieces to read': k,
           'read succeeds, nodes 90% online': round(p_at_least(k, n, 0.9), 5), 'read succeeds, nodes 70% online': round(p_at_least(k, n, 0.7), 5),
           'loss per year, 5%/month churn, monthly repair': loss_year(k, n), 'loss in a 40% correlated burst': loss_year_burst(k, n),
           'pieces moved per repair': k}
    out[name] = row
    print(f"{name:16s} {row['storage x']:8.2f} {row['pieces to suppress']:9d} {k:7d} {row['read succeeds, nodes 90% online']:13.5f} {row['read succeeds, nodes 70% online']:7.4f} {row['loss per year, 5%/month churn, monthly repair']:9.6f} {row['loss in a 40% correlated burst']:10.5f} {k:7d}")
json.dump(out, open('e8_results.json', 'w'), indent=1)
