"""Experiment 5 — the insurer market (Specification §4).

Part A — layer 0 shared by several clients. A layer 0 buffer of value B backs N responder clients; the
acceptance gate counts it at B/N for each (its encumbrance count). Each client commits misconduct or
a bannable act with probability m per year (after the insurer's vetting). Compared:
  whole layer   as written: such a finding seizes the whole first insurer layer
  counted part  the finding seizes the part of the layer the gate counted for that client (B/N at
                acceptance); the rest returns to the buffer script and keeps covering the others
Measured: the premium per unit of counted cover an insurer must charge to break even, and how often an
innocent client loses its cover mid-year because of someone else.

Part B — payment layers shared by many callers. A buffer of value B pays offers (value 1 each) for N
callers; an incident draws one offer. Incidents arrive at rate p per caller-year, plus cell shocks:
with probability q per cell-year, every caller in that cell has an incident with probability s (a riot,
a flood). Actuarial leverage = N / B (offers backed per offer held). The insurer refills the buffer once a
year. Measured: the chance that a caller's claim finds the layer exhausted, by leverage and by how the
insurer's clients are spread across cells. Compared filters: the encumbrance count alone, and the
count by parent cell.
"""
import random, json, statistics

def part_a(N, m=0.01, B=1.0, years=20000, rule='whole layer', seed=1):
    rng = random.Random(seed)
    loss = 0.0; innocent_gaps = 0; client_years = 0
    for _ in range(years):
        left = B
        bad = [i for i in range(N) if rng.random() < m]
        for i in bad:
            take = left if rule == 'whole layer' else min(left, B / N)
            loss += take; left -= take
        if bad and left < B * (N - len(bad)) / N - 1e-12:
            innocent_gaps += N - len(bad)
        client_years += N
    counted_unit_years = years * B         # B/N counted for each of N clients
    return {'break-even premium per unit of counted cover per year': round(loss / counted_unit_years, 4),
            'innocent clients losing cover mid-year, per client-year': round(innocent_gaps / client_years, 4)}

def part_b(N, B, cells, p=0.05, q=0.02, s=0.5, years=20000, seed=2):
    rng = random.Random(seed)
    claims = short = 0
    per_cell = [N // cells + (1 if c < N % cells else 0) for c in range(cells)]
    worst = []
    for _ in range(years):
        n_inc = 0
        for c in range(cells):
            k = per_cell[c]
            rate = s if rng.random() < q else p
            # binomial draw
            n_inc += sum(1 for _ in range(k) if rng.random() < rate) if k < 200 else int(rng.gauss(k * rate, (k * rate * (1 - rate)) ** 0.5) + 0.5)
        claims += n_inc; short += max(0, n_inc - int(B))
    return round(short / max(claims, 1), 4)

out = {'A': {}, 'B': {}}
print('Part A — shared layer 0, misconduct 1% per client-year')
for N in [1, 2, 5, 10, 50]:
    for rule in ['whole layer', 'counted part']:
        r = part_a(N, rule=rule); out['A'][f'N={N} | {rule}'] = r
        print(f'  N={N:3d} {rule:13s} {r}')

print('\nPart B — chance a claim finds the payment layer exhausted (incidents 5%/caller-yr; cell shock 2%/cell-yr hitting half the cell)')
for N in [100, 1000]:
    for lev in [5, 10, 20, 50]:
        B = N / lev
        row = {}
        for cells in [1, 3, 10, 50]:
            if cells > N: continue
            row[f'{cells} cells'] = part_b(N, B, cells, years=4000 if N == 1000 else 20000)
        out['B'][f'N={N} callers, actuarial leverage {lev}x'] = row
        print(f'  N={N:5d} leverage {lev:3d}x  ', row)
json.dump(out, open('e5_results.json', 'w'), indent=1)
