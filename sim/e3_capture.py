"""Experiment 3 — capturing the pool by queue pressure, with the voided-seat rule.

Honest pool of 200 clears C cases a day. To open a seat the attacker keeps the queue non-empty for
432 blocks (3 days), which takes more incoming disputes than the pool clears: about 3·C fake
escalated cases per window, each paid for by the attacker at the prevailing fee (whoever asks for a
ruling pays), with the time trigger compounding the fee 1.0625 per 18 blocks while the queue stands.
Every fake case is drawn for review with probability r and a drawn fake is recognised with
probability δ; one recognised fake voids every seat opened by a window it counted toward.
The attacker wins every seat it opens (best case for it). Goal: 101 of 200 seats.
"""
import random, json
def campaign(C, r, delta, fee0=1.0, days=730, seed=9, void=True):
    rng = random.Random(seed)
    seats = []                         # list of windows' fake-case sets that opened held seats
    cost = 0.0; day = 0; opened = 0; voided = 0
    while day < days and len([s for s in seats if s]) < 101:
        fakes = 3 * C
        fee = fee0
        window_cost = 0.0
        for block in range(0, 432, 18):
            fee *= 1.0625
        window_cost = fakes * 3 * (fee0 + fee) / 2      # 3 seats per first-instance panel, mean fee over the window
        cost += window_cost
        caught = any(rng.random() < r * delta for _ in range(fakes))
        opened += 1
        if caught and void:
            voided += 1                                  # seat voided; and every fake later traced reopens the rest
        else:
            seats.append(True)
        day += 3
    held = len(seats)
    return {'seats held': held, 'windows run': opened, 'seats voided': voided, 'days': day, 'fee cost (in starting fees)': round(cost)}
out = {}
for C in (10, 50, 200):
    for r, d in [(0.05, 0.5), (0.05, 0.9), (0.10, 0.9)]:
        for void in (False, True):
            k = f'capacity {C}/day, review {r:.0%}, recognition {d:.0%}, void rule {"on" if void else "off"}'
            out[k] = campaign(C, r, d, void=void); print(k, out[k])
json.dump(out, open('e3_results.json', 'w'), indent=1)
