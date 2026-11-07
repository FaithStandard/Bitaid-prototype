"""Experiment 2 — a colluding bloc buys verdicts on targeted cases.

Pool of 200; a bloc holds a fraction f. On cases its sponsor targets, every bloc member votes the
sponsor's (wrong) outcome; elsewhere bloc members act like honest 0.95 arbitrators. Seats are taken
blind (random). The wronged party re-rolls a wrong verdict with probability 0.7 at each tier;
10% of closed cases are drawn for the 100-arbitrator review. Penalties as in §10.4 with relative
momentum (experiment 1). Output: how often a targeted case ends wrong, and what each wrong verdict
costs the bloc in penalties.
"""
import random, json
def sim(f, n_target=20000, appeal=0.7, review=0.10, seed=3, max_panel=31):
    rng = random.Random(seed)
    wrong_final = 0; bloc_pen = 0.0; bloc_fee = 0.0; tiers_seen = 0
    for _ in range(n_target):
        n = 3; final = None; tiers = []
        while True:
            seats = [rng.random() < f for _ in range(n)]
            b = sum(seats)
            honest_wrong = sum(1 for s in seats if not s and rng.random() < 0.10)
            wrong_votes = b + honest_wrong
            if wrong_votes >= 2 * n / 3: r = False
            elif n - wrong_votes >= 2 * n / 3: r = True
            else: r = None
            tiers.append((n, b))
            if r is None or (r is False and rng.random() < appeal):
                if n >= max_panel: final = True; break
                n = 2 * n + 1; continue
            final = r; break
        if final is False and rng.random() < review:
            final = True
        tiers_seen += len(tiers)
        if final is False:
            wrong_final += 1
            for n, b in tiers: bloc_fee += b
        else:
            for n, b in tiers:
                if b:
                    p = min(max(b / n, 1 / n), 1 / 3)
                    k = 2.0 if n == 3 else 2 + 2 * ((1 / 3 - p) / (1 / 3 - 1 / n))
                    bloc_pen += b * k
    return {'targeted cases ending wrong': round(wrong_final / n_target, 4),
            'bloc penalty per targeted case (fees)': round(bloc_pen / n_target, 2),
            'bloc fees per targeted case': round(bloc_fee / n_target, 2),
            'mean tiers per case': round(tiers_seen / n_target, 2)}
out = {}
for f in (0.05, 0.10, 0.20, 0.33, 0.50, 0.67):
    out[f] = sim(f); print(f'bloc {f:.0%}:', out[f])
json.dump(out, open('e2_results.json', 'w'), indent=1)
