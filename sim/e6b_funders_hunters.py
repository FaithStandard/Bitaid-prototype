"""Experiment 6b — no protocol floor: funders review their own money, arbitrators hunt for fraud.

Replaces E6's 50% outside-money floor with two market forces:
  funder policy  whoever put outside money in a payout (an insurer's payment layer, liability cover, a sponsor)
                 is a party: it may escalate, pays the panel fee, and is repaid from what is seized. It commits a
                 review rate r for its draws, published with the buffer, and may add a release delay (money on an
                 escalated case waits for the ruling).
  hunters        any bonded arbitrator may flag any closed case from public metadata (cell, labor, stake,
                 insurer history), staking a challenge bond of 3 fees, lost if the case clears; it earns the
                 3-fee premium from the seizure if fraud is confirmed. A hunter flags when its posterior that the
                 case is fraud makes the flag profitable.
  random R       the value-based sampling stays underneath (5% at small values).
Rings of k responders + caller stage cases paid by outside money (one offer each); stakes 2 offers per responder.
Units: offers. fee = panel fee as a fraction of the offer.
"""
import random, math, json, statistics

def phi(x): return 0.5 * (1 + math.erf(x / math.sqrt(2)))

def hunter_rates(dprime, base_fraud, stake=3.0, premium=3.0, mimic=0.0):
    """Hunters see a suspicion score: honest ~ N(0,1), staged ~ N(d'-mimic, 1). They flag above the score t where
    P(fraud|s) * premium = (1-P) * stake. Returns (share of staged cases flagged, share of honest cases flagged)."""
    d = max(dprime - mimic, 1e-6)
    # posterior odds at s: base/(1-base) * exp(d*s - d^2/2); flag where odds >= stake/premium
    odds_need = stake / premium
    t = (math.log(odds_need * (1 - base_fraud) / base_fraud) + d * d / 2) / d
    return 1 - phi(t - d), 1 - phi(t)

def ring(r, hunt, R=0.05, k=1, delay=False, sims=20000, seed=3, max_n=200):
    rng = random.Random(seed)
    p = 1 - (1 - r) * (1 - hunt) * (1 - R)
    best = -1e9
    for n in [1, 2, 3, 5, 10, 20, 50, 100, 200]:
        tot = 0.0
        for _ in range(sims // 10):
            g = 0.0; caught = False
            for i in range(n):
                if rng.random() < p: caught = True; g += 0 if delay else 1; break
                g += 1
            tot += g - (2.0 * k if caught else 0)
        best = max(best, tot / (sims // 10))
    return round(best, 2)

def insurer_cost(r, fee, deterred, fraud_loss_if_not=0.3):
    """Cost per draw, in offers: review fees on every draw it escalates, plus fraud losses if rings are not deterred.
    Honest escalations clear; the fee is the insurer's. Confirmed frauds repay the fee from the seizure."""
    return r * fee + (0 if deterred else fraud_loss_if_not)

out = {'ring': {}, 'insurer': {}, 'hunters': {}}
print('1. Ring best-response profit (offers) against a committed funder review rate r, no hunters, random R 5%')
for k in [1, 3]:
    for delay in [False, True]:
        row = {r: ring(r, 0.0, k=k, delay=delay) for r in [0.0, 0.2, 0.33, 0.4, 0.5, 0.6, 0.8, 1.0]}
        out['ring'][f'k={k} delay={delay}'] = row
        print(f'  k={k} release delay={delay!s:5s}', row)

print('\n2. The insurer\'s choice: cheapest committed rate that deters a lone-responder ring, and its cost per draw')
for fee in [0.01, 0.05, 0.1, 0.3]:
    for delay in [False, True]:
        options = []
        for r in [x / 20 for x in range(0, 21)]:
            det = ring(r, 0.0, k=1, delay=delay, sims=6000) <= 0
            options.append((insurer_cost(r, fee, det), r, det))
        c, r, det = min(options)
        out['insurer'][f'fee {fee} delay {delay}'] = {'rate chosen': r, 'cost per draw (offers)': round(c, 3), 'deters': det}
        print(f'  fee {fee:4.2f} of the claim, delay {delay!s:5s}: chooses r={r:.2f}, cost {c:.3f} offers per draw, deters={det}')

print('\n3. Hunters alone (no funder review: small crowd top-ups), random R 5%')
for base in [0.01, 0.001]:
    for dp in [1.0, 2.0, 3.0]:
        for mimic in [0.0, 1.0]:
            caught, false_ = hunter_rates(dp, base, mimic=mimic)
            prof = ring(0.0, caught, k=1)
            key = f'fraud base {base} | signal d\' {dp} | ring mimicry {mimic}'
            out['hunters'][key] = {'staged flagged': round(caught, 3), 'honest flagged': round(false_, 4), 'ring profit k=1': prof, 'ring profit k=3': ring(0.0, caught, k=3)}
            print(f'  {key:55s} staged flagged {caught:.2f}  honest flagged {false_:.4f}  ring k=1 {prof:6.2f}  k=3 {out["hunters"][key]["ring profit k=3"]:6.2f}')
print('\n4. Hunters around a confirmed fraud (prior that a linked case is staged rises), no mimicry')
out['cascade'] = {}
for base in [0.05, 0.2, 0.5]:
    for dp in [1.0, 2.0]:
        c, f = hunter_rates(dp, base); out['cascade'][f'prior {base} | d\' {dp}'] = {'staged flagged': round(c, 3), 'honest flagged': round(f, 3)}
        print(f'  prior {base:4.2f} d\' {dp}: staged flagged {c:.2f}, honest flagged {f:.3f}')
json.dump(out, open('e6b_results.json', 'w'), indent=1)
