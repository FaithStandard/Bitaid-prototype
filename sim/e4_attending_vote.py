"""Experiment 4 — the attending vote under the merit weight (Specification §9).

A cell's responders accumulate labor = bounty earned from successful work, in units of the local median
bounty, seasoned (here: cases count once 90 days old, i.e. after a lag). Each incident draws up to five
attendees; one act is the key act. Ballots: honest attendees identify the key act correctly with
probability 0.9. A self-serving attendee always names itself as the key actor. The ballot-weighted
majority decides; a harmed attendee escalates when the stake is worth the panel fee, and the panel
finds the truth with probability 0.95; a ballot found false is fraud: the author's bond is seized and it
is excluded (bannable tier), with probability `catch` that the panel judges it blatant.

Questions: (1) how often does the weighted vote get the key act wrong? (2) can self-serving veterans
entrench through the labor feedback loop (weight -> pay -> labor -> weight)? (3) what does it cost them?
"""
import random, math, json, statistics

def run(n_resp=40, n_selfish=4, selfish_veteran=True, cases=6000, seed=2, weighted=True, catch=0.6, fee=0.0, escalate_any=False):
    rng = random.Random(seed)
    R = [{'labor': 0.0, 'pending': [], 'selfish': i < n_selfish, 'stake': rng.uniform(1, 3), 'active': True,
          'earned': 0.0, 'bond_lost': 0.0, 'acc_r': 0, 'acc_t': 0} for i in range(n_resp)]
    if selfish_veteran:
        for i in range(n_selfish): R[i]['labor'] = 30.0          # start as established veterans
    wrong = esc = 0
    for c in range(cases):
        for r in R:                                              # seasoning: labor credited after a lag
            while r['pending'] and r['pending'][0][0] <= c: r['labor'] += r['pending'].pop(0)[1]
        act = [i for i, r in enumerate(R) if r['active']]
        k = rng.randint(2, 5)
        att = rng.sample(act, k)
        key = rng.choice(att)
        def w(i):
            if not weighted: return 1.0
            r = R[i]; acc = (r['acc_r'] / r['acc_t']) if r['acc_t'] >= 5 else 1.0
            return math.sqrt(min(r['stake'], 3)) * (0.1 + r['labor']) * acc
        tally = {}
        ballots = {}
        for i in att:
            if R[i]['selfish']: b = i
            else: b = key if rng.random() < 0.9 else rng.choice(att)
            ballots[i] = b; tally[b] = tally.get(b, 0) + w(i)
        winner = max(tally, key=lambda x: (tally[x], -x))
        final = winner
        bounty = 1.0                                              # one median bounty per case; key act gets 2 shares, others 1
        if winner != key:
            wrong += 1
            # the true key actor escalates if the difference is worth the fee
            gain = bounty / (len(att) + 1)                    # what the true key actor recovers by escalating
            if not R[key]['selfish'] and (gain > fee or escalate_any) and rng.random() < 0.95:
                esc += 1
                if rng.random() < 0.95: final = key
                for i, b in ballots.items():                       # false ballots exposed
                    if final == key and b != key and R[i]['selfish'] and rng.random() < catch:
                        R[i]['active'] = False; R[i]['bond_lost'] += 10.0   # bond (in median bounties) and exclusion
        shares = {i: (2 if i == final else 1) for i in att}
        tot = sum(shares.values())
        for i in att:
            pay = bounty * shares[i] / tot
            R[i]['earned'] += pay
            if R[i]['active']: R[i]['pending'].append((c + 300, pay))     # success-only labor, seasoned after 300 cases
            if final in ballots.values():
                R[i]['acc_t'] += 1; R[i]['acc_r'] += ballots[i] == final
    s = [r for r in R if r['selfish']]; h = [r for r in R if not r['selfish']]
    return {'key act wrong after the vote': round(wrong / cases, 4), 'escalations per case': round(esc / cases, 4),
            'selfish still active': sum(r['active'] for r in s), 'selfish net (median bounties)': round(statistics.mean(r['earned'] - r['bond_lost'] for r in s), 1) if s else None,
            'honest mean earned': round(statistics.mean(r['earned'] for r in h), 1),
            'labor share held by selfish at end': round(sum(r['labor'] for r in s) / max(sum(r['labor'] for r in R), 1e-9), 3) if s else 0}
out = {}
for label, kw in [('no selfish, weighted', dict(n_selfish=0)),
                  ('4 selfish newcomers, weighted', dict(selfish_veteran=False)),
                  ('4 selfish veterans, weighted', dict()),
                  ('4 selfish veterans, unweighted (one ballot, one vote)', dict(weighted=False)),
                  ('4 selfish veterans, weighted, panels rarely judge false ballots blatant (catch 0.2)', dict(catch=0.2)),
                  ('4 selfish veterans, small bounties: panel fee 0.3 bounty, escalate only if worth it', dict(fee=0.3)),
                  ('same, unweighted', dict(fee=0.3, weighted=False)),
                  ('same, weighted, fee 0.3 but escalation fee recovered from the false-ballot author (any harmed party escalates)', dict(fee=0.3, escalate_any=True))]:
    out[label] = run(**kw); print(label, '\n   ', out[label])
json.dump(out, open('e4_results.json', 'w'), indent=1)
