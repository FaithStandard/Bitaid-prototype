"""Experiment 2b — does buying verdicts pay, once review, restitution and momentum-triggered review act?

Pool 200, bloc share f. A share tau of all cases are targeted, each worth V (in units of the case fee).
Bloc members vote the sponsor's wrong outcome on targeted cases and honestly (0.90 accuracy)
elsewhere; honest members are 0.90 accurate. Wronged parties re-roll a wrong verdict with p = 0.7.
Review: base rate by value (5% / 10% / 20% / 40%); an overturned verdict is repaid from the bonds of
those who voted for it (restitution up to V). Relative momentum (experiment 1): a member whose D
reaches 3 has its last 50 cases reviewed. Output: coalition profit per targeted case, in fees.
"""
import random, json
def review_rate(V):          # V in fees; fee assumed 1% of value -> V=100 is 0.01 BTC at a 0.0001 fee
    return 0.05 if V <= 100 else 0.10 if V <= 1000 else 0.20 if V <= 10000 else 0.40

def sim(f, tau, V, n_cases=40000, seed=5, appeal=0.7, full_seizure=False, cascade=False, split_rr=None):
    rng = random.Random(seed)
    N = 200; bloc = set(range(int(N * f)))
    D = [0.0] * N; hist = [[] for _ in range(N)]
    pool_rate = 0.1
    gain = pen = rest = fees = 0.0; wrong_kept = targeted = 0; bloc_seats_t = 0
    open_wrong = {}                               # case id -> (wrong voters of final tier) for targeted wrong finals
    rr = review_rate(V)
    split_reviews = [0]
    for c in range(n_cases):
        tgt = rng.random() < tau
        targeted += tgt
        n = 3; tiers = []
        while True:
            seats = rng.sample(range(N), n)
            votes = {}
            for a in seats:
                if tgt and a in bloc: votes[a] = False
                else: votes[a] = rng.random() < 0.90
            yes = sum(votes.values())
            r = True if yes >= 2 * n / 3 else False if n - yes >= 2 * n / 3 else None
            tiers.append((n, votes))
            if r is None or (r is False and rng.random() < appeal):
                if n >= 31: r = True; break
                n = 2 * n + 1; continue
            break
        final = r
        caught = False
        last_votes = list(tiers[-1][1].values())
        unanimous = all(v == last_votes[0] for v in last_votes)
        this_rr = rr if (unanimous or split_rr is None) else max(rr, split_rr)
        reviews_done = locals().get('reviews_done', 0)
        if not unanimous and split_rr is not None: split_reviews[0] += 1
        if final is False and rng.random() < this_rr:
            final = True; caught = tgt
        for n, votes in tiers:
            wrongv = [a for a, v in votes.items() if v != final]
            p = len(wrongv) / n
            for a, v in votes.items():
                if tgt and a in bloc: bloc_seats_t += 1
                if v == final:
                    if a in bloc and tgt: fees += 1
                    pool_rate *= 0.999
                else:
                    pc = min(max(p, 1 / n), 1 / 3)
                    k, w = (2.0, 0.5) if n == 3 else (2 + 2 * ((1 / 3 - pc) / (1 / 3 - 1 / n)), (1 / 3 - pc) / (1 / 3 - 1 / n))
                    if a in bloc and tgt: pen += k * min(2 ** D[a], 32)
                    D[a] += w; pool_rate = 0.999 * pool_rate + 0.001 * w
                D[a] = max(0.0, D[a] * 0.99 - 1.5 * pool_rate)
                hist[a] = (hist[a] + [c])[-50:]
        if tgt and final is False:
            gain += V; wrong_kept += 1
            open_wrong[c] = [a for a, v in tiers[-1][1].items() if v is False]
        if caught and full_seizure:
            voters = [a for a, v in tiers[-1][1].items() if v is False and a in bloc]
            rest += len(voters) * max(V, 1000)          # each loses a bond worth at least the case value (and the 0.1 BTC floor)
            queue = list(voters)
            seen = set()
            while queue and cascade:
                a = queue.pop(); 
                if a in seen: continue
                seen.add(a)
                for cid in hist[a]:
                    if cid in open_wrong:
                        gain -= V; wrong_kept -= 1
                        more = [x for x in open_wrong.pop(cid) if x in bloc]
                        rest += len(more) * max(V, 1000); queue += more
            for a in seen | set(voters):
                bloc.discard(a)                          # expelled; the seat goes back to the open pool
        # momentum-triggered review of a bloc member's recent cases
        for a in list(bloc):
            if D[a] >= 3:
                for cid in hist[a]:
                    if cid in open_wrong:
                        gain -= V; rest += V; wrong_kept -= 1
                        del open_wrong[cid]
                D[a] = 0.0
    profit = gain - pen - rest + fees - 0.7 * bloc_seats_t   # minus what those seats would have earned voting honestly
    return {'review load (split verdicts reviewed, share of cases)': round(split_reviews[0] * (split_rr or 0) / n_cases, 4), 'targeted wrong verdicts that stood': round(wrong_kept / max(targeted, 1), 4),
            'coalition profit per targeted case (fees)': round(profit / max(targeted, 1), 2),
            'of which penalties': round(-pen / max(targeted, 1), 2), 'restitution': round(-rest / max(targeted, 1), 2)}
import sys
if len(sys.argv) > 1:
    out = {}
    for label, kw in [('as modelled before (appeal 0.7, restitution only)', {}),
                      ('appeal 0.95', {'appeal': 0.95}),
                      ('appeal 0.95 + full bond seizure on review', {'appeal': 0.95, 'full_seizure': True}),
                      ('appeal 0.95 + seizure + review cascade', {'appeal': 0.95, 'full_seizure': True, 'cascade': True})]:
        print('\n==', label)
        for V in (1000, 10000):
            for f in (0.20, 0.33, 0.50):
                r = sim(f, 0.01, V, **kw); out[f'{label} | V={V} f={f}'] = r
                print(f'  V={V:>5}  bloc {f:>4.0%}  targets 1% ->', r)
    json.dump(out, open('e2c_results.json', 'w'), indent=1); sys.exit()
out = {}
for V in (100, 1000, 10000):
    for f in (0.10, 0.20, 0.33, 0.50):
        for tau in (0.01, 0.05, 0.20):
            r = sim(f, tau, V); out[f'V={V} f={f} tau={tau}'] = r
            print(f'V={V:>5} fees  bloc {f:>4.0%}  targets {tau:>4.0%} of cases ->', r)
json.dump(out, open('e2b_results.json', 'w'), indent=1)
