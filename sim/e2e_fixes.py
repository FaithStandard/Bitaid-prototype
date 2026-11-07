"""Experiment 2e — candidate fixes: (a) arbitrator eligibility bond ≥ m × case value (m = 1 now, 2 proposed);
(b) review rate for split verdicts raised to r_split. Appeal probability 0.95. Bloc targets 5% of cases."""
import json
exec(open('e2b_corruption_economics.py').read().split('import sys\nif len(sys.argv)')[0])
out = {}
for V in (1000, 10000):
    base = sim(0.0, 0.05, V, n_cases=200000, appeal=0.95)['targeted wrong verdicts that stood']
    for m, rs in [(1, None), (2, None), (2, 0.4), (2, 0.6)]:
        for f in (0.20, 0.33, 0.50):
            r = sim(f, 0.05, V, n_cases=200000, appeal=0.95, split_rr=rs)
            # share of the bloc's stood wrong verdicts that came from split panels is ~all of them below 50%;
            rr_eff = max(review_rate(V), rs or 0)
            dw = r['targeted wrong verdicts that stood'] - base
            gain = dw * V; seize = dw / max(1 - rr_eff, 1e-9) * rr_eff * 2 * m * V
            net = gain + r['of which penalties'] - seize
            key = f'V={V} bond×{m} split-review {rs} bloc {f:.0%}'
            out[key] = {'net per targeted case (fees)': round(net, 1), 'review load': r['review load (split verdicts reviewed, share of cases)']}
            print(key, out[key])
json.dump(out, open('e2e_results.json', 'w'), indent=1)
