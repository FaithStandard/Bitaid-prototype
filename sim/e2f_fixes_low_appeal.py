"""Experiment 2f — the adopted fixes when wronged parties re-roll only 70% of the time."""
import json
exec(open('e2b_corruption_economics.py').read().split('import sys\nif len(sys.argv)')[0])
out = {}
for V in (1000, 10000):
    base = sim(0.0, 0.05, V, n_cases=200000, appeal=0.7)['targeted wrong verdicts that stood']
    for f in (0.20, 0.33, 0.50):
        r = sim(f, 0.05, V, n_cases=200000, appeal=0.7, split_rr=0.4)
        rr_eff = max(review_rate(V), 0.4)
        dw = r['targeted wrong verdicts that stood'] - base
        net = dw * V + r['of which penalties'] - dw / (1 - rr_eff) * rr_eff * 4 * V
        out[f'V={V} bloc {f:.0%}'] = round(net, 1); print(f'appeal 0.7, bond×2, split review 40%, V={V}, bloc {f:.0%}: net {net:.1f} fees per targeted case')
json.dump(out, open('e2f_results.json', 'w'), indent=1)
