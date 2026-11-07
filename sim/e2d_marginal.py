"""Experiment 2d — the marginal effect of a corrupt bloc, against a no-bloc baseline.
Corruption gain = (wrong-verdict rate with the bloc − rate without it) × V. Cost = extra penalties on
targeted cases + expected seizures when review catches a corrupted verdict (two bonds ≥ V each).
"""
import json
exec(open('e2b_corruption_economics.py').read().split('import sys\nif len(sys.argv)')[0])
def rr_of(V): return review_rate(V)
out = {}
for appeal in (0.7, 0.95):
    for V in (1000, 10000):
        base = sim(0.0, 0.05, V, n_cases=200000, appeal=appeal)['targeted wrong verdicts that stood']
        for f in (0.10, 0.20, 0.33, 0.50):
            r = sim(f, 0.05, V, n_cases=200000, appeal=appeal)
            dw = r['targeted wrong verdicts that stood'] - base
            rr = rr_of(V)
            gain = dw * V
            seize = dw / (1 - rr) * rr * 2 * V          # caught corrupted verdicts: two bonds of ≥ V
            pen = -r['of which penalties']
            net = gain - pen - seize
            key = f'appeal {appeal}, V={V}, bloc {f:.0%}'
            out[key] = {'extra wrong verdicts per targeted case': round(dw, 4), 'gain': round(gain, 1), 'penalties': round(pen, 1), 'expected seizure': round(seize, 1), 'net per targeted case (fees)': round(net, 1)}
            print(key, out[key])
json.dump(out, open('e2d_results.json', 'w'), indent=1)
