"""Experiment 1b — herding: what happens as the share of lazy base-rate voters grows?"""
import json, random
exec(open('sim_arbitration.py').read().split("if __name__ == '__main__' and len")[0])
out = {}
for lazy in (10, 30, 50, 70):
    honest = 200 - lazy
    p = dict(BASE); p.update({'relative': True, 'rel_margin': 1.5,
        'mix': [('honest', honest // 2, 0.95), ('honest', honest - honest // 2, 0.90), ('lazy', lazy, 0), ('random', 0, 0)]})
    # measure final-ruling accuracy too
    r = run(p, n_cases=20000)
    out[f'{lazy}% lazy'] = r
    print(f'\n== {lazy/2:.0f}% of pool lazy ({lazy} of 200)')
    for k, v in r.items(): print(f'  {k:14s} profit {v["profit_per_case_in_fees"]:+.3f}  errors {v["error_rate"]:.3f}')
json.dump(out, open('e1b_results.json', 'w'), indent=1)
