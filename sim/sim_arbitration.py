"""Bitaid arbitration pool — economic simulation, experiment 1.

Rules are code, taken from Specification §10.4–10.5 (penalties, momentum, re-rolls, vindication)
and the review rates of whitepaper §7.4. Agents are fixed strategies, not learners:
  honest(skill)  reads the evidence, pays an effort cost, perceives the truth with an accuracy that
                 falls with case difficulty
  lazy           never looks; always votes the most common outcome (the base rate)
  random         coin flip
Question: under the rules as written, is honest work the profitable strategy, and by how much?
"""
import random, statistics, json, sys

def run(params, n_cases=20000, seed=1):
    rng = random.Random(seed)
    P = params
    pool = []
    for typ, count, skill in P['mix']:
        for _ in range(count):
            pool.append({'type': typ, 'skill': skill, 'pnl': 0.0, 'D': 0.0, 'cases': 0, 'errors': 0, 'reviews_triggered': 0})
    F = 1.0
    pool_rate = [P.get('init_rate', 0.1)]          # running mean error weight per vote across the pool

    def vote(a, truth, diff):
        if a['type'] == 'lazy': return P['base_outcome']
        if a['type'] == 'random': return rng.random() < 0.5
        acc = 0.5 + (a['skill'] - 0.5) * (1 - diff)
        return truth if rng.random() < acc else (not truth)

    def panel_ruling(n, truth, diff, seated):
        votes = [(a, vote(a, truth, diff)) for a in seated]
        yes = sum(1 for _, v in votes if v)
        # ⅔ supermajority; without it the case escalates as unresolved (treated as an appeal)
        if yes >= 2 * n / 3: return True, votes
        if n - yes >= 2 * n / 3: return False, votes
        return None, votes

    for c in range(n_cases):
        truth = rng.random() < P['p_true']           # base rate of outcome "True"
        diff = rng.betavariate(*P['difficulty'])
        tiers = []
        n = 3; ruling = None
        while True:
            seated = rng.sample(pool, n)
            for a in seated: a['cases'] += 1
            r, votes = panel_ruling(n, truth, diff, seated)
            tiers.append((n, votes, r))
            if r is None or (r != truth and rng.random() < P['p_appeal_wrong']) or (r == truth and rng.random() < P['p_appeal_frivolous']):
                if n >= P['max_panel']: ruling = r if r is not None else truth; break
                n = 2 * n + 1; continue
            ruling = r; break
        final = ruling
        if rng.random() < P['review_rate']:          # 100-arbitrator review: majority of honest-average judges
            yes = sum(1 for _ in range(100) if rng.random() < (0.5 + (P['review_skill'] - 0.5) * (1 - diff)) )
            final = truth if yes > 50 else (not truth)
        # settle every tier against the final ruling
        for n, votes, r in tiers:
            wrong = [a for a, v in votes if v != final]
            right = [a for a, v in votes if v == final]
            p = len(wrong) / n
            for a in right:
                a['pnl'] += F
                if a['type'] == 'honest': a['pnl'] -= P['effort']
            pen_pool = 0.0
            for a in wrong:
                if a['type'] == 'honest': a['pnl'] -= P['effort']
                if n == 3: k, w = 2.0, P['w3']
                else:
                    pc = min(max(p, 1 / n), 1 / 3)
                    k = 2 + 2 * ((1 / 3 - pc) / (1 / 3 - 1 / n)); w = (1 / 3 - pc) / (1 / 3 - 1 / n)
                    if r is not None and r == final and p < 1 / 3: pass
                pen = k * F * min(2 ** a['D'], P['cap'])
                a['pnl'] -= pen; pen_pool += pen
                a['D'] += w; a['errors'] += 1
                pool_rate[0] = 0.999 * pool_rate[0] + 0.001 * w
                if a['D'] >= 3: a['reviews_triggered'] += 1
            for a, v in votes:
                if v == final: pool_rate[0] = 0.999 * pool_rate[0]
                a['D'] *= P['lam']
                if P.get('relative'):
                    a['D'] = max(0.0, a['D'] - pool_rate[0] * P.get('rel_margin', 1.0))
    out = {}
    for typ in sorted({a['type'] + (f" {a['skill']:.2f}" if a['type'] == 'honest' else '') for a in pool}):
        grp = [a for a in pool if (a['type'] + (f" {a['skill']:.2f}" if a['type'] == 'honest' else '')) == typ]
        cases = sum(a['cases'] for a in grp)
        out[typ] = {'profit_per_case_in_fees': round(sum(a['pnl'] for a in grp) / max(cases, 1), 3),
                    'error_rate': round(sum(a['errors'] for a in grp) / max(cases, 1), 3),
                    'final_D_mean': round(statistics.mean(a['D'] for a in grp), 2),
                    'share_of_cases_under_D>=3': round(sum(a['reviews_triggered'] for a in grp) / max(cases, 1), 3)}
    return out

BASE = dict(
    mix=[('honest', 60, 0.95), ('honest', 60, 0.90), ('honest', 40, 0.80), ('lazy', 20, 0), ('random', 20, 0)],
    p_true=0.7, base_outcome=True, difficulty=(1.2, 5), effort=0.3,
    p_appeal_wrong=0.7, p_appeal_frivolous=0.03, max_panel=31,
    review_rate=0.10, review_skill=0.90, lam=0.99, cap=32, w3=0.5)

if __name__ == '__main__' and len(sys.argv) > 1 and sys.argv[1] == 'sweep':
    out = {}
    for label, diff in [('easy cases (mean difficulty 0.10)', (1, 9)), ('as assumed (0.19)', (1.2, 5)), ('hard (0.30)', (1.5, 3.5))]:
        for vname, ch in [('as written', {}), ('relative momentum', {'relative': True, 'rel_margin': 1.5})]:
            p = dict(BASE); p.update(ch); p['difficulty'] = diff
            r = run(p, n_cases=20000)
            out[f'{label} | {vname}'] = r
            print('\n==', label, '|', vname)
            for k, v in r.items(): print(f'  {k:14s} {v}')
    json.dump(out, open('e1_sweep.json', 'w'), indent=1)
    sys.exit()

if __name__ == '__main__':
    variants = {
        'As written (λ 0.99, cap 32×, 3-panel error weight 0.5)': {},
        'No momentum (penalty 2–4× only)': {'cap': 1},
        'Faster decay λ 0.95': {'lam': 0.95},
        'λ 0.95 and cap 4×': {'lam': 0.95, 'cap': 4},
        'λ 0.97, cap 8×, 3-panel errors weigh 0.25': {'lam': 0.97, 'cap': 8, 'w3': 0.25},
    }
    res = {}
    for name, ch in variants.items():
        p = dict(BASE); p.update(ch)
        res[name] = run(p)
        print('\n==', name)
        for k, v in res[name].items(): print(f'  {k:14s} {v}')
    json.dump(res, open('e1_results.json', 'w'), indent=1)
