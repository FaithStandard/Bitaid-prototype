"""Arbitration fee market: three rules compared from the parties' side.

Time step: 18 blocks (~3 h). Demand: escalated cases (weighted by legitimate responders) arrive Poisson.
Supply: pool slots, each clearing cases at a rate that rises with the fee (elasticity e, up to 3x, adjusting
with a one-week lag: teams, tools, hours). Slots open by the 0.06%-per-congested-week rule (min 1) plus
one yearly opening. Fees in USD per seat; a tier-1 panel is 3 seats.
Rules:
  A  spec before 2026-11-12: +-12.5% per case closed (queue>0 / =0), +6.25% per step while queue>0
  B  merged 2026-11-12: +-12.5% per close, +2.5%/step queue>0, -2.5%/step idle down to the reference fee
  C  proposal: no per-close step; per step 2.5% x clamp((Q - T)/T, -1, 1), T = one day of capacity;
     the rate halves for each further week of unbroken congestion; falling never below the reference fee
     unless the queue is empty
"""
import math, random, statistics as st

STEP_H = 3
def pois(rnd, m):
    if m <= 0: return 0
    if m > 30: return max(0, int(rnd.gauss(m, math.sqrt(m)) + 0.5))
    L, k, p = math.exp(-m), 0, 1.0
    while True:
        p *= rnd.random()
        if p < L: return k
        k += 1

def run(rule, scen, fee0, elast, seed, weeks=26, pool0=200, per_slot_day=0.02):
    rnd = random.Random(seed)
    steps = weeks * 56
    pool = pool0
    base_cap = pool0 * per_slot_day / 8          # cases per step at fee0 (8 steps a day)
    lam0 = base_cap * 0.8                         # demand at 80% of capacity
    fee, q, mult = fee0, [], 1.0                  # q: list of arrival steps (FIFO)
    cleared, rec = [fee0] * 20, []
    congested_steps, cong_week_idx = 0, 0
    week_cong = 0
    for t in range(steps):
        wk = t / 56
        if scen == 'steady': d = 1.0
        elif scen == 'spike': d = 3.0 if 4 <= wk < 6 else 1.0
        else: d = 2.0 if wk >= 4 else 1.0        # 'shift': demand doubles for good
        for _ in range(pois(rnd, lam0 * d)):
            q.append(t)
        # supply adjusts toward the fee's pull with a one-week lag
        target_mult = min(3.0, (fee / fee0) ** elast)
        mult += (target_mult - mult) / 56
        cap = pool * per_slot_day / 8 * mult
        served = min(len(q), pois(rnd, cap))
        for _ in range(served):
            arr = q.pop(0)
            rec.append((t, fee, (t - arr) * STEP_H / 24))
            cleared.append(fee)
            if rule in 'AB':
                fee *= 1.125 if q else 0.875
        ref = st.median(cleared[-100:])
        n = len(q)
        if rule == 'A':
            if n: fee *= 1.0625
        elif rule == 'B':
            if n: fee *= 1.025
            elif fee > ref: fee = max(ref, fee * 0.975)
        else:
            T = max(1.0, cap * 8)                 # one day of capacity
            x = max(-1.0, min(1.0, (n - T) / T))
            over = n > T
            congested_steps = congested_steps + 1 if over else 0
            halvings = congested_steps // 56
            step = 0.025 * x / (2 ** halvings if x > 0 else 1)
            new = fee * (1 + step)
            if step < 0 and n > 0: new = max(new, min(fee, ref))
            fee = new
        # slots: 0.06% of the pool per fully congested week (min 1), plus one yearly opening
        week_cong = week_cong + 1 if n > 0 else 0
        if week_cong >= 56:
            pool += max(1, int(pool * 0.0006)); week_cong = 0
        if t and t % (52 * 56) == 0:
            pool += max(1, int(pool * 0.0006))
    return rec, pool

def stakes(rnd, n):  # case pots in USD, lognormal around $500
    return [math.exp(rnd.gauss(math.log(500), 1.2)) for _ in range(n)]

def summary(rule, scen, fee0, elast, seeds=10):
    pan, waits, over10, over100, peak = [], [], [], [], []
    for s in range(seeds):
        rec, pool = run(rule, scen, fee0, elast, s)
        rnd = random.Random(1000 + s)
        sk = stakes(rnd, len(rec))
        p = [3 * f for _, f, _ in rec]
        pan += p; waits += [w for *_, w in rec]
        over10.append(sum(1 for a, b in zip(p, sk) if a > 0.10 * b) / max(1, len(p)))
        over100.append(sum(1 for a, b in zip(p, sk) if a > b) / max(1, len(p)))
        peak.append(max(p) if p else 0)
    pan.sort(); waits.sort()
    q = lambda v, x: v[min(len(v) - 1, int(x * len(v)))]
    return dict(med=q(pan, .5), p95=q(pan, .95), peak=st.median(peak), wait=q(waits, .5), wait95=q(waits, .95),
                o10=st.mean(over10), o100=st.mean(over100))

if __name__ == '__main__':
    import sys
    rows = []
    for fee0 in [30, 100, 300]:
        for scen in ['steady', 'spike', 'shift']:
            for elast in [0.3, 0.7]:
                for rule in 'ABC':
                    r = summary(rule, scen, fee0, elast)
                    rows.append((fee0, scen, elast, rule, r))
                    print(f"seat ${fee0:>3} {scen:6} e={elast} {rule}: panel median ${r['med']:>10,.0f} p95 ${r['p95']:>12,.0f} peak ${r['peak']:>14,.0f} | wait med {r['wait']:5.1f}d p95 {r['wait95']:5.1f}d | panel>10% of pots {r['o10']*100:5.1f}%  >pots {r['o100']*100:5.1f}%", flush=True)
