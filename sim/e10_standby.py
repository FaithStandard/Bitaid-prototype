"""Rule C with and without a standby queue (2026-11-12).

Each escalation posts a bid: 70% of parties post the current fee plus 10-30% headroom (impatient), 30% post
40-90% of it (patient, willing to wait). Price-out: a case whose bid falls below the fee for 6 steps (18 h)
leaves the active queue.
  C   priced-out and under-bid cases are dropped (refund; the ruling is never had)
  D   they wait in standby; a case activates when the fee falls to its bid, seated at the current fee;
      standby ends at the refund horizon (60 days), then the case refunds
Only the active queue drives the fee (rule C: 2.5% x backlog over a one-day target, halving per congested
week, never below the median of the last 100 cleared fees unless the active queue is empty).
"""
import math, random, statistics as st
from e9_fee_market import pois

def run(rule, scen, fee0, elast, seed, weeks=26, pool=200, per_slot_day=0.02, horizon_days=60):
    rnd = random.Random(seed)
    steps = weeks * 56
    lam0 = pool * per_slot_day / 8 * 0.8
    fee, mult = fee0, 1.0
    active, standby = [], []            # (arrival step, bid, under_since)
    cleared, ruled, dropped, fees = [fee0] * 20, [], 0, []
    cong = 0
    for t in range(steps):
        wk = t / 56
        d = (3.0 if 4 <= wk < 6 else 1.0) if scen == 'spike' else ((2.0 if wk >= 4 else 1.0) if scen == 'shift' else 1.0)
        for _ in range(pois(rnd, lam0 * d)):
            bid = fee * (rnd.uniform(1.1, 1.3) if rnd.random() < 0.7 else rnd.uniform(0.4, 0.9))
            if bid >= fee: active.append([t, bid, None])
            elif rule == 'D': standby.append([t, bid, None])
            else: dropped += 1
        mult += (min(3.0, (fee / fee0) ** elast) - mult) / 56
        cap = pool * per_slot_day / 8 * mult
        for _ in range(min(len(active), pois(rnd, cap))):
            a = active.pop(0)
            ruled.append((3 * fee, (t - a[0]) * 3 / 24)); cleared.append(fee)
        # price-out after 6 steps under water
        keep = []
        for a in active:
            if a[1] < fee:
                a[2] = t if a[2] is None else a[2]
                if t - a[2] >= 6:
                    if rule == 'D': standby.append([a[0], a[1], None])
                    else: dropped += 1
                    continue
            else: a[2] = None
            keep.append(a)
        active = keep
        if rule == 'D':
            standby.sort(key=lambda x: -x[1])
            still = []
            for s in standby:
                if s[1] >= fee: active.append([s[0], s[1], None])
                elif (t - s[0]) * 3 / 24 > horizon_days: dropped += 1
                else: still.append(s)
            standby = still
        ref = st.median(cleared[-100:]); n = len(active)
        T = max(1.0, cap * 8); x = max(-1.0, min(1.0, (n - T) / T))
        cong = cong + 1 if n > T else 0
        step = 0.025 * x / (2 ** (cong // 56) if x > 0 else 1)
        new = fee * (1 + step)
        if step < 0 and n > 0: new = max(new, min(fee, ref))
        fee = new; fees.append(fee)
    return ruled, dropped, fees

def summary(rule, scen, fee0, elast, seeds=10):
    pan, wait, share, vol = [], [], [], []
    for s in range(seeds):
        ruled, dropped, fees = run(rule, scen, fee0, elast, s)
        pan += [p for p, _ in ruled]; wait += [w for _, w in ruled]
        share.append(len(ruled) / max(1, len(ruled) + dropped))
        ch = [abs(math.log(fees[i + 8] / fees[i])) for i in range(0, len(fees) - 8, 8)]  # daily moves
        vol.append(st.mean(ch))
    pan.sort(); wait.sort()
    q = lambda v, x: v[min(len(v) - 1, int(x * len(v)))]
    return dict(med=q(pan, .5), p95=q(pan, .95), wait=q(wait, .5), wait95=q(wait, .95), ruled=st.mean(share), vol=st.mean(vol))

if __name__ == '__main__':
    for fee0 in [30, 100]:
        for scen in ['steady', 'spike', 'shift']:
            for elast in [0.3, 0.7]:
                for rule in 'CD':
                    r = summary(rule, scen, fee0, elast)
                    print(f"seat ${fee0:>3} {scen:6} e={elast} {rule}: ruled {r['ruled']*100:5.1f}% of escalations | panel median ${r['med']:>7,.0f} p95 ${r['p95']:>7,.0f} | wait med {r['wait']:5.1f}d p95 {r['wait95']:5.1f}d | daily fee move {r['vol']*100:4.1f}%", flush=True)
