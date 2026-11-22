"""Experiment 3b — slot-opening rules under the v6.0 EIP-1559 fee market (market.rs).

Faithfully implements market.rs's integer fee adjustment:
  - Step every 18 blocks (~3 h; 8 steps/day, 56 steps/week, 2,912 steps/year).
  - x = clamp((B - T) / T, -1, 1) in ppm, where B is active backlog and T is one
    day of pool capacity.
  - Rising (B > T): +2.5% * x, halving for each further consecutive week (56 steps)
    with B > T.
  - Falling (B < T): stops at min(fee, reference) unless active queue is empty,
    where reference is the lower median of the last 100 cleared fees.

Compares two slot-opening rules over 1 year (52 weeks):
  (a) queue > 0 for 1,008 consecutive blocks (56 steps) -> open max(1, int(pool * 0.0006))
  (b) backlog > T for 1,008 consecutive blocks (56 steps) -> open max(1, int(pool * 0.0006))

Tests three attackers (pool0 = 200, T0 = 20 cases/day, fee0 = 20,000 sats):
  1. trickle     keeps 1 fillable case waiting in the active queue at all times
                 (re-posts whenever its case clears, paying 3 * fee per cleared case).
  2. unfillable  posts 1 case too valuable for any arbitrator to take (sits in the
                 active queue without clearing until its 30-day lock expires, then
                 re-posts; pays 0 panel fees, only locks escrow).
  3. flood       keeps B = T + 1 active cases in the queue at all times, topping up
                 and replacing cleared cases at the prevailing fee.
"""
import collections
import json
import random

STEP_BLOCKS = 18
STEP_PPM = 25_000
WEEK_STEPS = 1008 // STEP_BLOCKS  # 56 steps = 1 week
YEAR_STEPS = 52 * WEEK_STEPS      # 2,912 steps = 52 weeks
REF_CASES = 100
PPM = 1_000_000


class Market:
    def __init__(self, fee0):
        self.fee = max(1, int(fee0))
        self.cleared = collections.deque([self.fee], maxlen=REF_CASES)
        self.over_steps = 0

    def reference(self):
        v = sorted(self.cleared)
        return v[(len(v) - 1) // 2]

    def clear_case(self):
        self.cleared.append(self.fee)

    def step(self, B, T):
        t = max(1, int(T))
        b = int(B)
        x = max(-PPM, min(PPM, ((b - t) * PPM) // t))
        self.over_steps = self.over_steps + 1 if b > t else 0
        step = (STEP_PPM * x) // PPM
        if step > 0:
            halvings = min((self.over_steps - 1) // WEEK_STEPS, 30)
            step >>= halvings
        delta = (self.fee * step) // PPM
        if delta == 0 and step != 0:
            delta = 1 if step > 0 else -1
        new = max(1, self.fee + delta)
        if step < 0 and b > 0:
            new = max(new, min(self.fee, self.reference()))
        self.fee = new


def run(rule, attacker, pool0=200, cap_per_slot_day=0.10, fee0=20_000, seed=11):
    """Simulates 1 year (2,912 steps). Returns seats opened, total fees paid, and fee path."""
    rng = random.Random(seed)
    m = Market(fee0)
    pool = pool0
    q_fillable = 0
    q_unfillable = 0
    streak = 0
    seats_opened = 0
    fees_paid_sats = 0
    path = {}

    for step in range(YEAR_STEPS):
        T = max(1, int(round(pool * cap_per_slot_day)))  # 1 day of capacity
        cap_step = T / 8.0                               # expected cases cleared per 3h step

        # Attacker maintains its target queue state at the start of each step
        if attacker == "trickle":
            if q_fillable == 0:
                q_fillable = 1
        elif attacker == "unfillable":
            q_unfillable = 1
        elif attacker == "flood":
            if q_fillable < T + 1:
                q_fillable = T + 1

        B = q_fillable + q_unfillable

        # Slot-opening trigger checked on the active queue
        cond = (B > 0) if rule == "a_queue_gt_0" else (B > T)
        streak = streak + 1 if cond else 0
        if streak >= WEEK_STEPS:
            add = max(1, int(pool * 0.0006))
            pool += add
            seats_opened += add
            streak = 0

        # Fee adjustment (exact market.rs rule)
        m.step(B, T)

        # Record fee milestones (in multiples of fee0)
        if step in (0, 4 * WEEK_STEPS, 13 * WEEK_STEPS, 26 * WEEK_STEPS, YEAR_STEPS - 1):
            wk = step // WEEK_STEPS
            path[f"w{wk}"] = round(m.fee / fee0, 2)

        # Pool clears fillable cases (deterministic floor + fractional Bernoulli for clean seeding)
        clear_n = int(cap_step) + (1 if rng.random() < (cap_step - int(cap_step)) else 0)
        served = min(q_fillable, clear_n)
        for _ in range(served):
            q_fillable -= 1
            m.clear_case()
            fees_paid_sats += 3 * m.fee  # 3 seats per tier-1 panel

    path["peak"] = round(max(path.values()), 2)
    return {
        "seats_opened": seats_opened,
        "total_fees_btc": round(fees_paid_sats / 1e8, 4),
        "total_fees_in_t1_panels": round(fees_paid_sats / (3 * fee0), 1),
        "fee_path_x_fee0": path,
    }


if __name__ == "__main__":
    out = {}
    print("=== Experiment 3b: Slot-opening rules under market.rs (1 year, pool0=200, T0=20/d, fee0=20k sat) ===")
    print(
        f"{'rule':14} {'attacker':11} {'seats':>6} {'paid (BTC)':>11} {'paid (panels)':>14} "
        f"{'w0':>5} {'w4':>6} {'w13':>6} {'w26':>6} {'w51':>6}"
    )
    for rule in ("a_queue_gt_0", "b_backlog_gt_T"):
        for attacker in ("trickle", "unfillable", "flood"):
            r = run(rule, attacker)
            out[f"{rule} | {attacker}"] = r
            p = r["fee_path_x_fee0"]
            print(
                f"{rule:14} {attacker:11} {r['seats_opened']:6d} {r['total_fees_btc']:11.4f} "
                f"{r['total_fees_in_t1_panels']:14.1f} "
                f"{p['w0']:5.2f} {p['w4']:6.2f} {p['w13']:6.2f} {p['w26']:6.2f} {p['w51']:6.2f}"
            )
    json.dump(out, open("e3b_results.json", "w"), indent=1)

