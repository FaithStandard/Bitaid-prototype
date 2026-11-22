"""Experiment 2g — conditional 3-0 bloc defection with correlated review errors.

Pool of N = 200 arbitrators; a bloc holds fraction f (B = round(N * f)).
The bloc defects ONLY when it holds all 3 seats of a tier-1 panel (unanimous 3-0);
otherwise its members vote honestly (zero extra gain, zero extra penalty).

For each case value V (in BTC):
  - Tier-1 seat fee is 0.0002 BTC (Specification Appendix A / B.7).
  - The losing party appeals with probability 0.5 to a 7-seat tier 2 drawn from N
    without replacement; tier 2 overturns unless the bloc holds >= 5 of 7 seats.
    If overturned on appeal, each of the 3 bloc members pays 4x the tier-1 fee.
  - If the wrong verdict stands, it is drawn for review at the Specification's base
    rate for V (5% <= 0.01, 10% <= 0.1, 20% <= 1.0, 40% > 1.0 BTC; no 40% split rate).
  - Staged review: three independent 30-seat panels drawn without replacement from
    the remaining N - 3 arbitrators. Case difficulty diff ~ Beta(1.2, 5) (as in
    sim_arbitration.py), so honest reviewers' errors are correlated on hard cases:
    each honest reviewer is right with probability 0.5 + (acc - 0.5) * (1 - diff).
    Bloc reviewers vote to keep the verdict.
  - Overturn needs >= 20/30 at every stage (2/3); each bloc member loses its case
    unit (2V). Entry-bond seizure (0.1 BTC) + expulsion (losing `future` BTC of
    remaining earnings) needs >= 24/30 (80%) at every stage.
  - If the wrong verdict survives, the bloc keeps `bribe * V` (default bribe = 1.0).
"""
import json
import os
import math
import random

# the losing party's appeal probability (APPEAL=0.8 python3 e2g_smart_bloc.py)
APPEAL = float(os.environ.get("APPEAL", "0.5"))

N = 200
FEE_T1 = 0.0002      # BTC per seat (Appendix A / B.7)
ENTRY_BOND = 0.1     # BTC (Appendix A)
DIFF_ALPHA = 1.2     # Beta(1.2, 5), matching sim_arbitration.py
DIFF_BETA = 5.0


def base_review_rate(V):
    if V <= 0.01:
        return 0.05
    if V <= 0.1:
        return 0.10
    if V <= 1.0:
        return 0.20
    return 0.40


def staged_review(rng, B, acc):
    """Returns (overturned_2_3, expelled_80) for three 30-seat panels from N - 3."""
    diff = rng.betavariate(DIFF_ALPHA, DIFF_BETA)
    p_honest = 0.5 + (acc - 0.5) * (1.0 - diff)
    rem_bloc = B - 3
    rem_honest = N - B
    pool = [False] * rem_bloc + [True] * rem_honest
    rng.shuffle(pool)
    overturned = True
    expelled = True
    for s in range(3):
        panel = pool[s * 30 : (s + 1) * 30]
        yes = sum(1 for h in panel if h and rng.random() < p_honest)
        if yes < 20:
            return False, False
        if yes < 24:
            expelled = False
    return overturned, expelled


def sim_defections(f, V, acc, future, bribe=1.0, rr_override=None, n_def=20000, seed=7):
    rng = random.Random(seed)
    B = int(round(N * f))
    def_rate = math.comb(B, 3) / math.comb(N, 3)
    rr = base_review_rate(V) if rr_override is None else rr_override

    caught_appeal = 0
    caught_review = 0
    expelled_cnt = 0
    net_btc = 0.0

    for _ in range(n_def):
        # 1. Appeal to 7-seat tier 2 (prob 0.5)
        if rng.random() < APPEAL:
            # Draw 7 from N without replacement; bloc holds B seats
            b2 = sum(1 for x in rng.sample(range(N), 7) if x < B)
            if b2 < 5:
                caught_appeal += 1
                net_btc -= 3 * (4.0 * FEE_T1)
                continue

        # 2. Review draw at base rate (unanimous -> no 40% split rate)
        if rng.random() < rr:
            overturned, expelled = staged_review(rng, B, acc)
            if overturned:
                caught_review += 1
                net_btc -= 3 * (2.0 * V)
                if expelled:
                    expelled_cnt += 1
                    net_btc -= 3 * (ENTRY_BOND + future)
                continue

        # 3. Wrong verdict stood
        net_btc += bribe * V

    return {
        "defection_rate": round(def_rate, 5),
        "p_caught_appeal": round(caught_appeal / n_def, 4),
        "p_caught_review": round(caught_review / n_def, 4),
        "p_caught_total": round((caught_appeal + caught_review) / n_def, 4),
        "p_expelled": round(expelled_cnt / n_def, 4),
        "net_per_defection_V": round((net_btc / n_def) / V, 4),
    }


def min_review_rate_to_deter(V, acc, future, f=0.20, bribe=1.0, n_def=15000, seed=19):
    """Binary search for the lowest base review rate in [0, 1] making net <= 0 at f."""
    if sim_defections(f, V, acc, future, bribe=bribe, rr_override=1.0, n_def=n_def, seed=seed)["net_per_defection_V"] > 0:
        return None  # even 100% review does not deter
    lo, hi = 0.0, 1.0
    for _ in range(14):
        mid = (lo + hi) / 2.0
        r = sim_defections(f, V, acc, future, bribe=bribe, rr_override=mid, n_def=n_def, seed=seed)
        if r["net_per_defection_V"] <= 0:
            hi = mid
        else:
            lo = mid
    return round(hi, 3)


if __name__ == "__main__":
    out = {"grid": {}, "min_rr_f20": {}}
    fs = [0.10, 0.15, 0.20, 0.25, 0.33]
    Vs = [0.001, 0.01, 0.1, 1.0]
    accs = [0.85, 0.95]
    futures = [0.0, 0.1]

    print(f"=== Experiment 2g: Smart 3-0 Bloc (N=200, bribe=1.0*V, appeal={APPEAL}) ===")
    for acc in accs:
        for future in futures:
            print(f"\n-- acc={acc:.2f}, future={future:.1f} BTC --")
            print(f"{'f':>5} {'V (BTC)':>8} {'rr':>5} {'def_rate':>9} {'P(caught)':>10} {'P(rev)':>8} {'net (V)':>10}")
            for V in Vs:
                for f in fs:
                    r = sim_defections(f, V, acc, future)
                    key = f"f={f:.2f} V={V} acc={acc:.2f} future={future}"
                    out["grid"][key] = r
                    print(
                        f"{f:5.2f} {V:8.3f} {base_review_rate(V):5.2f} "
                        f"{r['defection_rate']:9.5f} {r['p_caught_total']:10.4f} "
                        f"{r['p_caught_review']:8.4f} {r['net_per_defection_V']:+10.4f}"
                    )

    print("\n=== Lowest unanimous base review rate making net <= 0 at f = 0.20 ===")
    print(f"{'V (BTC)':>8} {'acc':>6} {'future':>8} {'spec_rr':>8} {'min_rr':>8}")
    for V in Vs:
        for acc in accs:
            for future in futures:
                mr = min_review_rate_to_deter(V, acc, future, f=0.20)
                key = f"V={V} acc={acc:.2f} future={future}"
                out["min_rr_f20"][key] = mr
                mr_s = f"{mr:.3f}" if mr is not None else ">1.000"
                print(f"{V:8.3f} {acc:6.2f} {future:8.1f} {base_review_rate(V):8.2f} {mr_s:>8}")

    json.dump(out, open("e2g_results.json", "w"), indent=1)

