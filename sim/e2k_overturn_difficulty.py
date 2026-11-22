"""Experiment 2k — Difficulty judged by the overturning panel (Tier 2 on appeal or review).

When a unanimous tier-1 verdict is overturned on appeal by a 7-seat tier 2, the 7 seats
also rate the case's difficulty (easy / ordinary / hard) by majority (>= 4 of 7).
  - Rated "easy":     each overturned tier-1 member loses `easy_seizure * V` (default 2V;
                      also tested capped at 1V and 0.5V) instead of fee penalties.
  - Rated "ordinary"
    or "hard":        normal fee penalties (4x fee * momentum multiplier) as today.

Models:
  1. Smart 3-0 bloc choosing which difficulty bucket to defect on (easy / ordinary / hard),
     with unanimous-overturn refund, rational appeal (5% friction), and all-case 50-case
     momentum D (as in e2h).
  2. Honest arbitrator income when honest overturning panels rate difficulty correctly
     70% or 80% of the time (compared against today's rules).
  3. Captured tier-2 attack (bloc holds >= 5 of 7 on tier 2) overturning an honest
     unanimous tier-1 verdict and rating it "easy" to seize honest units — at both
     normal frivolous appeal rate (3%) and worst-case adversarial appeal rate (100%),
     with seizure caps of 2V, 1V, and 0.5V per member.
"""
import json
import math
import random

N = 200
FEE_T1 = 0.0002
FEE_T2_TOTAL = 7 * 1.25 * FEE_T1
ENTRY_BOND = 0.1
DIFF_ALPHA = 1.2
DIFF_BETA = 5.0
FRICTION = 0.05


def base_review_rate(V):
    if V <= 0.01:
        return 0.05
    if V <= 0.1:
        return 0.10
    if V <= 1.0:
        return 0.20
    return 0.40


def bucket(diff):
    if diff < 0.15:
        return "easy"
    if diff < 0.30:
        return "ordinary"
    return "hard"


def p_overturn_tier2(B):
    total = math.comb(N, 7)
    bloc_wins = sum(
        math.comb(B, k) * math.comb(N - B, 7 - k)
        for k in range(5, min(7, B) + 1)
    )
    return 1.0 - bloc_wins / total


def tier2_rates_easy(rng, n_honest, true_b, rate_acc):
    """Majority (>= 4 of 7) rates the case 'easy'; bloc members on tier 2 never vote 'easy'."""
    p_easy = rate_acc if true_b == "easy" else (1.0 - rate_acc) / 2.0
    votes = sum(1 for _ in range(n_honest) if rng.random() < p_easy)
    return votes >= 4


def staged_review(rng, B, acc, diff):
    """Three 30-seat panels from N - 3; >= 20/30 overturns, >= 24/30 expels."""
    p_honest = 0.5 + (acc - 0.5) * (1.0 - diff)
    pool = [False] * (B - 3) + [True] * (N - B)
    rng.shuffle(pool)
    expelled = True
    for s in range(3):
        panel = pool[s * 30 : (s + 1) * 30]
        yes = sum(1 for h in panel if h and rng.random() < p_honest)
        if yes < 20:
            return False, False
        if yes < 24:
            expelled = False
    return True, expelled


def sim_bloc(f, V, acc, target_b, rate_acc=0.80, easy_seizure=2.0, n_cases=100000, seed=7):
    """Part 1: Smart 3-0 bloc defecting only on `target_b` cases, with all-case 50-case hist."""
    rng = random.Random(seed)
    B = int(round(N * f))
    p_ov = p_overturn_tier2(B)
    rational = (p_ov * V) > ((1.0 - p_ov) * FEE_T2_TOTAL)
    p_appeal = (1.0 - FRICTION) if rational else 0.0
    rr = base_review_rate(V)

    D = [0.0] * N
    hist = [[] for _ in range(N)]
    open_wrong = {}  # case_id -> (seats, diff)
    pool_rate = 0.05

    defections = caught_app_easy = caught_app_fee = caught_rev = caught_mom = 0
    net_btc = 0.0

    for c in range(n_cases):
        diff = rng.betavariate(DIFF_ALPHA, DIFF_BETA)
        true_b = bucket(diff)
        seats = rng.sample(range(N), 3)
        for a in seats:
            hist[a] = (hist[a] + [c])[-50:]

        is_bloc_3 = all(a < B for a in seats)
        if not (is_bloc_3 and true_b == target_b):
            # Honest play
            p_err = 1.0 - (0.5 + (acc - 0.5) * (1.0 - diff))
            for a in seats:
                if rng.random() < p_err:
                    D[a] += 0.5
                    pool_rate = 0.999 * pool_rate + 0.001 * 0.5
                else:
                    pool_rate *= 0.999
                D[a] = max(0.0, D[a] * 0.99 - 1.5 * pool_rate)
            continue

        # 3-0 bloc defection on target_b
        defections += 1
        if rng.random() < p_appeal:
            b2 = sum(1 for x in rng.sample(range(N), 7) if x < B)
            if b2 < 5:
                rated_easy = tier2_rates_easy(rng, 7 - b2, true_b, rate_acc)
                if rated_easy:
                    caught_app_easy += 1
                    net_btc -= 3 * (easy_seizure * V)
                else:
                    caught_app_fee += 1
                for a in seats:
                    if not rated_easy:
                        mult = min(2.0 ** D[a], 32.0)
                        net_btc -= 4.0 * FEE_T1 * mult
                    D[a] += 1.0
                    pool_rate = 0.999 * pool_rate + 0.001 * 1.0
                    D[a] = max(0.0, D[a] * 0.99 - 1.5 * pool_rate)
                    if D[a] >= 3.0:
                        for cid in list(hist[a]):
                            if cid in open_wrong:
                                _, d_old = open_wrong.pop(cid)
                                ov, exp = staged_review(rng, B, acc, d_old)
                                if ov:
                                    caught_mom += 1
                                    net_btc -= 3 * (2.0 * V)
                                    if exp:
                                        net_btc -= 3 * ENTRY_BOND
                        D[a] = 0.0
                continue

        # Stood after appeal -> base review draw
        if rng.random() < rr:
            ov, exp = staged_review(rng, B, acc, diff)
            if ov:
                caught_rev += 1
                net_btc -= 3 * (2.0 * V)
                if exp:
                    net_btc -= 3 * ENTRY_BOND
                continue

        net_btc += V
        open_wrong[c] = (tuple(seats), diff)
        for a in seats:
            pool_rate *= 0.999
            D[a] = max(0.0, D[a] * 0.99 - 1.5 * pool_rate)

    denom = max(defections, 1)
    return {
        "defections": defections,
        "net_V": round((net_btc / denom) / V, 4),
        "p_app_easy": round(caught_app_easy / denom, 4),
        "p_app_fee": round(caught_app_fee / denom, 4),
        "p_rev": round((caught_rev + caught_mom) / denom, 4),
    }


def sim_honest_income(V, acc, rate_acc, easy_seizure=2.0, n_cases=100000, seed=11):
    """Part 2: Honest arbitrator per-case profit (in fees) under overturn-rated difficulty."""
    rng = random.Random(seed)
    effort = 0.3 * FEE_T1
    pnl_today = 0.0
    pnl_new = 0.0
    unanimous_wrong = 0
    unit_seized = 0

    for _ in range(n_cases):
        diff = rng.betavariate(DIFF_ALPHA, DIFF_BETA)
        true_b = bucket(diff)
        p_right = 0.5 + (acc - 0.5) * (1.0 - diff)
        votes = [rng.random() < p_right for _ in range(3)]
        n_right = sum(votes)

        pnl_today -= effort
        pnl_new -= effort

        if n_right == 0:
            # Honest unanimous 3-0 error
            unanimous_wrong += 1
            if rng.random() < (1.0 - FRICTION):
                # Overturned on tier 2
                pnl_today -= 4.0 * FEE_T1
                if tier2_rates_easy(rng, 7, true_b, rate_acc):
                    unit_seized += 1
                    pnl_new -= easy_seizure * V
                else:
                    pnl_new -= 4.0 * FEE_T1
            else:
                pnl_today += FEE_T1
                pnl_new += FEE_T1
        elif n_right == 1:
            # Split 2-1 wrong (not unanimous -> normal rules)
            if rng.random() < (1.0 - FRICTION):
                delta = FEE_T1 if votes[0] else -4.0 * FEE_T1
            else:
                delta = -2.0 * FEE_T1 if votes[0] else FEE_T1
            pnl_today += delta
            pnl_new += delta
        else:
            # Honest panel got it right (2-1 or 3-0)
            delta = FEE_T1 if votes[0] else -2.0 * FEE_T1
            pnl_today += delta
            pnl_new += delta

    return {
        "today_fees": round((pnl_today / n_cases) / FEE_T1, 3),
        "new_fees": round((pnl_new / n_cases) / FEE_T1, 3),
        "p_unanimous_wrong": round(unanimous_wrong / n_cases, 5),
        "p_unit_seized": round(unit_seized / n_cases, 5),
    }


def sim_captured_t2_attack(f, V, p_appeal_honest, cap_V):
    """Part 3: Analytical exact expected cost to an honest arbitrator per honest unanimous case
    when a captured tier 2 (>= 5 of 7 bloc) overturns and rates it 'easy'."""
    B = int(round(N * f))
    p_cap_t2 = 1.0 - p_overturn_tier2(B)
    p_hit = p_appeal_honest * p_cap_t2
    cost_btc = p_hit * (cap_V * V)
    return {
        "p_captured_t2": round(p_cap_t2, 5),
        "p_hit_per_case": round(p_hit, 6),
        "cost_in_fees": round(cost_btc / FEE_T1, 3),
        "cost_in_V": round(p_hit * cap_V, 5),
    }


if __name__ == "__main__":
    out = {"part1_bloc": {}, "part2_honest": {}, "part3_captured_t2": {}}

    print("=== 1. Smart 3-0 Bloc net (V) by target bucket (overturn-rated easy -> 2V seizure, rate_acc=0.80) ===")
    print(f"{'f':>4} {'acc':>5} {'V (BTC)':>7} | {'tgt=easy':>10} {'tgt=ord':>10} {'tgt=hard':>10} | {'easy P(app_2V)':>14}")
    for f in (0.20, 0.25):
        for acc in (0.85, 0.95):
            for V in (0.01, 0.1, 1.0):
                row = {}
                for tgt in ("easy", "ordinary", "hard"):
                    runs = [sim_bloc(f, V, acc, tgt, rate_acc=0.80, easy_seizure=2.0, seed=7 + s) for s in range(3)]
                    row[tgt] = {
                        "net_V": round(sum(r["net_V"] for r in runs) / 3, 4),
                        "p_app_easy": round(sum(r["p_app_easy"] for r in runs) / 3, 4),
                        "p_rev": round(sum(r["p_rev"] for r in runs) / 3, 4),
                    }
                out["part1_bloc"][f"f={f:.2f} acc={acc:.2f} V={V}"] = row
                print(
                    f"{f:4.2f} {acc:5.2f} {V:7.3f} | {row['easy']['net_V']:+10.4f} "
                    f"{row['ordinary']['net_V']:+10.4f} {row['hard']['net_V']:+10.4f} | "
                    f"{row['easy']['p_app_easy']:14.4f}"
                )

    print("\n=== 2. Honest arbitrator income (in fees/case, no bloc) ===")
    print(f"{'acc':>5} {'V (BTC)':>7} {'rate_acc':>8} | {'today':>8} {'cap=2V':>9} {'cap=1V':>9} {'cap=0.5V':>9} {'P(seized)':>10}")
    for acc in (0.85, 0.95):
        for V in (0.01, 0.1, 1.0):
            for ra in (0.70, 0.80):
                r2 = sim_honest_income(V, acc, ra, easy_seizure=2.0)
                r1 = sim_honest_income(V, acc, ra, easy_seizure=1.0)
                r05 = sim_honest_income(V, acc, ra, easy_seizure=0.5)
                out["part2_honest"][f"acc={acc:.2f} V={V} ra={ra:.2f}"] = {
                    "today": r2["today_fees"],
                    "cap_2V": r2["new_fees"],
                    "cap_1V": r1["new_fees"],
                    "cap_0.5V": r05["new_fees"],
                    "p_unit_seized": r2["p_unit_seized"],
                }
                print(
                    f"{acc:5.2f} {V:7.3f} {ra:8.2f} | {r2['today_fees']:+8.3f} "
                    f"{r2['new_fees']:+9.3f} {r1['new_fees']:+9.3f} {r05['new_fees']:+9.3f} "
                    f"{r2['p_unit_seized']:10.5f}"
                )

    print("\n=== 3. Captured Tier 2 (5/7 bloc) attacking honest unanimous verdicts ===")
    print(f"{'f':>4} {'p_app':>6} {'V (BTC)':>7} {'P(5/7)':>8} | {'cap=2V (fees)':>13} {'cap=1V (fees)':>13} {'cap=0.5V (fees)':>15}")
    for f in (0.20, 0.25):
        for p_app in (0.03, 1.0):
            for V in (0.01, 0.1, 1.0):
                c2 = sim_captured_t2_attack(f, V, p_app, 2.0)
                c1 = sim_captured_t2_attack(f, V, p_app, 1.0)
                c05 = sim_captured_t2_attack(f, V, p_app, 0.5)
                out["part3_captured_t2"][f"f={f:.2f} p_app={p_app} V={V}"] = {
                    "p_captured_t2": c2["p_captured_t2"],
                    "cap_2V_fees": c2["cost_in_fees"],
                    "cap_1V_fees": c1["cost_in_fees"],
                    "cap_0.5V_fees": c05["cost_in_fees"],
                }
                print(
                    f"{f:4.2f} {p_app:6.2f} {V:7.3f} {c2['p_captured_t2']:8.5f} | "
                    f"{c2['cost_in_fees']:13.2f} {c1['cost_in_fees']:13.2f} {c05['cost_in_fees']:15.2f}"
                )

    json.dump(out, open("e2k_results.json", "w"), indent=1)

