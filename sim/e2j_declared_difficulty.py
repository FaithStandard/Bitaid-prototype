"""Experiment 2j — Declared difficulty (easy / ordinary / hard) as a self-betting menu.

Models:
  - True case difficulty diff ~ Beta(1.2, 5), bucketed into:
      easy:     diff < 0.15
      ordinary: 0.15 <= diff < 0.30
      hard:     diff >= 0.30
  - Declared difficulty rules (per Opus's design note):
      easy:     base review rate; if overturned on appeal OR review, panel loses 2V case units.
      ordinary: base review rate; normal fee penalties on appeal, 2V units on review.
      hard:     2x base review rate; fee penalties halved on appeal; if all 3 review stages
                rate the case "easy", each member gets +1 momentum weight.
  - Honest arbitrators:
      Vote right with p = 0.5 + (acc - 0.5) * (1 - diff).
      Rate difficulty accurately with probability rate_acc (0.70 or 0.80); otherwise misrate.
      Compares: (a) today's rules, (b) honest using all 3 ratings with noise, and
      (c) honest rationally avoiding "easy" (mapping easy -> ordinary).
  - Smart 3-0 bloc (f = 0.20, N = 200):
      Tests every (target_bucket, declared_rating) strategy under rational appeal +
      unanimous-overturn refund + 3x30 staged review.
"""
import json
import math
import random

N = 200
FEE_T1 = 0.0002
FEE_T2_TOTAL = 7 * 1.25 * FEE_T1
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


def draw_diff_in(rng, target):
    while True:
        d = rng.betavariate(DIFF_ALPHA, DIFF_BETA)
        if bucket(d) == target:
            return d


def p_overturn_tier2(B):
    total = math.comb(N, 7)
    bloc_wins = sum(
        math.comb(B, k) * math.comb(N - B, 7 - k)
        for k in range(5, min(7, B) + 1)
    )
    return 1.0 - bloc_wins / total


def staged_review(rng, B, acc, diff, rate_acc=0.80):
    """Returns (overturned_2_3, all_stages_say_easy)."""
    p_honest = 0.5 + (acc - 0.5) * (1.0 - diff)
    true_b = bucket(diff)
    p_say_easy = rate_acc if true_b == "easy" else (1.0 - rate_acc) / 2.0

    pool = [False] * (B - 3) + [True] * (N - B)
    rng.shuffle(pool)
    overturned = True
    all_easy = True
    for s in range(3):
        panel = pool[s * 30 : (s + 1) * 30]
        yes = 0
        easy_votes = 0
        for h in panel:
            if h:
                if rng.random() < p_honest:
                    yes += 1
                if rng.random() < p_say_easy:
                    easy_votes += 1
        if yes < 20:
            overturned = False
        if easy_votes < 20:
            all_easy = False
    return overturned, all_easy


def sim_bloc_strategy(f, V, acc, target_b, declared, rate_acc=0.80, n_def=10000, seed=7):
    rng = random.Random(seed)
    B = int(round(N * f))
    p_ov = p_overturn_tier2(B)
    rational = (p_ov * V) > ((1.0 - p_ov) * FEE_T2_TOTAL)
    p_appeal = (1.0 - FRICTION) if rational else 0.0

    rr = base_review_rate(V)
    if declared == "hard":
        rr = min(1.0, 2.0 * rr)

    net_btc = 0.0
    caught_app = caught_rev = mom_flags = 0

    for _ in range(n_def):
        diff = draw_diff_in(rng, target_b)
        if rng.random() < p_appeal:
            b2 = sum(1 for x in rng.sample(range(N), 7) if x < B)
            if b2 < 5:
                caught_app += 1
                if declared == "easy":
                    net_btc -= 3 * (2.0 * V)
                elif declared == "hard":
                    net_btc -= 3 * (2.0 * FEE_T1)  # penalties halved
                else:
                    net_btc -= 3 * (4.0 * FEE_T1)
                continue

        if rng.random() < rr:
            ov, all_easy = staged_review(rng, B, acc, diff, rate_acc=rate_acc)
            if declared == "hard" and all_easy:
                mom_flags += 1
            if ov:
                caught_rev += 1
                net_btc -= 3 * (2.0 * V)
                continue

        net_btc += V

    return {
        "net_V": round((net_btc / n_def) / V, 4),
        "p_app": round(caught_app / n_def, 3),
        "p_rev": round(caught_rev / n_def, 3),
        "p_hard_flag": round(mom_flags / n_def, 3),
    }


def sim_honest_income(V, acc, rate_acc, mode="today", n_cases=40000, seed=11):
    """Per-seat expected profit (in fees) for an honest arbitrator on a 3-seat panel."""
    rng = random.Random(seed)
    pnl = 0.0
    effort = 0.3 * FEE_T1
    unit_losses = 0

    for _ in range(n_cases):
        diff = rng.betavariate(DIFF_ALPHA, DIFF_BETA)
        p_right = 0.5 + (acc - 0.5) * (1.0 - diff)
        true_b = bucket(diff)

        # Panel of 3 honest arbitrators
        votes = [rng.random() < p_right for _ in range(3)]
        wrong_panel = sum(votes) < 2  # majority got it wrong

        # Seat 0's rating
        if mode == "today":
            declared = "ordinary"
        else:
            if rng.random() < rate_acc:
                declared = true_b
            else:
                others = [x for x in ("easy", "ordinary", "hard") if x != true_b]
                declared = rng.choice(others)
            if mode == "avoid_easy" and declared == "easy":
                declared = "ordinary"

        pnl -= effort
        if wrong_panel:
            # Assume wrong honest panel is appealed with prob 0.95 and overturned on tier 2
            if rng.random() < 0.95:
                if not votes[0]:
                    if mode != "today" and declared == "easy":
                        pnl -= 2.0 * V
                        unit_losses += 1
                    elif mode != "today" and declared == "hard":
                        pnl -= 2.0 * FEE_T1
                    else:
                        pnl -= 4.0 * FEE_T1
                else:
                    pnl += FEE_T1  # vindicated dissenter
            else:
                pnl += FEE_T1 if not votes[0] else -2.0 * FEE_T1
        else:
            # Panel got it right
            if votes[0]:
                pnl += FEE_T1
            else:
                pen = 1.0 * FEE_T1 if (mode != "today" and declared == "hard") else 2.0 * FEE_T1
                pnl -= pen

    return {
        "profit_in_fees": round((pnl / n_cases) / FEE_T1, 3),
        "unit_loss_rate": round(unit_losses / n_cases, 5),
    }


if __name__ == "__main__":
    out = {"bloc": {}, "honest": {}}

    print("=== 1. Smart 3-0 Bloc best response (f=0.20, acc=0.95, rate_acc=0.80) ===")
    print(f"{'V (BTC)':>7} {'target':>8} | {'decl=easy':>10} {'decl=ord':>10} {'decl=hard':>10} {'hard_flag':>10}")
    for V in (0.01, 0.1, 1.0):
        for tgt in ("easy", "ordinary", "hard"):
            row = {}
            for decl in ("easy", "ordinary", "hard"):
                row[decl] = sim_bloc_strategy(0.20, V, 0.95, tgt, decl, rate_acc=0.80)
            out["bloc"][f"V={V} tgt={tgt}"] = row
            print(
                f"{V:7.3f} {tgt:>8} | {row['easy']['net_V']:+10.4f} {row['ordinary']['net_V']:+10.4f} "
                f"{row['hard']['net_V']:+10.4f} {row['hard']['p_hard_flag']:10.3f}"
            )

    print("\n=== 2. Honest arbitrator income (in fees/case, acc=0.95) ===")
    print(f"{'V (BTC)':>7} {'rate_acc':>8} | {'today':>9} {'use_easy':>11} {'avoid_easy':>11} {'unit_loss':>10}")
    for V in (0.01, 0.1, 1.0):
        for ra in (0.70, 0.80):
            r_t = sim_honest_income(V, 0.95, ra, mode="today")
            r_u = sim_honest_income(V, 0.95, ra, mode="use_easy")
            r_a = sim_honest_income(V, 0.95, ra, mode="avoid_easy")
            out["honest"][f"V={V} rate_acc={ra}"] = {"today": r_t, "use_easy": r_u, "avoid_easy": r_a}
            print(
                f"{V:7.3f} {ra:8.2f} | {r_t['profit_in_fees']:+9.3f} {r_u['profit_in_fees']:+11.3f} "
                f"{r_a['profit_in_fees']:+11.3f} {r_u['unit_loss_rate']:10.5f}"
            )

    json.dump(out, open("e2j_results.json", "w"), indent=1)

