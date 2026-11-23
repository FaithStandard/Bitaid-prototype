"""Experiment 2h — (1) all-case 50-case hist window for momentum review, and
(2) staged-review power curve P(overturn | drawn) by reviewer accuracy and bloc share.
"""
import json
import math
import os
import random

# RULE=gated: the staged review adopted from e2l (first panel at 15 of 30 to go on, the first two at 30
# of 60 for the third to sit, overturn at 60 of 90 pooled, expulsion at 72 of 90); default: three
# stages each at 20 of 30 (expulsion at 24 of 30 each)
RULE = os.environ.get("RULE", "current")

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


def p_overturn_tier2(B):
    total = math.comb(N, 7)
    bloc_wins = sum(
        math.comb(B, k) * math.comb(N - B, 7 - k)
        for k in range(5, min(7, B) + 1)
    )
    return 1.0 - bloc_wins / total


def staged_review(rng, B, acc, correlated=True):
    """Three 30-seat panels drawn without replacement from N - 3; >= 20/30 overturns, >= 24/30 expels."""
    if correlated:
        diff = rng.betavariate(DIFF_ALPHA, DIFF_BETA)
        p_honest = 0.5 + (acc - 0.5) * (1.0 - diff)
    else:
        p_honest = acc
    pool = [False] * (B - 3) + [True] * (N - B)
    rng.shuffle(pool)
    if RULE == "gated":
        tot = 0
        for s in range(3):
            panel = pool[s * 30 : (s + 1) * 30]
            tot += sum(1 for h in panel if h and rng.random() < p_honest)
            if (s == 0 and tot < 15) or (s == 1 and tot < 30):
                return False, False
        return tot >= 60, tot >= 72
    expelled = True
    for s in range(3):
        panel = pool[s * 30 : (s + 1) * 30]
        yes = sum(1 for h in panel if h and rng.random() < p_honest)
        if yes < 20:
            return False, False
        if yes < 24:
            expelled = False
    return True, expelled


def sim_all_hist(f, V, acc, future=0.0, bribe=1.0, n_cases=100000, seed=7):
    """Same as e2g with momentum, but hist[a] tracks ALL last 50 cases served by a."""
    rng = random.Random(seed)
    B = int(round(N * f))
    p_ov = p_overturn_tier2(B)
    rational = (p_ov * V) > ((1.0 - p_ov) * FEE_T2_TOTAL)
    p_appeal = (1.0 - FRICTION) if rational else 0.0
    rr = base_review_rate(V)

    D = [0.0] * N
    hist = [[] for _ in range(N)]
    open_wrong = {}
    pool_rate = 0.05

    defections = caught_appeal = caught_review = caught_momentum = 0
    net_btc = 0.0

    for c in range(n_cases):
        seats = rng.sample(range(N), 3)
        for a in seats:
            hist[a] = (hist[a] + [c])[-50:]

        if not all(a < B for a in seats):
            p_err = 1.0 - acc
            for a in seats:
                if rng.random() < p_err:
                    w = 0.5
                    D[a] += w
                    pool_rate = 0.999 * pool_rate + 0.001 * w
                else:
                    pool_rate *= 0.999
                D[a] = max(0.0, D[a] * 0.99 - 1.5 * pool_rate)
            continue

        defections += 1
        if rng.random() < p_appeal:
            b2 = sum(1 for x in rng.sample(range(N), 7) if x < B)
            if b2 < 5:
                caught_appeal += 1
                for a in seats:
                    mult = min(2.0 ** D[a], 32.0)
                    net_btc -= 4.0 * FEE_T1 * mult
                    D[a] += 1.0
                    pool_rate = 0.999 * pool_rate + 0.001 * 1.0
                    D[a] = max(0.0, D[a] * 0.99 - 1.5 * pool_rate)
                    if D[a] >= 3.0:
                        for cid in list(hist[a]):
                            if cid in open_wrong:
                                open_wrong.pop(cid)
                                ov, exp = staged_review(rng, B, acc, correlated=True)
                                if ov:
                                    caught_momentum += 1
                                    net_btc -= 3 * (2.0 * V)
                                    if exp:
                                        net_btc -= 3 * (ENTRY_BOND + future)
                        D[a] = 0.0
                continue

        if rng.random() < rr:
            ov, exp = staged_review(rng, B, acc, correlated=True)
            if ov:
                caught_review += 1
                net_btc -= 3 * (2.0 * V)
                if exp:
                    net_btc -= 3 * (ENTRY_BOND + future)
                continue

        net_btc += bribe * V
        open_wrong[c] = tuple(seats)
        for a in seats:
            pool_rate *= 0.999
            D[a] = max(0.0, D[a] * 0.99 - 1.5 * pool_rate)

    denom = max(defections, 1)
    return {
        "defections": defections,
        "p_caught_momentum": round(caught_momentum / denom, 4),
        "p_caught_review": round(caught_review / denom, 4),
        "net_per_defection_V": round((net_btc / denom) / V, 4),
    }


def power_curve(fs=(0.10, 0.20, 0.25), accs=(0.80, 0.85, 0.90, 0.95, 0.97, 0.99), trials=20000, seed=13):
    rng = random.Random(seed)
    res = {}
    for corr_label, corr in [("correlated_beta", True), ("flat_acc", False)]:
        res[corr_label] = {}
        for f in fs:
            B = int(round(N * f))
            row = {}
            for acc in accs:
                ov_cnt = 0
                exp_cnt = 0
                for _ in range(trials):
                    ov, exp = staged_review(rng, B, acc, correlated=corr)
                    ov_cnt += ov
                    exp_cnt += exp
                row[f"{acc:.2f}"] = {
                    "p_overturn": round(ov_cnt / trials, 4),
                    "p_expel": round(exp_cnt / trials, 4),
                }
            res[corr_label][f"{f:.2f}"] = row
    return res


if __name__ == "__main__":
    out = {"all_case_hist": {}, "power_curve": {}}

    print("=== 1. All-case 50-case hist window (5-seed mean, n_cases=100k) ===")
    print(f"{'f':>4} {'acc':>5} {'V (BTC)':>8} | {'net (V)':>9} {'P(mom_rev)':>10} {'P(rev)':>8}")
    for f in (0.20, 0.33):
        for acc in (0.85, 0.95):
            for V in (0.01, 0.1, 1.0):
                runs = [sim_all_hist(f, V, acc, seed=7 + s) for s in range(5)]
                net = sum(r["net_per_defection_V"] for r in runs) / 5
                pm = sum(r["p_caught_momentum"] for r in runs) / 5
                pr = sum(r["p_caught_review"] for r in runs) / 5
                out["all_case_hist"][f"f={f:.2f} acc={acc:.2f} V={V}"] = {
                    "net_mean_V": round(net, 4),
                    "p_caught_momentum": round(pm, 4),
                    "p_caught_review": round(pr, 4),
                }
                print(f"{f:4.2f} {acc:5.2f} {V:8.3f} | {net:+9.4f} {pm:10.4f} {pr:8.4f}")

    pc = power_curve()
    out["power_curve"] = pc
    for mode in ("correlated_beta", "flat_acc"):
        print(f"\n=== 2. Review power curve P(overturn | drawn) [{mode}] ===")
        accs = ("0.80", "0.85", "0.90", "0.95", "0.97", "0.99")
        print(f"{'f':>5} | " + " ".join(f"{a:>7}" for a in accs))
        for f in ("0.10", "0.20", "0.25"):
            vals = [pc[mode][f][a]["p_overturn"] for a in accs]
            print(f"{f:>5} | " + " ".join(f"{v:7.4f}" for v in vals))

    json.dump(out, open("e2h_power_results.json" if RULE == "current" else f"e2h_power_results_{RULE}.json", "w"), indent=1)

