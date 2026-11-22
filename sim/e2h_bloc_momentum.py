"""Experiment 2h (from 2g) — conditional 3-0 bloc defection with rational appeal, unanimous-overturn
refund, relative momentum D (with D >= 3 triggered review), and optional unanimous review floor.

Pool of N = 200 arbitrators; a bloc holds fraction f (B = round(N * f)).
The bloc defects ONLY when it holds all 3 seats of a tier-1 panel (unanimous 3-0);
otherwise its members vote honestly.

Rules modelled (Specification §10.2–§10.5, Appendix A):
  1. Rational appeal + unanimous-overturn refund:
     Tier-1 seat fee F = 0.0002 BTC; tier-2 panel is 7 seats at 1.25*F (total 8.75*F).
     With the unanimous-overturn refund, an appellant who overturns a unanimous tier-1
     verdict is refunded in full from the overturned panel's forfeitures (3 * 4*F = 12*F).
     The wronged party appeals whenever P(overturn) * V > (1 - P(overturn)) * 8.75*F,
     subject to a small friction rate (FRICTION = 0.05 -> 95% appeal when rational).
     Tier 2 overturns unless the bloc holds >= 5 of 7 seats.
  2. Relative momentum D (when use_momentum=True):
     Tracked per arbitrator across the full case stream: decays by lam=0.99 per case
     served, minus 1.5 * pool_rate, floored at 0. An overturned 3-0 defection adds
     isolation weight w = 1.0 and charges 4*F * min(2**D, 32) per bloc member.
     When D >= 3, all unreviewed wrong verdicts in that member's last 50 cases are
     sent to the 3x30 staged review.
  3. Staged review:
     Base review rate by value V (5% <= 0.01, 10% <= 0.1, 20% <= 1.0, 40% > 1.0 BTC),
     optionally raised by `unanimous_floor` for V >= 0.1 BTC.
     Three independent 30-seat panels drawn without replacement from N - 3; honest
     reviewers have correlated errors via case difficulty diff ~ Beta(1.2, 5).
     Overturn (>= 20/30 at all 3 stages) seizes 2V per bloc member; expulsion
     (>= 24/30 at all 3 stages) also seizes the 0.1 BTC entry bond + `future` BTC.
"""
import json
import math
import random

N = 200
FEE_T1 = 0.0002          # BTC per seat (Appendix A / B.7)
FEE_T2_TOTAL = 7 * 1.25 * FEE_T1  # 8.75 * FEE_T1 = 0.00175 BTC
ENTRY_BOND = 0.1         # BTC (Appendix A)
DIFF_ALPHA = 1.2         # Beta(1.2, 5), matching sim_arbitration.py
DIFF_BETA = 5.0
FRICTION = 0.05          # share of rational victims who still fail to appeal


def base_review_rate(V):
    if V <= 0.01:
        return 0.05
    if V <= 0.1:
        return 0.10
    if V <= 1.0:
        return 0.20
    return 0.40


def p_overturn_tier2(B):
    """Exact probability that a 7-seat tier-2 draw from N has fewer than 5 bloc members."""
    total = math.comb(N, 7)
    bloc_wins = sum(
        math.comb(B, k) * math.comb(N - B, 7 - k)
        for k in range(5, min(7, B) + 1)
    )
    return 1.0 - bloc_wins / total


def staged_review(rng, B, acc):
    """Returns (overturned_2_3, expelled_80) for three 30-seat panels from N - 3."""
    diff = rng.betavariate(DIFF_ALPHA, DIFF_BETA)
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


def sim_stream(
    f,
    V,
    acc,
    future=0.0,
    bribe=1.0,
    use_momentum=True,
    unanimous_floor=None,
    rr_override=None,
    n_cases=60000,
    seed=7,
):
    rng = random.Random(seed)
    B = int(round(N * f))
    p_ov = p_overturn_tier2(B)
    # Rational appeal with unanimous-overturn refund: expected gain > expected failed-appeal fee
    rational = (p_ov * V) > ((1.0 - p_ov) * FEE_T2_TOTAL)
    p_appeal = (1.0 - FRICTION) if rational else 0.0

    if rr_override is not None:
        rr = rr_override
    else:
        rr = base_review_rate(V)
        if unanimous_floor is not None and V >= 0.1:
            rr = max(rr, unanimous_floor)

    D = [0.0] * N
    hist = [[] for _ in range(N)]
    open_wrong = {}  # case_id -> tuple of 3 bloc member ids
    pool_rate = 0.05

    defections = 0
    caught_appeal = 0
    caught_review = 0
    caught_momentum = 0
    expelled_cnt = 0
    net_btc = 0.0

    for c in range(n_cases):
        seats = rng.sample(range(N), 3)
        if not all(a < B for a in seats):
            # Honest case: update momentum decay and pool error rate for seated arbitrators
            if use_momentum:
                # Occasional honest 2-1 split (approx 3 * (1-acc) * acc^2)
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

        # 3-0 bloc defection
        defections += 1
        appealed = rng.random() < p_appeal
        if appealed:
            b2 = sum(1 for x in rng.sample(range(N), 7) if x < B)
            if b2 < 5:
                caught_appeal += 1
                for a in seats:
                    mult = min(2.0 ** D[a], 32.0) if use_momentum else 1.0
                    net_btc -= 4.0 * FEE_T1 * mult
                    if use_momentum:
                        D[a] += 1.0
                        pool_rate = 0.999 * pool_rate + 0.001 * 1.0
                        D[a] = max(0.0, D[a] * 0.99 - 1.5 * pool_rate)
                        # D >= 3 triggers review of this member's recent unreviewed wrong cases
                        if D[a] >= 3.0:
                            for cid in list(hist[a]):
                                if cid in open_wrong:
                                    members = open_wrong.pop(cid)
                                    ov, exp = staged_review(rng, B, acc)
                                    if ov:
                                        caught_momentum += 1
                                        net_btc -= 3 * (2.0 * V)
                                        if exp:
                                            expelled_cnt += 1
                                            net_btc -= 3 * (ENTRY_BOND + future)
                            D[a] = 0.0
                continue

        # Verdict stood after tier 1/2 -> review draw at unanimous rate rr
        if rng.random() < rr:
            ov, exp = staged_review(rng, B, acc)
            if ov:
                caught_review += 1
                net_btc -= 3 * (2.0 * V)
                if exp:
                    expelled_cnt += 1
                    net_btc -= 3 * (ENTRY_BOND + future)
                continue

        # Wrong verdict survived initial draw
        net_btc += bribe * V
        if use_momentum:
            open_wrong[c] = tuple(seats)
            for a in seats:
                pool_rate *= 0.999
                D[a] = max(0.0, D[a] * 0.99 - 1.5 * pool_rate)
                hist[a] = (hist[a] + [c])[-50:]

    denom = max(defections, 1)
    return {
        "defections": defections,
        "p_appeal": round(p_appeal, 3),
        "p_caught_appeal": round(caught_appeal / denom, 4),
        "p_caught_review": round(caught_review / denom, 4),
        "p_caught_momentum": round(caught_momentum / denom, 4),
        "p_expelled": round(expelled_cnt / denom, 4),
        "net_per_defection_V": round((net_btc / denom) / V, 4),
    }


def min_review_floor(f, V, acc, use_momentum, future=0.0, n_cases=40000, seed=19):
    """Binary search for lowest unanimous review rate in [0, 1] making net <= 0."""
    if sim_stream(f, V, acc, future=future, use_momentum=use_momentum, rr_override=0.0, n_cases=n_cases, seed=seed)["net_per_defection_V"] <= 0:
        return 0.0
    if sim_stream(f, V, acc, future=future, use_momentum=use_momentum, rr_override=1.0, n_cases=n_cases, seed=seed)["net_per_defection_V"] > 0:
        return None
    lo, hi = 0.0, 1.0
    for _ in range(10):
        mid = (lo + hi) / 2.0
        r = sim_stream(f, V, acc, future=future, use_momentum=use_momentum, rr_override=mid, n_cases=n_cases, seed=seed)
        if r["net_per_defection_V"] <= 0:
            hi = mid
        else:
            lo = mid
    return round(hi, 3)


if __name__ == "__main__":
    out = {"momentum_vs_none": {}, "floors_large_V": {}, "min_floor": {}}
    fs = [0.20, 0.33]
    Vs = [0.001, 0.01, 0.1, 1.0]
    accs = [0.85, 0.95]

    print("=== 1. Rational appeal + unanimous-overturn refund: No momentum vs Momentum D ===")
    print(f"{'f':>4} {'acc':>5} {'V (BTC)':>8} | {'no-D net(V)':>11} | {'with-D net(V)':>13} {'P(mom_rev)':>10} {'P(rev)':>8}")
    for f in fs:
        for acc in accs:
            for V in Vs:
                r0 = sim_stream(f, V, acc, use_momentum=False)
                r1 = sim_stream(f, V, acc, use_momentum=True)
                key = f"f={f:.2f} acc={acc:.2f} V={V}"
                out["momentum_vs_none"][key] = {"no_momentum": r0, "with_momentum": r1}
                print(
                    f"{f:4.2f} {acc:5.2f} {V:8.3f} | {r0['net_per_defection_V']:+11.4f} | "
                    f"{r1['net_per_defection_V']:+13.4f} {r1['p_caught_momentum']:10.4f} {r1['p_caught_review']:8.4f}"
                )

    print("\n=== 2. Optional unanimous review floor for V >= 0.1 BTC (with momentum D) ===")
    print(f"{'f':>4} {'acc':>5} {'V (BTC)':>8} | {'base':>9} {'fl=0.15':>9} {'fl=0.25':>9} {'fl=0.30':>9}")
    for f in fs:
        for acc in accs:
            for V in (0.1, 1.0):
                row = {}
                vals = []
                for fl in (None, 0.15, 0.25, 0.30):
                    r = sim_stream(f, V, acc, use_momentum=True, unanimous_floor=fl)
                    row[str(fl)] = r["net_per_defection_V"]
                    vals.append(r["net_per_defection_V"])
                out["floors_large_V"][f"f={f:.2f} acc={acc:.2f} V={V}"] = row
                print(f"{f:4.2f} {acc:5.2f} {V:8.3f} | {vals[0]:+9.4f} {vals[1]:+9.4f} {vals[2]:+9.4f} {vals[3]:+9.4f}")

    print("\n=== 3. Lowest unanimous review floor making net <= 0 (with vs without momentum) ===")
    print(f"{'f':>4} {'acc':>5} {'V (BTC)':>8} {'spec_rr':>8} | {'no-D floor':>10} {'with-D floor':>12}")
    for f in fs:
        for acc in accs:
            for V in Vs:
                m0 = min_review_floor(f, V, acc, use_momentum=False)
                m1 = min_review_floor(f, V, acc, use_momentum=True)
                out["min_floor"][f"f={f:.2f} acc={acc:.2f} V={V}"] = {"no_momentum": m0, "with_momentum": m1}
                s0 = f"{m0:.3f}" if m0 is not None else ">1.000"
                s1 = f"{m1:.3f}" if m1 is not None else ">1.000"
                print(f"{f:4.2f} {acc:5.2f} {V:8.3f} {base_review_rate(V):8.2f} | {s0:>10} {s1:>12}")

    json.dump(out, open("e2h_results.json", "w"), indent=1)

