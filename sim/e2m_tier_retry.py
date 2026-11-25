"""Experiment 2m — a tier that lapses: advance at once, or retry the same tier once? (Specification issue #37)

A tier lapses when a seated arbitrator puts up no stake and no offer is left to draw in its place
(§10.4, §10.5). Two rules for what follows a lapse the seats caused:

  advance     the case may go on to the next, larger tier (today's rule, `Tier::lapse_carries`)
  retry_once  the same tier is drawn once more, from fresh offers, without the non-stakers; a second
              lapse advances

Model. A pool of N active arbitrators; for each tier's posting each offers independently with
probability q (fresh offers for a retry or a new tier, so a retry can find arbitrators who did not
offer the first time). A share f of the pool are griefers who offer every time and never stake (what
issue #38's strike counter leaves of them at any moment). An honest seated arbitrator misses its
stake with probability p_fail. Seats are drawn in random order from the offers; each seat that misses
is replaced from the offers left; when none is left the tier lapses. Non-stakers are excluded from
every later draw of the case. Tier k seats 3, 7, 15 (§10.5).

Fees: a seated panel is paid only once every seat has staked. A panel of tier k costs
panel_size(k) x seat_fee(k), seat_fee(k) = fee1 x 1.25^(k-1) (the per-tier surcharge, §10.5); fee1/V is
swept. A case that cannot seat a tier at all (fewer offers than seats, or lapses with nothing above it
within --max tier 3) is abandoned: no ruling, the refund path (§3).

Delay: counted in stake windows (one per draw, one per replacement round).
"""
import json
import os
import random

PANEL = {1: 3, 2: 7, 3: 15}
MAX_TIER = 3
TRIALS = 40_000
RNG = random.Random(37)


def seat_tier(k, n_honest, n_grief, q, p_fail, excluded_grief, excluded_honest):
    """One attempt to seat tier k. Returns (seated, windows, new_nonstakers_honest, new_nonstakers_grief)."""
    size = PANEL[k]
    avail_h = n_honest - excluded_honest
    avail_g = n_grief - excluded_grief
    offers = ["h"] * sum(1 for _ in range(avail_h) if RNG.random() < q) + ["g"] * avail_g
    if len(offers) < size:
        return False, 1, 0, 0, "few"
    RNG.shuffle(offers)
    seats, rest = offers[:size], offers[size:]
    windows, ns_h, ns_g = 1, 0, 0
    missing = [s for s in seats if s == "g" or RNG.random() < p_fail]
    while missing:
        for s in missing:
            if s == "g":
                ns_g += 1
            else:
                ns_h += 1
        need = len(missing)
        if len(rest) < need:
            return False, windows, ns_h, ns_g, "lapse"
        windows += 1
        repl, rest = rest[:need], rest[need:]
        missing = [s for s in repl if s == "g" or RNG.random() < p_fail]
    return True, windows, ns_h, ns_g, "ok"


def case(rule, N, q, p_fail, f):
    n_grief = int(round(N * f))
    n_honest = N - n_grief
    ex_h = ex_g = 0
    k, windows, retried, lapses1 = 1, 0, False, 0
    while k <= MAX_TIER:
        ok, w, nh, ng, why = seat_tier(k, n_honest, n_grief, q, p_fail, ex_g, ex_h)
        windows += w
        ex_h += nh
        ex_g += ng
        if ok:
            return {"tier": k, "windows": windows, "abandoned": False, "lapse1": lapses1}
        if k == 1:
            lapses1 += 1
        if why == "few":
            return {"tier": None, "windows": windows, "abandoned": True, "lapse1": lapses1}
        if rule == "retry_once" and not retried:
            retried = True
            continue
        retried = False
        k += 1
    return {"tier": None, "windows": windows, "abandoned": True, "lapse1": lapses1}


def fee_of(tier, fee1_v):
    return PANEL[tier] * fee1_v * 1.25 ** (tier - 1) / 3 if tier else 0.0  # in units of V, fee1_v = tier-1 panel / V


if __name__ == "__main__":
    out = {}
    print(f"{'N':>4} {'q':>4} {'p':>5} {'f':>4} | {'rule':>10} | {'lapse1':>7} {'abandon':>8} {'tier2+':>7} {'windows':>7} | fees/V at fee1/V = 0.02 0.05 0.10")
    for N in (5, 8, 12, 20, 50):
        for q in (0.6,):
            for p in (0.02, 0.05, 0.10, 0.20):
                for f in (0.0, 0.10, 0.20):
                    for rule in ("advance", "retry_once"):
                        rs = [case(rule, N, q, p, f) for _ in range(TRIALS)]
                        lapse1 = sum(r["lapse1"] > 0 for r in rs) / TRIALS
                        ab = sum(r["abandoned"] for r in rs) / TRIALS
                        up = sum((r["tier"] or 0) >= 2 for r in rs) / TRIALS
                        win = sum(r["windows"] for r in rs) / TRIALS
                        fees = {fv: sum(fee_of(r["tier"], fv) for r in rs) / TRIALS for fv in (0.02, 0.05, 0.10)}
                        key = f"N={N} q={q} p={p} f={f} {rule}"
                        out[key] = {"lapse1": lapse1, "abandon": ab, "tier2plus": up, "windows": win, "fees_v": fees}
                        print(f"{N:4d} {q:4.1f} {p:5.2f} {f:4.2f} | {rule:>10} | {lapse1:7.4f} {ab:8.4f} {up:7.4f} {win:7.2f} | "
                              + " ".join(f"{fees[x]:.4f}" for x in (0.02, 0.05, 0.10)))
    json.dump(out, open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "results", "e2m_results.json"), "w"), indent=1)
