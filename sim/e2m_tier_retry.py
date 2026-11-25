"""Experiment 2m — a tier that lapses: advance at once, or retry the same tier once? (Specification issue #37)

A tier lapses when a seated arbitrator puts up no stake and no offer is left to draw in its place
(§10.4, §10.5). Two rules for what follows a lapse the seats caused:

  advance     the case may go on to the next, larger tier (today's rule, `Tier::lapse_carries`)
  retry_once  the same tier is drawn once more, from fresh offers, without the non-stakers; a second
              lapse advances

Model. A pool of N active arbitrators; for each tier's posting each offers independently with
probability q (fresh offers for a retry or a new tier, so a retry can find arbitrators who did not
offer the first time). A share f of the pool are griefers who offer every time and never stake (what
issue #38's strike counter leaves of them at any moment: f is that residual share, smaller than a bloc's
whole size, since #38 suspends a non-staker after three or four misses). An honest seated arbitrator misses its
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
TRIALS = 20_000
RNG = random.Random(37)


def seat_tier(k, n_honest, n_grief, q, p_fail, excluded, prev, rho):
    """One attempt to seat tier k. Arbitrators are ids: honest 0..n_honest-1, griefers after. An honest
    arbitrator offers with probability q; on a later attempt of the same case it repeats its last choice
    with probability rho (availability correlated across consecutive windows: capital, fee preference,
    being offline), else decides afresh. Returns (seated, windows, new non-stakers, offered, why)."""
    size = PANEL[k]
    offered = set()
    for a in range(n_honest):
        if a in excluded:
            continue
        if prev is not None and RNG.random() < rho:
            if a in prev:
                offered.add(a)
        elif RNG.random() < q:
            offered.add(a)
    offers = list(offered) + [g for g in range(n_honest, n_honest + n_grief) if g not in excluded]
    if len(offers) < size:
        return False, 1, set(), offered, "few"
    RNG.shuffle(offers)
    seats, rest = offers[:size], offers[size:]
    windows, ns = 1, set()
    missing = [a for a in seats if a >= n_honest or RNG.random() < p_fail]
    while missing:
        ns.update(missing)
        need = len(missing)
        if len(rest) < need:
            return False, windows, ns, offered, "lapse"
        windows += 1
        repl, rest = rest[:need], rest[need:]
        missing = [a for a in repl if a >= n_honest or RNG.random() < p_fail]
    return True, windows, ns, offered, "ok"


def case(rule, N, q, p_fail, f, rho=0.0):
    # (round half up: Python's round(0.5) is 0, which left N = 5, f = 0.10 with no griefer; review by Neon)
    n_grief = int(N * f + 0.5)
    n_honest = N - n_grief
    excluded = set()
    k, windows, retried, lapses1, prev = 1, 0, False, 0, None
    while k <= MAX_TIER:
        ok, w, ns, offered, why = seat_tier(k, n_honest, n_grief, q, p_fail, excluded, prev if retried else None, rho)
        windows += w
        excluded |= ns
        if ok:
            return {"tier": k, "windows": windows, "abandoned": False, "lapse1": lapses1}
        if k == 1:
            lapses1 += 1
        if why == "few":
            return {"tier": None, "windows": windows, "abandoned": True, "lapse1": lapses1}
        # the retry is for tier 1 only, as recommended (review by Neon: the first version retried at
        # every tier)
        if rule == "retry_once" and k == 1 and not retried:
            retried = True
            prev = offered
            continue
        retried = False
        k += 1
    return {"tier": None, "windows": windows, "abandoned": True, "lapse1": lapses1}


def fee_of(tier, fee1_v):
    return PANEL[tier] * fee1_v * 1.25 ** (tier - 1) / 3 if tier else 0.0  # in units of V, fee1_v = tier-1 panel / V


if __name__ == "__main__":
    out = {}
    print(f"{'N':>4} {'p':>5} {'f':>4} {'rho':>4} | {'rule':>10} | {'abandon':>8} {'tier2+':>7} {'windows':>7} | fees/V at fee1/V = 0.05")
    for N in (5, 8, 12, 20):
        for p in (0.02, 0.05, 0.10):
            for f in (0.0, 0.05, 0.10):
                for rho in (0.0, 0.5, 0.8):
                    for rule in ("advance", "retry_once"):
                        if rule == "advance" and rho > 0:
                            continue  # advance never redraws the same tier: rho has no effect
                        rs = [case(rule, N, 0.6, p, f, rho) for _ in range(TRIALS)]
                        ab = sum(r["abandoned"] for r in rs) / TRIALS
                        up = sum((r["tier"] or 0) >= 2 for r in rs) / TRIALS
                        win = sum(r["windows"] for r in rs) / TRIALS
                        fees = sum(fee_of(r["tier"], 0.05) for r in rs) / TRIALS
                        out[f"N={N} p={p} f={f} rho={rho} {rule}"] = {"abandon": ab, "tier2plus": up, "windows": win, "fees_v_at_0.05": fees}
                        print(f"{N:4d} {p:5.2f} {f:4.2f} {rho:4.1f} | {rule:>10} | {ab:8.4f} {up:7.4f} {win:7.2f} | {fees:.4f}")
    json.dump(out, open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "results", "e2m_results.json"), "w"), indent=1)
