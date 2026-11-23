"""Experiment 2l — which staged-review rule? Power against a bloc against safety for honest panels.

The staged review draws three panels of 30 from the pool (without replacement, the case's own seats
excluded). Candidate rules for overturning a verdict:

  current   each of the 3 stages reaches 20 of 30 (two thirds)
  pooled    at least 60 of all 90 votes (two thirds of the pooled votes)
  two_of_3  at least 2 of the 3 stages reach 20 of 30
  sixty     each of the 3 stages reaches 18 of 30 (60%)
  gated     the first stage reaches 15 of 30 (half) to go on, the first two 30 of 60 for the third to
            sit (below that 60 of 90 is out of reach), then at least 60 of all 90; expulsion at 72 of 90

A clean review stops at the first stage that cannot reach its bar, so the rules also differ in
cost: the expected number of reviewers sat per drawn case (`seats_*`). Under `pooled` a review never
stops early (60 of 90 stays reachable after any first stage); `gated` restores the early stop.

Power: a bloc holding a share f of the pool votes to keep its own (wrong) verdict; honest reviewers
vote to overturn with p = 0.5 + (acc - 0.5) * (1 - diff), diff ~ Beta(1.2, 5) per case (as in
sim_arbitration.py), or diff = 0 ("flat").

Safety: the verdict under review is right. Honest reviewers vote to overturn it wrongly with
1 - p; with an attacking bloc, its members vote to overturn (a bloc out to strip honest arbitrators).

Expulsion keeps its own bar (80%); reported for the current rule's structure (each stage 24 of 30)
and for the pooled form (72 of 90).
"""
import json

import numpy as np

N = 200
RNG = np.random.default_rng(23)
TRIALS = 200_000


def panels(f, trials):
    """Bloc members on each of the three 30-seat panels, drawn without replacement from N - 3."""
    pool = N - 3
    b = int(round(N * f)) - 3 if f > 0 else 0
    b = max(b, 0)
    k1 = RNG.hypergeometric(b, pool - b, 30, trials)
    k2 = RNG.hypergeometric(b - k1, (pool - b) - (30 - k1), 30)
    k3 = RNG.hypergeometric(b - k1 - k2, (pool - b) - (60 - k1 - k2), 30)
    return np.stack([k1, k2, k3], axis=1)


def votes(f, acc, correlated, bloc_votes_overturn, right_verdict, trials=TRIALS):
    """Overturn votes per stage (trials x 3)."""
    k = panels(f, trials)
    diff = RNG.beta(1.2, 5.0, trials) if correlated else np.zeros(trials)
    p_right = 0.5 + (acc - 0.5) * (1.0 - diff)
    # an honest reviewer votes to overturn when the verdict is wrong and it sees that, or when the
    # verdict is right and it errs
    p_over = (1.0 - p_right) if right_verdict else p_right
    honest = 30 - k
    yes = RNG.binomial(honest, p_over[:, None])
    if bloc_votes_overturn:
        yes = yes + k
    return yes


def rules(yes):
    tot = yes.sum(axis=1)
    return {
        "current": (yes >= 20).all(axis=1).mean(),
        "pooled": (tot >= 60).mean(),
        "two_of_3": ((yes >= 20).sum(axis=1) >= 2).mean(),
        "sixty": (yes >= 18).all(axis=1).mean(),
        "gated": ((yes[:, 0] >= 15) & (tot >= 60)).mean(),
        # expected seats sat per drawn case: a stage sits only while its rule can still be met
        "seats_current": (30 + 30 * (yes[:, 0] >= 20) + 30 * ((yes[:, 0] >= 20) & (yes[:, 1] >= 20))).mean(),
        "seats_pooled": 90.0,
        "seats_two_of_3": (60 + 30 * (((yes[:, 0] >= 20) ^ (yes[:, 1] >= 20)))).mean(),
        "seats_sixty": (30 + 30 * (yes[:, 0] >= 18) + 30 * ((yes[:, 0] >= 18) & (yes[:, 1] >= 18))).mean(),
        # gated: the second panel sits once the first reaches half; the third only while 60 of 90 is
        # still reachable (s1 + s2 >= 30), a stop that loses no power
        "seats_gated": (30 + 30 * (yes[:, 0] >= 15) + 30 * ((yes[:, 0] >= 15) & (yes[:, :2].sum(axis=1) >= 30))).mean(),
        "expel_current": (yes >= 24).all(axis=1).mean(),
        "expel_pooled": (tot >= 72).mean(),
        "expel_gated": ((yes[:, 0] >= 15) & (yes[:, :2].sum(axis=1) >= 30) & (tot >= 72)).mean(),
    }


if __name__ == "__main__":
    out = {"power": {}, "safety": {}}
    names = ["current", "pooled", "two_of_3", "sixty", "gated"]
    print("=== Power: P(overturn | drawn) of a bloc's wrong verdict, bloc voting to keep ===")
    for corr in (True, False):
        print(f"\n-- {'mixed difficulty, Beta(1.2, 5)' if corr else 'flat accuracy'} --")
        print(f"{'f':>5} {'acc':>5} | " + " ".join(f"{n:>9}" for n in names))
        for f in (0.10, 0.20, 0.25, 0.33):
            for acc in (0.80, 0.85, 0.90, 0.95, 0.99):
                r = rules(votes(f, acc, corr, False, False))
                out["power"][f"{'corr' if corr else 'flat'} f={f} acc={acc}"] = {k: round(float(v), 5) for k, v in r.items()}
                print(f"{f:5.2f} {acc:5.2f} | " + " ".join(f"{r[n]:9.4f}" for n in names) + f" | expel cur {r['expel_current']:.4f} gated {r['expel_gated']:.4f}")
    print("\n=== Safety: P(wrongful overturn) of an honest panel's right verdict ===")
    for corr in (True, False):
        print(f"\n-- {'mixed difficulty' if corr else 'flat accuracy'} --")
        print(f"{'bloc':>5} {'acc':>5} | " + " ".join(f"{n:>9}" for n in names) + f" {'expel_cur':>10} {'expel_gate':>10}")
        for f in (0.0, 0.20, 0.25):
            for acc in (0.60, 0.70, 0.85):
                r = rules(votes(f, acc, corr, f > 0, True))
                out["safety"][f"{'corr' if corr else 'flat'} attack_f={f} acc={acc}"] = {k: float(v) for k, v in r.items()}
                print(f"{f:5.2f} {acc:5.2f} | " + " ".join(f"{r[n]:9.2e}" for n in names) + f" {r['expel_current']:10.2e} {r['expel_gated']:10.2e}")
    print("\n=== Cost: expected reviewers sat per drawn case whose verdict was right (no bloc, mixed difficulty) ===")
    out["cost"] = {}
    for acc in (0.70, 0.85, 0.95):
        r = rules(votes(0.0, acc, True, False, True))
        out["cost"][f"acc={acc}"] = {k: round(float(v), 2) for k, v in r.items() if k.startswith("seats")}
        print(f"acc {acc:.2f} | " + " ".join(f"{n}={r['seats_' + n]:.1f}" for n in names))
    json.dump(out, open("results/e2l_results.json", "w"), indent=1)
