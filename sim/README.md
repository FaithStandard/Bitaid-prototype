# Bitaid economic simulations

The code behind Specification **Appendix B.10**. Each experiment writes the protocol's rules as code
(Specification §4, §8.3, §9, §10.2–10.5, Appendix B.5) and runs them against agents with fixed
strategies — honest arbitrators of given accuracy who pay an effort cost, lazy voters who always
pick the most common outcome, random voters, colluding blocs, self-serving responders, staging rings,
deleting or challenge-watching storage nodes — over thousands to hundreds of thousands of cases.

Python 3, standard library only. Every run is seeded, so the numbers are identical on any machine.

```
sh run_all.sh            # all experiments, about 3 minutes; results/ rewritten
git diff results/        # empty if your run reproduced the published results
python3 e4_attending_vote.py   # any one experiment, printing its tables
```

Money is counted in case fees (E1–E3), median bounties (E4) or offers (E5–E6). Case difficulty, effort
cost, how often a wronged party re-rolls and similar quantities are **assumptions**, stated in each
file's header; the orderings (which strategy profits, which loses, which rule closes an attack) matter
more than the absolute numbers. Where a rule as first drafted failed, the experiment runs both the
draft and the change the Specification adopted.

## Which file answers which question of Appendix B.10

| Question in B.10 | Experiment | Output |
|---|---|---|
| Is honest work profitable under the penalties? | `sim_arbitration.py` (E1: profit by arbitrator type, absolute vs relative momentum); `sim_arbitration.py sweep` (case difficulty × momentum) | `e1_results.json`, `e1_sweep.json` |
| Does lazy voting take over as its share grows? | `e1b_herding.py` | `e1b_results.json` |
| Do bought verdicts pay? | `e2_collusion.py` (a bloc buying verdicts); `e2b_corruption_economics.py` (with review, restitution and momentum-triggered review; `c` variant: higher re-roll rates and seizure); `e2d_marginal.py` (gain against a no-bloc baseline); `e2e_fixes.py` (bond ≥ 2× case value, split verdicts reviewed ≥ 40%); `e2f_fixes_low_appeal.py` (the adopted fixes when wronged parties re-roll only 70% of the time) | `e2*_results.json` |
| Can seats be captured by fake queue pressure? | `e3_capture.py` | `e3_results.json` |
| Does the weighted attending vote settle the key act correctly? Can self-serving veterans entrench through labor? | `e4_attending_vote.py` | `e4_results.json` |
| Does a shared layer 0 survive misconduct findings? Is the encumbrance count enough to read a layer's risk? | `e5_insurers.py` | `e5_results.json` |
| Does staging pay? Who examines the cases around a confirmed fraud? | `e6_staging.py` (superseded review floor, kept for the record); `e6b_funders_hunters.py` (funders as parties, open flagging) | `e6_results.json`, `e6b_results.json` |
| Can storage nodes fake availability? | `e7_availability.py` (public challenge; secret spot checks) | `e7_results.json` |
| How should base slots store evidence? Can redundancy follow a case's age? | `e8_storage_layout.py` | `e8_results.json` |

## What these do and do not show

They show whether the rules, *if followed and enforced*, make honest work pay and attacks lose, across
many cases and strategies. Whether the rules *are* enforced is shown separately by the prototype's own
test runs (`results/` at the top of this repository, Specification Appendix B.9): the forfeitures,
restitutions and reviews happening on a real chain. Neither shows how real people behave; that is the
testnet pilot with independent operators (milestone M5).

The simulations encode the rules independently of the Rust implementation. Shared test vectors, so
that both compute the same penalties and payouts for the same cases, are planned for the review
package (M6).

Not simulated: the governance signal weight (§15), which uses the same merit function as the
attending vote but moves no money, and the off-chain recourse between insurers and their clients,
which is priced outside the protocol.

Note on `e2b_results.json` and `e2c_results.json`: the copies first used were produced by an earlier
draft of `e2b_corruption_economics.py`, before split-verdict review was added to the model; the files
here are what the published code produces. The B.10 conclusions drawn from E2 (bought verdicts pay on
large cases under the rules as first written; they lose under the adopted fixes, E2e–E2f) hold in both.
