# Design note: arbitrators declare a case's difficulty with their vote

Status: idea (Albert, 2026-11-22). Closed: both forms were simulated and fail (`sim/e2j_declared_difficulty.py`,
`sim/e2k_overturn_difficulty.py`); see the last section for why, and what it teaches.

## Why it matters

The staged review's power against a bloc depends heavily on how hard the case is
(`sim/e2h_power_and_hist.py`): a 20% bloc's wrong verdict, drawn for review, is overturned about 86% of
the time when reviewers are 95% accurate on an easy case, but only about 44% when case difficulty
varies. A smart bloc defects where review is weakest. Today the protocol has one difficulty signal,
the split itself (a split panel is reviewed at 40%, a unanimous one at 5–20%), and one per-predicate
flag, the canon's *uncertain*, which adds nothing to momentum.

## The idea

Each arbitrator commits, with its vote and under the same commit-reveal, a coarse difficulty rating
of the case: easy, ordinary, hard. The protocol uses it afterwards.

## The danger: a self-rating used for anything that benefits the rater is gamed

- If "hard" softens penalties, a bloc rates every bought verdict hard.
- If "hard" only raises review, a bloc rates every bought verdict easy.

So the rating works only as a **bet the rater places on itself**, each choice costing something:

| Declared | Review of the verdict | If the verdict is later overturned (appeal or review) |
| --- | --- | --- |
| easy | the base rate | treated as more than an honest error: an easy case decided wrongly; the panel's case units are taken, not only the fee penalties |
| ordinary | as today | as today |
| hard | a higher rate | penalties softened (honest error on a hard question), but the verdict is checked more often |

What this does to the bloc found in E2g/E2h:
- It cannot declare its verdict easy without risking its units when an appeal overturns it, which
  closes the hole where an appeal overturn costs a bloc only fees.
- Declaring it hard draws more review. Review is weak only on cases that *are* hard, not on cases
  *declared* hard: an easy case declared hard is reviewed by reviewers who find it easy, at full
  power.
- What remains is a bloc defecting on cases that genuinely are hard. That is indistinguishable from
  honest error by any mechanism, and is the limit already stated.

## A second use: divergence is evidence

Reviewers rate difficulty too. A unanimous panel that declared a case hard, which every review stage
finds easy, has declared something no honest panel would. That divergence can weigh in momentum, so
"hard" stops being a free shelter.

## Open questions

- How well honest arbitrators rate difficulty. The categories must be coarse, and a mis-rating must
  cost little when the verdict stands.
- Whether the panel's rating is the median of its seats, or each seat's bet is its own.
- The review rates and penalty changes per category: to be simulated against the bloc models
  (E2g/E2h) and against honest error.
- Interaction with the canon's *uncertain* flag, which is a difficulty statement fixed in advance by
  the canon rather than declared per case.

## Simulated (E2j, 2026-11-22): the self-declared menu fails

The independent reviewer found, and the run confirms, that "easy" is dominated: it pays the same as
"ordinary" and costs the case units on any overturn. Honest arbitrators who use it with 70–80%
rating accuracy lose their unit on about 1% of cases (−85 to −96 fees per case at V = 1 BTC); one
who avoids it does fine. The bloc simply declares "ordinary" (or "hard" on hard cases) and keeps
its +0.03 to +0.05 V. A menu helps against the bloc only if its best entry is worse for the bloc than
today's rules, and "ordinary" *is* today's rules. Self-declaration is dropped.

## What survives: difficulty judged by whoever overturns

The divergence point above needs no self-declaration. When a unanimous verdict is overturned, the
deciders of the overturn (the larger panel on appeal, the reviewers on review) say whether the
question was hard. The panel overturned cannot choose that label.

- Overturned and judged easy: three arbitrators unanimously wrong on an easy question. Honest panels
  almost never do this (each errs about 1 time in 20 on an easy case at 95% accuracy, all three
  together far more rarely), so it is treated as misconduct-level: the case units, not only fees.
- Overturned and judged hard: an honest error, fee penalties as today.

This targets exactly the hole of E2g/E2h: today an appeal overturn costs a bloc only fees. Against a
bloc defecting on easy cases, appeals then cost it 2V per member; on hard cases nothing changes,
which is the irreducible limit. To simulate before adoption: the bloc's net and honest income with
the overturning panel judging difficulty with noise; and whether a captured larger panel could
label an honest panel's verdict "easy" to seize its units (that larger panel must already be
captured to overturn, so the new harm is the size of the seizure, which needs bounding).

## Simulated (E2k, 2026-11-22): difficulty judged by the overturning panel also fails

- Against the bloc it only moves the defections: on easy cases the bloc now loses about 4V per
  defection, so it defects on ordinary and hard cases instead and keeps +0.01 to +0.05 V, as before.
- It ruins honest arbitrators. Honest panels are unanimously wrong, and then rated easy, on about
  0.04% of cases at 95% accuracy and 0.25% at 85%. Each such case costs 2V, and V is about 5,000
  times the seat fee for a 1 BTC case, so honest income of +0.2 fees a case turns into −3.5 (95%)
  to −25 (85%). Capping the seizure at 0.5V still leaves it negative at V = 1 BTC.
- (A captured tier 2 labelling an honest verdict easy matters less than the run shows: penalties
  are taken only on the final ruling, the honest dissenters would re-roll to tier 3, and a 20% bloc
  holds 10 of 15 there about 5 times in 100,000.)

## What it teaches

No penalty sized to the case value can be triggered by anything an honest panel does with a
probability above about fee ÷ V (1 in 5,000 for a 1 BTC case at today's fee): honest income cannot
absorb it. Case units are taken today only on a confirmed staged-review overturn, which requires many
independent reviewers to agree, and that is why they are safe for the honest. The lever against a
bloc is therefore the review's power, not new seizure triggers: see the requested comparison of
review rules (pooled two thirds of 90, two of three stages, three stages at 60%), which trades some
of the review's large safety margin for power.
