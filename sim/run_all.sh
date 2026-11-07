#!/bin/sh
# Re-runs every experiment and writes its results to results/. Python 3, standard library only;
# every run is seeded, so the results are identical on any machine. About 3 minutes in all.
# After running, `git diff results/` shows whether anything differs from the published results.
set -e
cd "$(dirname "$0")"
for c in "sim_arbitration.py" "sim_arbitration.py sweep" e1b_herding.py e2_collusion.py \
         e2b_corruption_economics.py "e2b_corruption_economics.py c" e2d_marginal.py e2e_fixes.py \
         e2f_fixes_low_appeal.py e3_capture.py e4_attending_vote.py e5_insurers.py e6_staging.py \
         e6b_funders_hunters.py e7_availability.py e8_storage_layout.py; do
  echo "== $c"
  python3 $c > /dev/null
done
mv -f ./*.json results/
echo "done: results/ rewritten"
