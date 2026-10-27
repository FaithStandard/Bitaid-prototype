#!/bin/sh
# Arbitration end to end on one machine (Specification §10): a responder who documented claims in its
# ballot that it intervened, the attending vote deadlocks, it escalates; nine arbitrators (two corrupt)
# offer seats blind; a panel of 3 is drawn from a block, reviews the encrypted footage and votes by
# commit-reveal; the liar appeals to 7; the oracle pool checks the record and attests the final verdict.
#   BITAID_CLI=... BITAID_RPC=... sh scripts/m3_arb_local.sh
cd "$(dirname "$0")/.."
BIN=target/release; CLI=${BITAID_CLI:?set BITAID_CLI}; L=arblogs; mkdir -p $L; rm -f $L/*
H=$($CLI getblockcount); [ "$H" -lt 110 ] && $CLI -rpcwallet=w generatetoaddress 110 $($CLI -rpcwallet=w getnewaddress) >/dev/null
for w in caller r1 r3; do
  $CLI createwallet $w >/dev/null 2>&1 || $CLI loadwallet $w >/dev/null 2>&1
  for i in 1 2 3; do $CLI -rpcwallet=w sendtoaddress $($CLI -rpcwallet=$w getnewaddress) 3 >/dev/null; done
done
$CLI -rpcwallet=w generatetoaddress 1 $($CLI -rpcwallet=w getnewaddress) >/dev/null
P="--peer 127.0.0.1:7700 --pool arb"
BITAID_WALLET=w $BIN/bitaid-node --role core --name core --listen-gossip 127.0.0.1:7700 2>$L/core.log & PIDS="$!"
sleep 0.5
for i in 1 2 3 4; do
  BITAID_WALLET=w $BIN/bitaid-node --role pool-member --name pool$i --id $i --n 4 --t 3 $P --exit-after 300 2>$L/pool$i.log & PIDS="$PIDS $!"
done
BITAID_WALLET=w $BIN/bitaid-node --role archivist --name archivist $P --listen 127.0.0.1:7481 --exit-after 300 2>$L/archivist.log & PIDS="$PIDS $!"
for i in 1 2 3 4 5 6 7 8 9 10; do
  extra=""; [ $i = 4 ] && extra="--corrupt"; [ $i = 8 ] && extra="--corrupt"
  # CAPTURE=1: a captured first panel, deterministically — only arb1 (honest), arb4 and arb8 (corrupt)
  # serve tier 1; arb1 and the six other honest arbitrators serve tier 2
  if [ -n "$CAPTURE" ]; then case $i in 1) extra="--tiers 1,2";; 4|8) extra="--corrupt --tiers 1";; *) extra="--tiers 2";; esac; fi
  # CHALLENGE=1: no party appeals; arb1, the honest dissenter, buys the re-roll and opens tier 2 itself
  [ -n "$CHALLENGE" ] && [ $i = 1 ] && extra="$extra --challenge"
  # (the challenger cannot sit on the tier it opens, so the corrupt pair also serve tier 2: 6 honest of 8)
  [ -n "$CHALLENGE" ] && [ -n "$CAPTURE" ] && { [ $i = 4 ] || [ $i = 8 ]; } && extra="--corrupt --tiers 1,2"
  # CHALLENGE=bad: an honest tier 1 (arb1, arb2) outvotes corrupt arb4, which re-rolls anyway and loses its fees
  if [ "$CHALLENGE" = bad ]; then case $i in 1|2) extra="--tiers 1,2";; 4) extra="--corrupt --tiers 1 --challenge";; 8) extra="--corrupt --tiers 2";; *) extra="--tiers 2";; esac; fi
  # STALL: arb9 and arb10 serve tier 2 but never vote: a seated one misses its commit deadline, its seat
  # forfeiture refunds the fee and a replacement is drawn (§10.4); arb10 otherwise sits idle
  [ $i = 10 ] && extra="--tiers 2"
  [ $i = 1 ] && extra="$extra --greedy-release"
  [ -n "$STALL" ] && { [ $i = 9 ] || [ $i = 10 ]; } && extra="--tiers 2 --no-vote"
  BITAID_WALLET=w $BIN/bitaid-node --role arbitrator --name arb$i $P $extra --offer-window 8 --exit-after 300 >$L/arb$i.out 2>$L/arb$i.log & PIDS="$PIDS $!"
done
sleep 2
COMMON="$P --mine --settle-wait 600"
R3APPEAL="--appeal --greedy"; [ -n "$CHALLENGE" ] && R3APPEAL=""
R1APPEAL="--appeal"; [ "$CHALLENGE" = bad ] && R1APPEAL=""
BITAID_WALLET=r3 $BIN/bitaid-node --role responder --name r3 $COMMON --act I --claim I --others D $R3APPEAL --offer-window 8 --broadcast > $L/r3.out 2>$L/r3.log & RP="$!"
BITAID_WALLET=r1 $BIN/bitaid-node --role responder --name r1-liar $COMMON --act D --claim I --others D --escalate $R1APPEAL --offer-window 8 --accept-delay-ms 300 > $L/r1.out 2>$L/r1.log & RP="$RP $!"
sleep 2
BITAID_WALLET=caller $BIN/bitaid-node --role caller --name caller $COMMON --window 6 --dispute-window 8 --alert-delay 4 --commit-deadline 20 ${REVIEW_PCT:+--review-pct $REVIEW_PCT} > $L/caller.out 2>$L/caller.log
for p in $RP; do wait $p; done
# §10.2-10.3: every seated arbitrator waits for the case's review draw and, if passed over, releases its
# units with the pool's co-signature; give them time before stopping the network
for i in $(seq 1 90); do
  n=0; for f in $(grep -l "case unit" $L/arb*.log 2>/dev/null); do grep -q "review draw\|not released" ${f%.log}.out || n=$((n+1)); done
  [ $n = 0 ] && break; sleep 2
done
grep -h "review draw\|unit of\|FAIL" $L/arb*.out | sort | uniq -c | tee arb_release.txt
kill $PIDS 2>/dev/null
[ "$CHALLENGE" = bad ] && CHALLENGER=4
[ -n "$CHALLENGE" ] && for i in $(seq 1 150); do grep -q "passed" $L/arb${CHALLENGER:-1}.out 2>/dev/null && break; sleep 2; done
cat $L/caller.out $L/r1.out $L/r3.out $L/arb${CHALLENGER:-1}.out | tee arb_result.txt
grep -h "FAIL" $L/*.out >/dev/null && exit 1 || exit 0
