#!/bin/sh
# Many cases through one long-lived oracle pool, archivist and pool of arbitrators, to show what a single
# case cannot: momentum (§10.4). Each case: the attending vote deadlocks (r1 documented but claims it
# intervened), r1 escalates; 3 of 13 arbitrators are drawn; whoever the verdict goes against appeals once
# to 7; penalties are taken from seat stakes and distributed. Arbitrators: arb1-8 honest (misread 5% of
# cases), arb9-10 sloppy (misread 35%), arb11-12 corrupt (always side against the footage), arb13 commits and never reveals. Each seat's
# momentum is read from every tier committed before it and sizes the seat's stake and penalties.
#   BITAID_CLI=... BITAID_RPC=... CASES=20 sh scripts/m3_multi.sh
cd "$(dirname "$0")/.."
BIN=target/release; CLI=${BITAID_CLI:?set BITAID_CLI}; L=multilogs; mkdir -p $L; rm -f $L/*
N=${CASES:-20}
H=$($CLI getblockcount); [ "$H" -lt 110 ] && $CLI -rpcwallet=w generatetoaddress 110 $($CLI -rpcwallet=w getnewaddress) >/dev/null
for w in caller r1 r3; do
  $CLI createwallet $w >/dev/null 2>&1 || $CLI loadwallet $w >/dev/null 2>&1
  for i in 1 2 3 4 5 6; do $CLI -rpcwallet=w sendtoaddress $($CLI -rpcwallet=$w getnewaddress) 3 >/dev/null; done
done
$CLI -rpcwallet=w generatetoaddress 1 $($CLI -rpcwallet=w getnewaddress) >/dev/null
P="--peer 127.0.0.1:7700 --pool multi"
X="--exit-after 1800"
BITAID_WALLET=w $BIN/bitaid-node --role core --name core --listen-gossip 127.0.0.1:7700 2>$L/core.log & PIDS="$!"
sleep 0.5
for i in 1 2 3 4; do
  BITAID_WALLET=w $BIN/bitaid-node --role pool-member --name pool$i --id $i --n 4 --t 3 --batch 300 $P $X 2>$L/pool$i.log & PIDS="$PIDS $!"
done
BITAID_WALLET=w $BIN/bitaid-node --role archivist --name archivist $P --listen 127.0.0.1:7482 $X 2>$L/archivist.log & PIDS="$PIDS $!"
for i in 1 2 3 4 5 6 7 8 9 10 11 12 13; do
  extra="--error-rate 0.05"
  { [ $i = 9 ] || [ $i = 10 ]; } && extra="--error-rate 0.35"
  { [ $i = 11 ] || [ $i = 12 ]; } && extra="--corrupt"
  [ $i = 13 ] && extra="--no-reveal"
  BITAID_WALLET=w $BIN/bitaid-node --role arbitrator --name arb$i $P $extra $X >$L/arb$i.out 2>$L/arb$i.log & PIDS="$PIDS $!"
done
sleep 3
COMMON="$P --mine --settle-wait 900 --offer-window 8"
for c in $(seq 1 $N); do
  echo "== case $c" >> $L/cases.txt
  BITAID_WALLET=r3 $BIN/bitaid-node --role responder --name r3 $COMMON --act I --claim I --others D --appeal --broadcast > $L/r3.$c.out 2>$L/r3.$c.log & RP="$!"
  BITAID_WALLET=r1 $BIN/bitaid-node --role responder --name r1-liar $COMMON --act D --claim I --others D --escalate --appeal --accept-delay-ms 300 > $L/r1.$c.out 2>$L/r1.$c.log & RP="$RP $!"
  sleep 2
  BITAID_WALLET=caller $BIN/bitaid-node --role caller --name caller $COMMON --window 6 --dispute-window 8 --alert-delay 4 --commit-deadline 20 > $L/caller.$c.out 2>$L/caller.$c.log
  for p in $RP; do wait $p; done
  grep -h "passed\|tier . verdict\|standing verdict\|forfeited\|distributed" $L/caller.$c.out $L/r1.$c.out $L/r3.$c.out $L/r1.$c.log $L/r3.$c.log 2>/dev/null | cut -c1-200 >> $L/cases.txt
done
kill $PIDS 2>/dev/null
echo "== momentum when seated, by arbitrator (case order)" >> $L/cases.txt
for i in 1 2 3 4 5 6 7 8 9 10 11 12 13; do
  echo "arb$i: $(grep -o 'momentum [0-9.]*' $L/arb$i.log | cut -d' ' -f2 | tr '\n' ' ')" >> $L/cases.txt
done
cat $L/cases.txt | tail -40
grep -h "passed" $L/*.out | grep -v " 0 failed" && exit 1 || exit 0
