#!/bin/bash
# 7 oracle members as separate processes over the relay; member 5 stalls on co-signing, member 6 lies
# on attestation; members 1 and 2 go offline after setup.
BIN=${BIN:-$(cd "$(dirname "$0")/.." && pwd)/target/release}
LOGS=${LOGS:-/tmp/bitaid-pool}; mkdir -p $LOGS; cd $LOGS; rm -f node*.log hub.log
$BIN/bitaid-hub 127.0.0.1:7400 2>hub.log & HUB=$!
sleep 0.5
for i in 1 2 3 4 5 6 7; do
  extra=""; [ $i = 5 ] && extra="--stall"; [ $i = 6 ] && extra="--liar"
  $BIN/bitaid-oracle-node --hub 127.0.0.1:7400 --id $i --n 7 --t 4 --batch 8 $extra 2>node$i.log &
  eval P$i=$!
done
for k in $(seq 1 60); do [ $(grep -l "ready:" node*.log 2>/dev/null | wc -l) = 7 ] && break; sleep 0.5; done
grep -h "ready:\|pool key" node1.log
kill $P1 $P2; sleep 0.3
"$BIN/bitaid-oracle-client" --hub 127.0.0.1:7400 --n 7 --t 4
RC=$?
kill $P3 $P4 $P5 $P6 $P7 $HUB 2>/dev/null
exit $RC
