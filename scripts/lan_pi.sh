#!/bin/sh
# Pi side of the two-machine pool test: relay + members 1-4 here (member 4 stalls on co-signing),
# members 5-7 on the phone (scripts/lan_phone.sh). Member 1 goes offline once everyone is ready,
# then the client co-signs and attests over the LAN. Result: lan_result.txt
cd "$(dirname "$0")/.."
BIN=target/release; mkdir -p lanlogs; rm -f lanlogs/*
$BIN/bitaid-hub 0.0.0.0:7400 2>lanlogs/hub.log & HUB=$!
sleep 0.5
for i in 1 2 3 4; do
  extra=""; [ $i = 4 ] && extra="--stall"
  $BIN/bitaid-oracle-node --hub 127.0.0.1:7400 --id $i --n 7 --t 4 --batch 20 $extra 2>lanlogs/node$i.log &
  eval P$i=$!
done
echo "Pi members 1-4 started. Now start the phone's members (scripts/lan_phone.sh). Waiting for all 7..."
while [ $(grep -h "ready:" lanlogs/node*.log 2>/dev/null | wc -l) -lt 4 ]; do sleep 1; done
sleep 3
kill $P1
echo "Member 1 taken offline. Running the client..."
{ echo "Bitaid oracle pool across two machines — $(date -u '+%Y-%m-%d %H:%M UTC') — client on $(hostname) $(uname -m)"
  grep -h "pool key\|ready:" lanlogs/node2.log
  $BIN/bitaid-oracle-client --hub 127.0.0.1:7400 --n 7 --t 4; } 2>&1 | tee lan_result.txt
kill $P2 $P3 $P4 $HUB 2>/dev/null
echo "Done. You can stop the phone's members now (Ctrl+C there)."
