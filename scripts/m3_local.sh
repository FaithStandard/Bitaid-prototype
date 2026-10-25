#!/bin/sh
# M3 end to end on one machine: relay, a 4-member oracle pool, two archivists, caller, three responders (one sends a
# bad partial signature and is dropped), all separate processes, over Nostr, on Bitcoin Core regtest.
#   BITAID_CLI="bitcoin-cli -regtest -rpcuser=u -rpcpassword=p -rpcport=18543" \
#   BITAID_RPC=http://u:p@127.0.0.1:18543 sh scripts/m3_local.sh
cd "$(dirname "$0")/.."
BIN=target/release; CLI=${BITAID_CLI:?set BITAID_CLI}; mkdir -p m3logs; rm -f m3logs/*
H=$($CLI getblockcount)
[ "$H" -lt 110 ] && $CLI -rpcwallet=w generatetoaddress 110 $($CLI -rpcwallet=w getnewaddress) >/dev/null
for w in caller r1 r2 r3; do
  $CLI createwallet $w >/dev/null 2>&1 || $CLI loadwallet $w >/dev/null 2>&1
  for i in 1 2 3; do $CLI -rpcwallet=w sendtoaddress $($CLI -rpcwallet=$w getnewaddress) 3 >/dev/null; done
done
$CLI -rpcwallet=w generatetoaddress 1 $($CLI -rpcwallet=w getnewaddress) >/dev/null
R=--relay; RELAY=ws://127.0.0.1:7447
$BIN/bitaid-relay 127.0.0.1:7447 2>m3logs/relay.log & PIDS="$!"
sleep 0.5
# oracle pool: 4 members, threshold 3; member 3 stalls on co-signing, member 4 attests a different outcome
for i in 1 2 3 4; do
  extra=""; [ $i = 3 ] && extra="--stall"; [ $i = 4 ] && extra="--liar"
  BITAID_WALLET=w $BIN/bitaid-node --role pool-member --name pool$i --id $i --n 4 --t 3 $extra $R $RELAY --exit-after 120 2>m3logs/pool$i.log & PIDS="$PIDS $!"
done
for a in 1 2; do
  BITAID_WALLET=w $BIN/bitaid-node --role archivist --name archivist$a $R $RELAY --listen 127.0.0.1:748$a --exit-after 120 2>m3logs/archivist$a.log & PIDS="$PIDS $!"
done
sleep 1
COMMON="$R $RELAY --archivists 2 --mine"
BITAID_WALLET=r1 $BIN/bitaid-node --role responder --name r1 $COMMON --ballot I,D --lat 13.6935 --lon -89.2190 --broadcast > m3logs/r1.out 2>m3logs/r1.log & RP="$!"
BITAID_WALLET=r2 $BIN/bitaid-node --role responder --name r2 $COMMON --ballot I,D --lat 13.6920 --lon -89.2170 > m3logs/r2.out 2>m3logs/r2.log & RP="$RP $!"
BITAID_WALLET=r3 $BIN/bitaid-node --role responder --name r3 $COMMON --ballot I,D --bad-partial --accept-delay-ms 300 > m3logs/r3.out 2>m3logs/r3.log & RP="$RP $!"
sleep 2
BITAID_WALLET=caller $BIN/bitaid-node --role caller --name caller $COMMON --alert-delay 3 --window 6 --dispute-window 3 > m3logs/caller.out 2>m3logs/caller.log
for p in $RP; do wait $p; done
kill $PIDS 2>/dev/null
cat m3logs/caller.out m3logs/r1.out m3logs/r2.out m3logs/r3.out | tee m3_result.txt
grep -h "FAIL" m3logs/*.out >/dev/null && exit 1 || exit 0
