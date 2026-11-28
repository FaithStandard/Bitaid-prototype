#!/bin/sh
# M3 end to end on one machine: a gossip Core, a 4-member oracle pool, two archivists, caller, three responders (one sends a
# bad partial signature and is dropped), all separate processes, over Nostr, on Bitcoin Core regtest.
#   BITAID_CLI="bitcoin-cli -regtest -rpcuser=u -rpcpassword=p -rpcport=18543" \
#   BITAID_RPC=http://u:p@127.0.0.1:18543 sh scripts/m3_local.sh
cd "$(dirname "$0")/.."
BIN=target/release; CLI=${BITAID_CLI:?set BITAID_CLI}; mkdir -p m3logs; rm -f m3logs/*
H=$($CLI getblockcount)
# every node reads the chain's records (postings, registrations) from the same height
export BITAID_INDEX_FROM=$($CLI getblockcount)
# timed messages are anchored by a checkpoint every block here (blocks come every 2 s)
export BITAID_CHECKPOINT_BLOCKS=${BITAID_CHECKPOINT_BLOCKS:-1}
[ "$H" -lt 110 ] && $CLI -rpcwallet=w generatetoaddress 110 $($CLI -rpcwallet=w getnewaddress) >/dev/null
for w in caller r1 r2 r3; do
  $CLI createwallet $w >/dev/null 2>&1 || $CLI loadwallet $w >/dev/null 2>&1
  for i in 1 2 3; do $CLI -rpcwallet=w sendtoaddress $($CLI -rpcwallet=$w getnewaddress) 3 >/dev/null; done
done
$CLI -rpcwallet=w generatetoaddress 1 $($CLI -rpcwallet=w getnewaddress) >/dev/null
# transport: gossip through a Core (Specification §7); RELAY_STANDIN=1 uses the earlier Nostr-relay stand-in
if [ -n "$RELAY_STANDIN" ]; then
  R=--relay; RELAY=ws://127.0.0.1:7447
  $BIN/bitaid-relay 127.0.0.1:7447 2>m3logs/relay.log & PIDS="$!"
else
  R=--peer; RELAY=127.0.0.1:7700
  BITAID_PUBKEY_FILE=m3logs/core.pub BITAID_WALLET=w $BIN/bitaid-node --role core --name core --listen-gossip 127.0.0.1:7700 2>m3logs/core.log & PIDS="$!"
fi
sleep 0.5
# protocol deadlines are block heights: on regtest a block clock makes a block every BLOCK seconds
# (default 2), as a real chain would, beside the blocks nodes mine on demand
[ "$CHAIN" = signet ] || { CLI="$CLI" BLOCK=${BLOCK:-2} sh scripts/block_producer.sh & PIDS="$PIDS $!"; }
# oracle pool: 4 members, threshold 3; member 3 stalls on co-signing, member 4 attests a different outcome
for i in 1 2 3 4; do
  extra=""; [ $i = 3 ] && extra="--stall"; [ $i = 4 ] && extra="--liar"
  # LIGHT_R1=1: pool1 and pool2 also listen on gossip so r1 can query them as 2 independent TipSources (§7.2)
  lg=""; pkf=""
  if [ -n "${LIGHT_R1:-}" ] && [ -z "$RELAY_STANDIN" ] && { [ $i = 1 ] || [ $i = 2 ]; }; then
    lg="--listen-gossip 127.0.0.1:770$i"; pkf="BITAID_PUBKEY_FILE=m3logs/pool$i.pub"
  fi
  # LAG4: pool member 4 on a far slower link than the rest (a phone over Tor running behind)
  [ $i = 4 ] && [ -n "${LAG4:-}" ] && L4="BITAID_LAG=$LAG4" || L4=
  env $L4 $pkf BITAID_WALLET=w $BIN/bitaid-node --role pool-member --name pool$i --id $i --n 4 --t 3 $extra $lg $R $RELAY --exit-after 120 2>m3logs/pool$i.log & PIDS="$PIDS $!"
done
for a in 1 2; do
  BITAID_WALLET=w $BIN/bitaid-node --role archivist --name archivist$a $R $RELAY --listen 127.0.0.1:748$a --exit-after 120 2>m3logs/archivist$a.log & PIDS="$PIDS $!"
done
sleep 1
COMMON="$R $RELAY --archivists 2 --mine"
# APP=1: r1 and the caller run as the Android app will (M4): the library driven through its events
# and commands by examples/app_drive (accept on the alert event, ballot I,D on the ballot event, the
# alert raised on the ready event), with its settings passed in rather than read from the environment
R1=$BIN/bitaid-node; CALLER=$BIN/bitaid-node; R1X=""; CX=""
[ -n "$APP" ] && { R1=$BIN/examples/app_drive; CALLER=$BIN/examples/app_drive; R1X="--ask-accept --ask-vote"; CX="--ask-alert"; export BITAID_APP_BALLOT=I,D; }
# LIGHT_R1=1 (Step 6): run r1 with BITAID_CHAIN=core, pinned Core key, BITAID_ANCHOR, and 2 independent
# worker TipSources (pool1 + pool2). LIGHT_R1_NEG=1 gives only 1 TipSource so r1's sign_gate must FAIL.
R1_ENV="BITAID_RPC_COUNT=1"; R1_PEERS=""
if [ -n "${LIGHT_R1:-}" ] && [ -z "$RELAY_STANDIN" ]; then
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    [ -s m3logs/core.pub ] && [ -s m3logs/pool1.pub ] && [ -s m3logs/pool2.pub ] && break
    sleep 0.5
  done
  CORE_PK=$(cat m3logs/core.pub)
  P1_PK=$(cat m3logs/pool1.pub)
  P2_PK=$(cat m3logs/pool2.pub)
  ANCHOR_H=$($CLI getblockcount)
  ANCHOR_H=$((ANCHOR_H > 12 ? ANCHOR_H - 12 : 0))
  ANCHOR_HASH=$($CLI getblockhash $ANCHOR_H)
  if [ -n "${LIGHT_R1_NEG:-}" ]; then
    TIP_SRCS="$P1_PK@127.0.0.1:7701"
    R1_PEERS="--peer 127.0.0.1:7701"
  else
    TIP_SRCS="$P1_PK@127.0.0.1:7701,$P2_PK@127.0.0.1:7702"
    R1_PEERS="--peer 127.0.0.1:7701 --peer 127.0.0.1:7702"
  fi
  R1_ENV="$R1_ENV BITAID_CHAIN=core BITAID_CORE_KEY=$CORE_PK BITAID_CORE_PEER=127.0.0.1:7700 BITAID_ANCHOR=$ANCHOR_H:$ANCHOR_HASH BITAID_TIP_SOURCES=$TIP_SRCS"
fi
env $R1_ENV BITAID_RPC_DELAY_MS=${R1_RPC_DELAY_MS:-0} BITAID_WALLET=r1 $R1 $R1X --role responder --name r1 $COMMON $R1_PEERS --ballot I,D --lat 13.6935 --lon -89.2190 --broadcast > m3logs/r1.out 2>m3logs/r1.log & RP="$!"
BITAID_WALLET=r2 $BIN/bitaid-node --role responder --name r2 $COMMON --ballot I,D --lat 13.6920 --lon -89.2170 > m3logs/r2.out 2>m3logs/r2.log & RP="$RP $!"
BITAID_WALLET=r3 $BIN/bitaid-node --role responder --name r3 $COMMON --ballot I,D --bad-partial --accept-delay-ms 300 > m3logs/r3.out 2>m3logs/r3.log & RP="$RP $!"
sleep 2
BITAID_WALLET=caller $CALLER $CX --role caller --name caller $COMMON --alert-delay ${ALERT_DELAY:-3} --window ${WINDOW:-6} --dispute-blocks 3 --commit-blocks ${COMMIT_BLOCKS:-30} --reveal-blocks ${REVEAL_BLOCKS:-6} > m3logs/caller.out 2>m3logs/caller.log
for p in $RP; do wait $p; done
kill $PIDS 2>/dev/null
cat m3logs/caller.out m3logs/r1.out m3logs/r2.out m3logs/r3.out | tee m3_result.txt
grep -h "FAIL" m3logs/*.out >/dev/null && exit 1 || exit 0
