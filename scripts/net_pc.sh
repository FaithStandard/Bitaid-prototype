#!/bin/sh
# Internet test, PC side (WSL2): the regtest chain, a gossip Core, oracle pool members 1-2 (2 stalls),
# the archivist, responders r3 and r4 (r4 sends a bad partial signature). One onion address carries
# the Core (7700), the archive (7480) and the chain's RPC (18443); nothing is opened on the router.
#   sh scripts/net_pc.sh start | report | stop
# Logs also go to LOGDIR (default: the Windows "Files for Claude\pc_logs" folder) so they can be read there.
cd "$(dirname "$0")/.."
. "$HOME/.cargo/env" 2>/dev/null
V=31.1; B=${BITCOIN_BIN:-$HOME/bitcoin-$V/bin}; D=${REGTEST_DIR:-$HOME/bitaid-regtest}
CLI="$B/bitcoin-cli -regtest -datadir=$D -rpcuser=bitaid -rpcpassword=regtest -rpcport=18443"
WIN="/mnt/c/Users/alber/OneDrive/Documentos/Bitaid/10/v6/Files for Claude"
L=${LOGDIR:-$WIN/pc_logs}; mkdir -p "$L"
case "$1" in
start)
  pkill -x bitaid-node 2>/dev/null; sleep 1
  mkdir -p $D
  $CLI getblockcount >/dev/null 2>&1 || $B/bitcoind -regtest -datadir=$D -rpcuser=bitaid -rpcpassword=regtest -rpcport=18443 \
      -rpcbind=127.0.0.1 -rpcallowip=127.0.0.1 -port=18444 -listen=0 -fallbackfee=0.0001 -txindex=1 -daemon
  for i in $(seq 1 60); do $CLI getblockcount >/dev/null 2>&1 && break; sleep 2; done
  $CLI createwallet w >/dev/null 2>&1 || $CLI loadwallet w >/dev/null 2>&1
  H=$($CLI getblockcount); [ "$H" -lt 110 ] && $CLI -rpcwallet=w generatetoaddress 110 $($CLI -rpcwallet=w getnewaddress) >/dev/null
  for w in caller r1 r3 r4; do
    $CLI createwallet $w >/dev/null 2>&1 || $CLI loadwallet $w >/dev/null 2>&1
    for i in 1 2 3; do $CLI -rpcwallet=w sendtoaddress $($CLI -rpcwallet=$w getnewaddress) 3 >/dev/null; done
  done
  $CLI -rpcwallet=w generatetoaddress 1 $($CLI -rpcwallet=w getnewaddress) >/dev/null
  echo "chain: regtest height $($CLI getblockcount)"
  OUT=$(sh scripts/tor_up.sh 7700 7480 18443) || { echo "$OUT"; exit 1; }
  ONION=$(echo "$OUT" | sed -n 's/^ONION=//p')
  [ -z "$NO_TOR" ] && export BITAID_SOCKS=127.0.0.1:${TOR_SOCKS:-9160}
  export BITAID_RPC=http://bitaid:regtest@127.0.0.1:18443
  X="--exit-after 3600"; P="--peer 127.0.0.1:7700 --pool ${POOL:-tor1}"
  rm -f "$L"/*.log "$L"/*.out
  BITAID_WALLET=w nohup target/release/bitaid-node --role core --name core-pc --listen-gossip 127.0.0.1:7700 >/dev/null 2>"$L/core.log" </dev/null &
  sleep 1
  BITAID_WALLET=w nohup target/release/bitaid-node --role pool-member --name pool1-pc --id 1 --n 4 --t 3 --setup-wait 3600 $P $X >/dev/null 2>"$L/pool1.log" </dev/null &
  BITAID_WALLET=w nohup target/release/bitaid-node --role pool-member --name pool2-pc-stall --id 2 --n 4 --t 3 --stall --setup-wait 3600 $P $X >/dev/null 2>"$L/pool2.log" </dev/null &
  BITAID_WALLET=w nohup target/release/bitaid-node --role archivist --name archivist-pc --listen 127.0.0.1:7480 --public-url http://$ONION:7480 $P $X >/dev/null 2>"$L/archivist.log" </dev/null &
  sleep 2
  BITAID_WALLET=r3 nohup target/release/bitaid-node --role responder --name r3-pc $P --mine --ballot I,D --lat 13.6920 --lon -89.2170 $X >"$L/r3.out" 2>"$L/r3.log" </dev/null &
  BITAID_WALLET=r4 nohup target/release/bitaid-node --role responder --name r4-pc-cheat $P --mine --ballot I,D --bad-partial --accept-delay-ms 800 $X >"$L/r4.out" 2>"$L/r4.log" </dev/null &
  sleep 3
  echo "$ONION" > "$L/onion.txt"
  echo "PC_READY  onion: $ONION"
  ;;
report)
  cat "$L"/*.out; grep -h "link up\|link down\|pool key\|pool ready\|reserved\|co-signed\|stalling\|attestation share\|deemed" "$L"/*.log | tail -30
  ;;
stop)
  pkill -x bitaid-node; $CLI stop >/dev/null 2>&1; pkill -f "tor -f $HOME/bitaid-tor/torrc"; echo stopped
  ;;
esac
