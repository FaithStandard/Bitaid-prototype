#!/bin/sh
# Internet test, Pi side: everything over Tor onion services, nothing exposed on the router.
#   CHAIN_ONION=<tablet onion> sh scripts/net_pi.sh start
# Runs: a gossip Core (onion :7700), pool members 1-2 (2 stalls), the archivist (onion :7480),
# responders r3 and r4 (r4 sends a bad partial signature). The regtest chain is the tablet's, over Tor.
cd "$(dirname "$0")/.."
[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"
case "$1" in
start)
  pkill -x bitaid-node; pkill -x bitaid-relay; sleep 1
  OUT=$(sh scripts/tor_up.sh 7700 7480) || { echo "$OUT"; exit 1; }
  echo "$OUT"; ONION=$(echo "$OUT" | sed -n 's/^ONION=//p')
  export BITAID_SOCKS=127.0.0.1:${TOR_SOCKS:-9160}
  export BITAID_RPC=http://bitaid:regtest@${CHAIN_ONION:?set CHAIN_ONION to the tablet onion}:18443
  mkdir -p m3logs; rm -f m3logs/*
  X="--exit-after 3600"; P="--peer 127.0.0.1:7700 --pool ${POOL:-tor1}"
  BITAID_WALLET=w nohup target/release/bitaid-node --role core --name core-pi --listen-gossip 127.0.0.1:7700 >/dev/null 2>m3logs/core.log </dev/null &
  sleep 1
  BITAID_WALLET=w nohup target/release/bitaid-node --role pool-member --name pool1-pi --id 1 --n 4 --t 3 --setup-wait 3600 $P $X >/dev/null 2>m3logs/pool1.log </dev/null &
  BITAID_WALLET=w nohup target/release/bitaid-node --role pool-member --name pool2-pi-stall --id 2 --n 4 --t 3 --stall --setup-wait 3600 $P $X >/dev/null 2>m3logs/pool2.log </dev/null &
  BITAID_WALLET=w nohup target/release/bitaid-node --role archivist --name archivist-pi --listen 127.0.0.1:7480 --public-url http://$ONION:7480 $P $X >/dev/null 2>m3logs/archivist.log </dev/null &
  sleep 2
  BITAID_WALLET=r3 nohup target/release/bitaid-node --role responder --name r3-pi $P --mine --ballot I,D --lat 13.6920 --lon -89.2170 $X >m3logs/r3.out 2>m3logs/r3.log </dev/null &
  BITAID_WALLET=r4 nohup target/release/bitaid-node --role responder --name r4-pi-cheat $P --mine --ballot I,D --bad-partial --accept-delay-ms 800 $X >m3logs/r4.out 2>m3logs/r4.log </dev/null &
  sleep 3; echo "PI_READY core onion: $ONION:7700"
  ;;
report)
  cat m3logs/*.out; grep -h "link up\|link down\|pool key\|pool ready\|reserved\|co-signed\|stalling\|attestation share\|deemed" m3logs/*.log | tail -30
  ;;
esac
