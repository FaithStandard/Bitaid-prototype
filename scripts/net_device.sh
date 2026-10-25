#!/bin/sh
# Internet test, Termux side. Every connection goes through this device's own Tor.
#   sh scripts/net_device.sh chain                tablet (home): regtest node, its RPC as an onion service
#   CORE=<pi onion> CHAIN_ONION=<tablet onion> sh scripts/net_device.sh responder   pool member 3 + responder r1
#   CORE=<pi onion> CHAIN_ONION=<tablet onion> sh scripts/net_device.sh caller      pool member 4 (lies) + caller
cd "$(dirname "$0")/.."
BIN=target/release/bitaid-node
case "$1" in
chain)
  sh scripts/m3_chain.sh || exit 1
  sh scripts/tor_up.sh 18443
  ;;
responder|caller)
  OUT=$(sh scripts/tor_up.sh) || { echo "$OUT"; exit 1; }; echo "$OUT"
  export BITAID_SOCKS=127.0.0.1:${TOR_SOCKS:-9160}
  export BITAID_RPC=http://bitaid:regtest@${CHAIN_ONION:?set CHAIN_ONION}:18443
  P="--peer ${CORE:?set CORE to the Pi onion}:7700 --pool ${POOL:-tor1}"
  if [ "$1" = responder ]; then
    BITAID_WALLET=w $BIN --role pool-member --name pool3 --id 3 --n 4 --t 3 --setup-wait 3600 $P --exit-after 3600 2>pool.log & PM=$!
    BITAID_WALLET=r1 $BIN --role responder --name r1 $P --mine --ballot I,D --broadcast --lat 13.6935 --lon -89.2190
  else
    BITAID_WALLET=w $BIN --role pool-member --name pool4-liar --id 4 --n 4 --t 3 --liar --setup-wait 3600 $P --exit-after 3600 2>pool.log & PM=$!
    BITAID_WALLET=caller $BIN --role caller --name caller $P --mine --window 30 --dispute-window 15
    sleep 5
  fi
  kill $PM 2>/dev/null
  ;;
esac
