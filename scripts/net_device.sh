#!/bin/sh
# Internet test, Termux side. Every connection goes through this device's own Tor.
#   PC=<pc onion> sh scripts/net_device.sh responder   pool member 3 + responder r1
#   PC=<pc onion> sh scripts/net_device.sh caller      pool member 4 (lies) + caller
# The PC's one onion address carries its gossip Core (7700), archive (7480) and the chain's RPC (18443).
cd "$(dirname "$0")/.."
BIN=target/release/bitaid-node
case "$1" in
chain)
  sh scripts/m3_chain.sh || exit 1
  sh scripts/tor_up.sh 18443
  ;;
responder|caller)
  OUT=$(sh scripts/tor_up.sh) || { echo "$OUT"; exit 1; }; echo "$OUT"
  [ -z "$NO_TOR" ] && export BITAID_SOCKS=127.0.0.1:${TOR_SOCKS:-9160}
  PC=${PC:-$CORE}; [ -n "$PC" ] || { echo "set PC to the PC's onion address"; exit 1; }
  case "$PC" in *.*) ;; *) PC=$PC.onion ;; esac
  export BITAID_RPC=http://bitaid:regtest@${CHAIN_ONION:-$PC}:18443
  P="--peer $PC:7700 --pool ${POOL:-tor1}"
  termux-wake-lock 2>/dev/null
  if [ "$1" = responder ]; then
    BITAID_WALLET=w $BIN --role pool-member --name pool3 --id 3 --n 4 --t 3 --setup-wait 3600 $P --exit-after 3600 2>pool.log & PM=$!
    # r1 documented (what its footage shows) but claims in its ballot that it intervened; it escalates
    # when the vote deadlocks and appeals once if the panel rules against it (ARB=0: an honest r1)
    if [ "${ARB:-1}" = 1 ]; then CLAIM="--act D --claim I --others D --escalate --appeal --offer-window 40"; else CLAIM="--act D --claim D --others I"; fi
    BITAID_WALLET=r1 $BIN --role responder --name r1 $P --mine $CLAIM --broadcast --settle-wait 1800 --lat 13.6935 --lon -89.2190
  else
    BITAID_WALLET=w $BIN --role pool-member --name pool4-liar --id 4 --n 4 --t 3 --liar --setup-wait 3600 $P --exit-after 3600 2>pool.log & PM=$!
    BITAID_WALLET=caller $BIN --role caller --name caller $P --mine --window 30 --dispute-window 20 --settle-wait 1800
    sleep 5
  fi
  kill $PM 2>/dev/null
  ;;
esac
