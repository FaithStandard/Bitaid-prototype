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
reclaim)
  OUT=$(sh scripts/tor_up.sh) || { echo "$OUT"; exit 1; }
  [ -z "$NO_TOR" ] && export BITAID_SOCKS=127.0.0.1:${TOR_SOCKS:-9160}
  PC=${PC:-$CORE}; case "$PC" in *.*) ;; *) PC=$PC.onion ;; esac
  export BITAID_RPC=http://bitaid:${RPC_PASS:-regtest}@$PC:18443 BITAID_WALLET=bitaid
  for f in $HOME/bitaid_keys_*.jsonl; do [ -f "$f" ] && { echo "== $f"; $BIN --role reclaim --keys "$f"; }; done
  ;;
responder|caller)
  OUT=$(sh scripts/tor_up.sh) || { echo "$OUT"; exit 1; }; echo "$OUT"
  [ -z "$NO_TOR" ] && export BITAID_SOCKS=127.0.0.1:${TOR_SOCKS:-9160}
  PC=${PC:-$CORE}; [ -n "$PC" ] || { echo "set PC to the PC's onion address"; exit 1; }
  case "$PC" in *.*) ;; *) PC=$PC.onion ;; esac
  export BITAID_RPC=http://bitaid:${RPC_PASS:-regtest}@${CHAIN_ONION:-$PC}:18443
  P="--peer $PC:7700 --pool ${POOL:-tor1}"
  termux-wake-lock 2>/dev/null
  # slower blocks: TIME_SCALE stretches every wait of a minute or more; SAT_SCALE divides every amount
  # (a faucet-funded chain); RPC_PASS is the chain node's RPC password (the PC prints them all)
  export BITAID_TIME_SCALE=${TIME_SCALE:-1} BITAID_SAT_SCALE=${SAT_SCALE:-1}
  # INDEX_FROM: the height the run began at, for a chain node without a transaction index
  [ -n "$INDEX_FROM" ] && export BITAID_INDEX_FROM=$INDEX_FROM
  # faucet coins: keep the keys of this device's bond and funding output, to take back what is left
  # a day later (sh scripts/net_device.sh reclaim, with the same RPC_PASS and PC)
  [ "${SAT_SCALE:-1}" -gt 1 ] && export BITAID_KEYFILE=$HOME/bitaid_keys_$1.jsonl
  # the pool member stays for the late penalties, distribution and unit releases (on the public signet
  # these came 5 hours after the device's own checks)
  LINGER=${LINGER:-$(( 1200 * ${TIME_SCALE:-1} ))}
  # a pool member started with & ignores Ctrl+C, so one from an earlier run can still be alive and
  # answer under an old identity: stop it first, and stop ours when this run is interrupted
  if [ "$1" = responder ]; then PMNAME=pool3; else PMNAME=pool4-liar; fi
  pkill -f -- "--name $PMNAME " 2>/dev/null && { echo "stopped a pool member left from an earlier run"; sleep 2; }
  trap 'kill $PM 2>/dev/null; exit 130' INT TERM
  if [ "$1" = responder ]; then
    BITAID_WALLET=w $BIN --role pool-member --name pool3 --id 3 --n 4 --t 3 --setup-wait 3600 $P --exit-after 3600 2>pool.log & PM=$!
    # r1 documented (what its footage shows) but claims in its ballot that it intervened; it escalates
    # when the vote deadlocks and appeals once if the panel rules against it (ARB=0: an honest r1)
    if [ "${ARB:-1}" = 1 ]; then CLAIM="--act D --claim I --others D --escalate --appeal --offer-window 40"; else CLAIM="--act D --claim D --others I"; fi
    BITAID_WALLET=r1 $BIN --role responder --name r1 $P --mine $CLAIM --broadcast --settle-wait 1800 --lat 13.6935 --lon -89.2190
  else
    BITAID_WALLET=w $BIN --role pool-member --name pool4-liar --id 4 --n 4 --t 3 --liar --setup-wait 3600 $P --exit-after 3600 2>pool.log & PM=$!
    BITAID_WALLET=caller $BIN --role caller --name caller $P --mine --window 30 --dispute-window 20 --settle-wait 1800 ${REVIEW_PCT:+--review-pct $REVIEW_PCT}
    sleep 5
  fi
  # the pool member stays up a while: after settlement the pool still co-signs the penalties and the
  # seizure output's distribution (§10.4, §12)
  echo "keeping pool member up ${LINGER:-300} s for penalties"; sleep ${LINGER:-300}
  kill $PM 2>/dev/null
  ;;
esac
