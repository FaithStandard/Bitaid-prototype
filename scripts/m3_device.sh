#!/bin/sh
# M3 across devices, phone/tablet side (Termux). The Pi runs scripts/m3_pi.sh start first.
#   sh scripts/m3_device.sh responder     tablet: pool member 3 and responder r1 (ARCHIVIST=1 adds an archivist)
#   sh scripts/m3_device.sh caller        phone: pool member 4 (lies on attestation) and the caller
cd "$(dirname "$0")/.."
PI=${PI:-192.168.1.147}
CHAIN=${CHAIN:-$PI}
export BITAID_RPC=${BITAID_RPC:-http://bitaid:regtest@$CHAIN:18443}
R="--relay ws://$PI:7447 $EXTRA_RELAYS"
BIN=target/release/bitaid-node
case "$1" in
responder)
  BITAID_WALLET=w $BIN --role pool-member --name pool3-tablet --id 3 --n 4 --t 3 $R --exit-after 3600 2>pool.log &
  # a second archivist here only if other devices can reach this one (not on routers that isolate Wi-Fi clients)
  [ -n "$ARCHIVIST" ] && BITAID_WALLET=w $BIN --role archivist --name archivist-$(uname -n) $R --listen 0.0.0.0:7481 --public-url auto --exit-after 3600 2>archivist.log &
  sleep 2
  BITAID_WALLET=r1 $BIN --role responder --name r1-tablet $R --archivists ${ARCHIVISTS:-1} --mine --ballot I,D --broadcast --lat 13.6935 --lon -89.2190
  kill %1 %2 2>/dev/null
  ;;
caller)
  BITAID_WALLET=w $BIN --role pool-member --name pool4-phone-liar --id 4 --n 4 --t 3 --liar $R --exit-after 3600 2>pool.log &
  BITAID_WALLET=caller $BIN --role caller --name caller-phone $R --archivists ${ARCHIVISTS:-1} --mine --window 20 --dispute-window 10
  sleep 5; kill %1 2>/dev/null
  ;;
esac
