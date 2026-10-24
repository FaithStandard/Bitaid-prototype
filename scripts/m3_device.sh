#!/bin/sh
# M3 across devices, phone/tablet side (Termux). The Pi runs scripts/m3_pi.sh start first.
#   sh scripts/m3_device.sh responder     tablet: responder r1 and a second archivist
#   sh scripts/m3_device.sh caller        phone: the caller, alerting once the others are listening
cd "$(dirname "$0")/.."
PI=${PI:-192.168.1.147}
export BITAID_RPC=${BITAID_RPC:-http://bitaid:regtest@$PI:18443}
R="--relay ws://$PI:7447 $EXTRA_RELAYS"
BIN=target/release/bitaid-node
case "$1" in
responder)
  BITAID_WALLET=w $BIN --role archivist --name archivist-$(uname -n) $R --listen 0.0.0.0:7481 --public-url auto --exit-after 3600 2>archivist.log &
  sleep 2
  BITAID_WALLET=r1 $BIN --role responder --name r1-tablet $R --archivists 2 --mine --ballot I,D --broadcast --lat 13.6935 --lon -89.2190
  kill %1 2>/dev/null
  ;;
caller)
  BITAID_WALLET=caller $BIN --role caller --name caller-phone $R --archivists 2 --mine --window 20 --dispute-window 10
  ;;
esac
