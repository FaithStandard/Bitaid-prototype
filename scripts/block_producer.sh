#!/bin/sh
# Block producer for a custom signet: one block every BLOCK seconds (default 20) to a fresh address of
# wallet w, with real proof of work. Nodes never mine on such a chain; they wait for these blocks.
#   CLI="bitcoin-cli -signet -signetchallenge=51 ..." BLOCK=20 sh scripts/block_producer.sh
A=$($CLI -rpcwallet=w getnewaddress)
while true; do
  $CLI generatetoaddress 1 $A 1000000000 >/dev/null 2>&1
  sleep ${BLOCK:-20}
done
