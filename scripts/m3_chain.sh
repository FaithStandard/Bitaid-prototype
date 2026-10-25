#!/bin/sh
# Regtest Bitcoin node for the M3 device test, on a phone in Termux (Bitcoin Core 29+ needed for
# zero-fee version-3 transactions with pay-to-anchor outputs). Test coins only, home network only.
#   sh scripts/m3_chain.sh          install if needed, start, fund the test wallets
#   sh scripts/m3_chain.sh stop
D=$HOME/bitaid-regtest
CLI="bitcoin-cli -regtest -datadir=$D -rpcuser=bitaid -rpcpassword=regtest -rpcport=18443"
if [ "$1" = stop ]; then $CLI stop; exit; fi
command -v bitcoind >/dev/null || pkg install -y bitcoin
V=$(bitcoind -version | head -1 | sed -n 's/.*v\([0-9]*\)\..*/\1/p')
echo "Bitcoin Core $V"; [ "${V:-0}" -ge 29 ] || { echo "NEED_CORE_29"; exit 1; }
mkdir -p $D
$CLI getblockcount >/dev/null 2>&1 || bitcoind -regtest -datadir=$D -rpcuser=bitaid -rpcpassword=regtest -rpcport=18443 \
  -rpcbind=0.0.0.0 -rpcallowip=192.168.1.0/24 -rpcallowip=127.0.0.1 -port=18444 -listen=0 \
  -fallbackfee=0.0001 -txindex=1 -dbcache=50 -daemon
for i in $(seq 1 60); do $CLI getblockcount >/dev/null 2>&1 && break; sleep 2; done
$CLI createwallet w >/dev/null 2>&1 || $CLI loadwallet w >/dev/null 2>&1
H=$($CLI getblockcount); [ "$H" -lt 110 ] && $CLI -rpcwallet=w generatetoaddress 110 $($CLI -rpcwallet=w getnewaddress) >/dev/null
for w in caller r1 r3 r4; do
  $CLI createwallet $w >/dev/null 2>&1 || $CLI loadwallet $w >/dev/null 2>&1
  for i in 1 2 3; do $CLI -rpcwallet=w sendtoaddress $($CLI -rpcwallet=$w getnewaddress) 3 >/dev/null; done
done
$CLI -rpcwallet=w generatetoaddress 1 $($CLI -rpcwallet=w getnewaddress) >/dev/null
IP=$(ifconfig 2>/dev/null | grep -o "inet 192\.168\.[0-9.]*" | head -1 | cut -d" " -f2)
echo "CHAIN_READY height $($CLI getblockcount) at ${IP:-this phone's LAN address}:18443"
