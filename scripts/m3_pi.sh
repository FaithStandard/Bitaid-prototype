#!/bin/sh
# M3 across devices, Pi side.
#   sh scripts/m3_pi.sh setup     regtest node (Bitcoin Core 31.1, checksum verified) + wallets, then build
#   sh scripts/m3_pi.sh start     relay, oracle, archivist, an honest responder and a cheating one
# Regtest only, LAN only: the RPC credentials below guard nothing of value.
cd "$(dirname "$0")/.."
[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"
V=31.1; D=$HOME/bitaid-regtest; B=$HOME/bitcoin-$V/bin
CLI="$B/bitcoin-cli -regtest -datadir=$D -rpcuser=bitaid -rpcpassword=regtest -rpcport=18443"
case "$1" in
setup)
  ( CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS:-2} cargo build --release -p bitaid-node > $HOME/m3_build.log 2>&1 && echo BUILD_DONE >> $HOME/m3_build.log ) &
  if [ ! -x $B/bitcoind ]; then
    cd $HOME
    F=bitcoin-$V-arm-linux-gnueabihf.tar.gz
    curl -sSfO https://bitcoincore.org/bin/bitcoin-core-$V/$F && curl -sSfO https://bitcoincore.org/bin/bitcoin-core-$V/SHA256SUMS
    grep " $F\$" SHA256SUMS | sha256sum -c - || { echo "CHECKSUM FAILED"; exit 1; }
    tar xzf $F && cd - >/dev/null
  fi
  # this release needs glibc 2.29+; on an older system (e.g. Debian 10) use the system's bitcoind if it is 28 or newer
  if ! $B/bitcoind -version >/dev/null 2>&1; then
    SB=$(dirname "$(command -v bitcoind || echo /usr/local/bin/bitcoind)")
    V2=$($SB/bitcoind -version 2>/dev/null | head -1 | sed -n 's/.*v\([0-9]*\)\..*/\1/p')
    echo "downloaded bitcoind cannot run here; system bitcoind at $SB is version ${V2:-none}"
    # 27 predates TRUC (v3) and pay-to-anchor standardness; on regtest it may accept them as non-standard
    if [ "${V2:-0}" -ge 27 ]; then B=$SB; CLI="$B/bitcoin-cli -regtest -datadir=$D -rpcuser=bitaid -rpcpassword=regtest -rpcport=18443"; else echo "NO_USABLE_BITCOIND"; fi
    [ "${V2:-0}" -lt 28 ] && EXTRA_BTC="-acceptnonstdtxn=1"
  fi
  mkdir -p $D
  pgrep -f "datadir=$D" >/dev/null || $B/bitcoind -regtest -datadir=$D -rpcuser=bitaid -rpcpassword=regtest -rpcport=18443 \
      -rpcbind=0.0.0.0 -rpcallowip=192.168.1.0/24 -rpcallowip=127.0.0.1 -port=18444 -listen=0 -fallbackfee=0.0001 -txindex=1 -dbcache=50 $EXTRA_BTC -daemon
  for i in $(seq 1 60); do $CLI getblockcount >/dev/null 2>&1 && break; sleep 2; done
  $CLI getblockcount >/dev/null 2>&1 || { echo "BITCOIND_NOT_RUNNING"; tail -20 $D/regtest/debug.log; wait; exit 1; }
  $CLI createwallet w >/dev/null 2>&1 || $CLI loadwallet w >/dev/null 2>&1
  H=$($CLI getblockcount); [ "$H" -lt 110 ] && $CLI -rpcwallet=w generatetoaddress 110 $($CLI -rpcwallet=w getnewaddress) >/dev/null
  for w in caller r1 r3 r4; do
    $CLI createwallet $w >/dev/null 2>&1 || $CLI loadwallet $w >/dev/null 2>&1
    for i in 1 2 3; do $CLI -rpcwallet=w sendtoaddress $($CLI -rpcwallet=$w getnewaddress) 3 >/dev/null; done
  done
  $CLI -rpcwallet=w generatetoaddress 1 $($CLI -rpcwallet=w getnewaddress) >/dev/null
  echo "regtest height $($CLI getblockcount), wallets: $($CLI listwallets | tr -d '\n ')"
  echo "BITCOIN=$B" > $HOME/.bitaid_bitcoin
  wait
  ;;
start)
  pkill -x bitaid-relay; pkill -x bitaid-node; sleep 1
  mkdir -p m3logs; rm -f m3logs/*
  export BITAID_RPC=${BITAID_RPC:-http://bitaid:regtest@${CHAIN:-127.0.0.1}:18443}
  R="--relay ws://127.0.0.1:7447 $EXTRA_RELAYS"; X="--exit-after 3600"
  nohup target/release/bitaid-relay 0.0.0.0:7447 >/dev/null 2>m3logs/relay.log </dev/null &
  sleep 1
  BITAID_WALLET=w nohup target/release/bitaid-node --role oracle --name oracle $R $X >/dev/null 2>m3logs/oracle.log </dev/null &
  BITAID_WALLET=w nohup target/release/bitaid-node --role archivist --name archivist-pi $R --listen 0.0.0.0:7480 --public-url http://$(hostname -I | cut -d" " -f1):7480 $X >/dev/null 2>m3logs/archivist.log </dev/null &
  sleep 2
  BITAID_WALLET=r3 nohup target/release/bitaid-node --role responder --name r3-pi $R --archivists 2 --mine --ballot I,D --lat 13.6920 --lon -89.2170 $X >m3logs/r3.out 2>m3logs/r3.log </dev/null &
  BITAID_WALLET=r4 nohup target/release/bitaid-node --role responder --name r4-pi-cheat $R --archivists 2 --mine --ballot I,D --bad-partial --accept-delay-ms 800 $X >m3logs/r4.out 2>m3logs/r4.log </dev/null &
  sleep 3; echo "Pi side running: relay :7447, oracle, archivist :7480, responders r3 and r4 (r4 cheats)"
  ;;
report)
  cat m3logs/*.out; grep -h "attesting\|deemed\|stored\|seated\|escalation" m3logs/*.log
  ;;
esac
