#!/bin/sh
# Internet test, PC side (WSL): the regtest chain, a gossip Core, oracle pool members 1-2 (2 stalls),
# the archivist, nine arbitrators (two corrupt), responders r3 (intervened) and r4 (sends a bad partial
# signature). One onion address carries
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
  # Bitcoin Core 31.1: install it if missing, from the copy in the Windows folder or from bitcoincore.org,
  # checking the release checksum either way
  if ! $B/bitcoind -version >/dev/null 2>&1; then
    F=bitcoin-$V-x86_64-linux-gnu.tar.gz; T=$(mktemp -d)
    if [ -f "$WIN/$F" ] && [ -f "$WIN/SHA256SUMS" ]; then cp "$WIN/$F" "$WIN/SHA256SUMS" $T/
    else (cd $T && curl -sSfO https://bitcoincore.org/bin/bitcoin-core-$V/$F && curl -sSfO https://bitcoincore.org/bin/bitcoin-core-$V/SHA256SUMS); fi
    (cd $T && grep " $F\$" SHA256SUMS | sha256sum -c -) || { echo "BITCOIN_CHECKSUM_FAILED"; exit 1; }
    # extracted with Python: Ubuntu 24.04's tar uses a system call WSL1 lacks ("Function not implemented")
    python3 -c "import tarfile,sys; tarfile.open(sys.argv[1]).extractall(sys.argv[2])" $T/$F $HOME && rm -rf $T
    chmod +x $HOME/bitcoin-$V/bin/* $HOME/bitcoin-$V/libexec/* 2>/dev/null
    B=$HOME/bitcoin-$V/bin; CLI="$B/bitcoin-cli -regtest -datadir=$D -rpcuser=bitaid -rpcpassword=regtest -rpcport=18443"
  fi
  $B/bitcoind -version | head -1 || { echo "BITCOIND_CANNOT_RUN"; ls -l $B; exit 1; }
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
  export BITAID_RPC=http://bitaid:regtest@127.0.0.1:18443 BITAID_SELF_ONION=$ONION
  X="--exit-after 3600"; P="--peer 127.0.0.1:7700 --pool ${POOL:-tor1}"
  rm -f "$L"/*.log "$L"/*.out
  # REVIEW=1: the staged review (§10.3) — a captured tier 1 that no one appeals or challenges, drawn for
  # review (the phone's caller sets REVIEW_PCT=100), three independent panels of 5 drawn from 26 arbitrators
  if [ "$REVIEW" = 1 ]; then CHALLENGE=0; STALL=0; CAPTURE=1; ARBS=${ARBS:-26}; fi
  BITAID_WALLET=w nohup target/release/bitaid-node --role core --name core-pc --listen-gossip 127.0.0.1:7700 >/dev/null 2>"$L/core.log" </dev/null &
  sleep 1
  BITAID_WALLET=w nohup target/release/bitaid-node --role pool-member --name pool1-pc --id 1 --n 4 --t 3 --setup-wait 3600 $P $X >/dev/null 2>"$L/pool1.log" </dev/null &
  BITAID_WALLET=w nohup target/release/bitaid-node --role pool-member --name pool2-pc-stall --id 2 --n 4 --t 3 --stall --setup-wait 3600 $P $X >/dev/null 2>"$L/pool2.log" </dev/null &
  BITAID_WALLET=w nohup target/release/bitaid-node --role archivist --name archivist-pc --listen 127.0.0.1:7480 --public-url http://$ONION:7480 $P $X >"$L/archivist.out" 2>"$L/archivist.log" </dev/null &
  for i in $(seq 1 ${ARBS:-10}); do
    extra=""; for c in ${CORRUPT:-4 8}; do [ $i = $c ] && extra="--corrupt"; done
    # CAPTURE=1 (default; CAPTURE=0 for a random draw): a captured first panel, deterministically — only arb1 (honest), arb4 and arb8 (corrupt)
    # serve tier 1; arb1 and the six other honest arbitrators serve tier 2
    if [ "${CAPTURE:-1}" = 1 ]; then case $i in 1) extra="--tiers 1,2";; 4|8) extra="--corrupt --tiers 1";; *) extra="--tiers 2";; esac; fi
    # CHALLENGE=1 (default): no party appeals; arb1, the honest dissenter, buys the re-roll to tier 2
    [ "${CHALLENGE:-1}" = 1 ] && [ $i = 1 ] && extra="$extra --challenge"
    # (the challenger cannot sit on the tier it opens, so the corrupt pair also serve tier 2: 6 honest of 8)
    [ "${CHALLENGE:-1}" = 1 ] && [ "${CAPTURE:-1}" = 1 ] && { [ $i = 4 ] || [ $i = 8 ]; } && extra="--corrupt --tiers 1,2"
    # STALL: arb9 and arb10 serve tier 2 but never vote: a seated one misses its commit deadline, its seat
    # forfeiture refunds the fee and a replacement is drawn (§10.4); arb10 otherwise sits idle
    [ $i = 10 ] && extra="--tiers 2"
    [ "${STALL:-1}" = 1 ] && { [ $i = 9 ] || [ $i = 10 ]; } && extra="--tiers 2 --no-vote"
    # review duty (§10.3): replacement seats taken only at 25,000 sats or more; arb21-24 pay their way out
    # of any review seat they are drawn for, arb25-26 stay silent
    extra="$extra --review-price 25000"
    { [ $i -ge 21 ] && [ $i -le 24 ]; } && extra="$extra --review-leave"
    { [ $i = 25 ] || [ $i = 26 ]; } && extra="$extra --review-silent"
    # ... and arb20 accepts any review seat and never gives its finding (charged as a missed reveal)
    [ "$REVIEW" = 1 ] && [ $i = 20 ] && extra="$extra --no-vote"
    BITAID_WALLET=w nohup target/release/bitaid-node --role arbitrator --name arb$i-pc $P $extra --offer-window 40 $X >"$L/arb$i.out" 2>"$L/arb$i.log" </dev/null &
  done
  sleep 2
  R3APPEAL="--appeal --greedy"; [ "${CHALLENGE:-1}" = 1 ] && R3APPEAL=""; [ "$REVIEW" = 1 ] && R3APPEAL=""
  BITAID_WALLET=r3 nohup target/release/bitaid-node --role responder --name r3-pc $P --mine --act I --claim I --others D $R3APPEAL --offer-window 40 --settle-wait 1800 --lat 13.6920 --lon -89.2170 $X >"$L/r3.out" 2>"$L/r3.log" </dev/null &
  BITAID_WALLET=r4 nohup target/release/bitaid-node --role responder --name r4-pc-cheat $P --mine --claim I --others D --bad-partial --accept-delay-ms 800 $X >"$L/r4.out" 2>"$L/r4.log" </dev/null &
  sleep 3
  echo "$ONION" > "$L/onion.txt"
  echo "PC_READY  onion: $ONION"
  ;;
report)
  cat "$L"/r*.out "$L"/arb1.out "$L"/archivist.out 2>/dev/null; grep -h "review\|unit of\|FAIL" "$L"/arb*.out 2>/dev/null | sed 's/arb[0-9]*-pc //' | sed 's/ — .*//' | sort | uniq -c; grep -h "link up\|link down\|pool key\|pool ready\|reserved\|co-signed\|stalling\|attestation share\|deemed" "$L"/*.log | tail -30
  ;;
stop)
  pkill -x bitaid-node; $CLI stop >/dev/null 2>&1; pkill -f "tor -f $HOME/bitaid-tor/torrc"; echo stopped
  ;;
esac
