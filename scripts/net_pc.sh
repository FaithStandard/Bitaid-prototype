#!/bin/sh
# Internet test, PC side (WSL): the regtest chain, a gossip Core, oracle pool members 1-2 (2 stalls),
# the archivist, nine arbitrators (two corrupt), responders r3 (intervened) and r4 (sends a bad partial
# signature). One onion address carries
# the Core (7700), the archive (7480) and the chain's RPC (18443); nothing is opened on the router.
#   sh scripts/net_pc.sh start | report | stop | balances | sweep (CHAIN=public: where the test coins are, and back to the faucet)
#   APP=1 CHAIN=signet BLOCK=20 sh scripts/net_pc.sh start   for the Android app (M4): the whole pool
#     (members 1-4, none stalling) and three arbitrators here, no responder of the PC's own, so the
#     phone's app is the one that accepts; then  sh scripts/net_pc.sh alert  starts the caller
# Logs also go to LOGDIR (default: the Windows "Files for Claude\pc_logs" folder) so they can be read there.
cd "$(dirname "$0")/.."
. "$HOME/.cargo/env" 2>/dev/null
V=31.1; B=${BITCOIN_BIN:-$HOME/bitcoin-$V/bin}
# CHAIN=signet: a custom signet (challenge OP_TRUE) instead of regtest: nobody mines on demand, a block
# producer on this PC makes a block every BLOCK seconds (default 20), and every node waits for blocks as
# on a real chain. Its data is kept between runs, so only the first start mines the first 110 blocks.
# Waits of a minute or more are tuned for 20-second blocks; TIME_SCALE (default BLOCK/20, at least 1)
# stretches them for slower blocks. The devices must be started with the same TIME_SCALE.
TS=$(( ${BLOCK:-20} / 20 )); [ "$TS" -lt 1 ] && TS=1
export BITAID_TIME_SCALE=${TIME_SCALE:-$TS}
# CHAIN=public: the public signet, through the Windows node that START_bitaid_signet.bat runs (pruned,
# no transaction index: the nodes index the blocks of the run themselves). Blocks every ~10 minutes,
# so TIME_SCALE defaults to 30, and its coins come from a faucet, so every amount is divided by
# SAT_SCALE (default 100). The devices are started with the TIME_SCALE, SAT_SCALE and RPC_PASS shown.
[ "$CHAIN" = public ] && TS=30
export BITAID_TIME_SCALE=${TIME_SCALE:-$TS}
SS=1; [ "$CHAIN" = public ] && SS=100
export BITAID_SAT_SCALE=${SAT_SCALE:-$SS}
RPCPORT=18443; PASS=regtest
if [ "$CHAIN" = public ]; then
  WCONF=/mnt/c/Users/alber/bitaid-signet/bitcoin.conf
  PASS=$(sed -n 's/^rpcpassword=//p' "$WCONF" 2>/dev/null | tr -d '\r' | head -1)
  [ -n "$PASS" ] || { echo "NO_WINDOWS_SIGNET_NODE: run START_bitaid_signet.bat first ($WCONF)"; exit 1; }
  NET="-signet"; RPCPORT=38332; P2P=38333
  CLI="$B/bitcoin-cli -signet -rpcconnect=127.0.0.1 -rpcport=$RPCPORT -rpcuser=bitaid -rpcpassword=$PASS"
elif [ "$CHAIN" = signet ]; then
  NET="-signet -signetchallenge=51"; D=${SIGNET_DIR:-$HOME/bitaid-signet}; P2P=38333
else
  NET="-regtest"; D=${REGTEST_DIR:-$HOME/bitaid-regtest}; P2P=18444
fi
[ "$CHAIN" = public ] || CLI="$B/bitcoin-cli $NET -datadir=$D -rpcuser=bitaid -rpcpassword=regtest -rpcport=18443"
# many small coins in each wallet: every zero-fee transaction's fee child needs a confirmed coin of its
# own, and with 10-minute blocks change confirms too slowly to be reused (public signet; SMALL=1 elsewhere)
# (each fee child pays the node's estimate for the whole package, a few thousand sats at signet's
# usual 10 sat/vB: a fee coin is 15,000 sats)
fund_small() {  # wallet, lump in BTC, number of fee coins
  m="\"$($CLI -rpcwallet=$1 getnewaddress)\":$2"
  for i in $(seq 1 $3); do m="$m,\"$($CLI -rpcwallet=$1 getnewaddress)\":0.00015"; done
  $CLI -rpcwallet=$SRC -named sendmany amounts="{$m}" fee_rate=${FUND_RATE:-2} >/dev/null || { echo "FUNDING_FAILED ($1)"; exit 1; }
}
# until every test wallet's coins are confirmed (the next block can come from a template made before
# the funding was sent, so one block is not enough)
wait_funded() {
  for w in w caller r1 r3 r4; do
    while $CLI -rpcwallet=$w getbalances | tr -d ' \n' | grep -Eq '"untrusted_pending":([1-9]|0\.0*[1-9])'; do sleep 10; done
  done
}
# tops wallet $1 up to $2 BTC in coins of 0.0005 or more and to $3 fee coins (0.00015 to 0.0005)
topup() {
  read add n <<EOT
$($CLI -rpcwallet=$1 listunspent 0 | python3 -c "
import json,sys; u=json.load(sys.stdin); big=sum(x['amount'] for x in u if x['amount']>=0.0005)
fee=sum(1 for x in u if 0.00015<=x['amount']<0.0005)
print('%.8f' % max(0,$2-big), max(0,$3-fee))")
EOT
  [ -n "$n" ] || { echo "FUNDING_FAILED ($1: cannot read the wallet)"; exit 1; }
  # the lump in $4 coins (default 1): nodes sharing a wallet each take one, instead of queueing on
  # one coin's unconfirmed change (ten arbitrators' bonds from one lump were refused for an hour)
  k=${4:-1}; m=""
  if [ "$add" != "0.00000000" ]; then
    part=$(python3 -c "print('%.8f' % ($add/$k))")
    for i in $(seq 1 $k); do m="$m${m:+,}\"$($CLI -rpcwallet=$1 getnewaddress)\":$part"; done
  fi
  for i in $(seq 1 $n); do m="$m${m:+,}\"$($CLI -rpcwallet=$1 getnewaddress)\":0.00015"; done
  [ -z "$m" ] && { echo "$1: already funded"; return; }
  echo "$1: adding $add BTC and $n fee coins"
  $CLI -rpcwallet=$SRC -named sendmany amounts="{$m}" fee_rate=${FUND_RATE:-2} >/dev/null || { echo "FUNDING_FAILED ($1)"; exit 1; }
}
# merges the faucet wallet's coins: reclaims return many small coins, and a funding transaction that
# has to gather thousands of them pays more in fees than the wallet holds (2026-11-17). Batches of 400
# of the smallest confirmed coins, each sent back to the wallet at 1 sat/vB.
consolidate() {
  for round in $(seq 1 30); do
    ins=$($CLI -rpcwallet=$SRC listunspent 1 | python3 -c "
import json,sys; u=sorted(json.load(sys.stdin), key=lambda x: x['amount'])
print(len(u), json.dumps([{'txid':x['txid'],'vout':x['vout']} for x in u[:400]]))")
    count=${ins%% *}; list=${ins#* }
    echo "faucet wallet: $count coins"
    [ "$count" -le 60 ] && return 0
    $CLI -rpcwallet=$SRC -named sendall recipients="[\"$($CLI -rpcwallet=$SRC getnewaddress)\"]" inputs="$list" fee_rate=1 >/dev/null \
      || { echo "CONSOLIDATE_FAILED"; return 1; }
  done
}
WIN="/mnt/c/Users/alber/OneDrive/Documentos/Bitaid/10/v6/Files for Claude"
L=${LOGDIR:-$WIN/pc_logs}; mkdir -p "$L"
# the app's run: the pool the app looks for by default (bitaid), unless POOL says otherwise
[ "$APP" = 1 ] && POOL=${POOL:-bitaid}
case "$1" in
start)
  pkill -x bitaid-node 2>/dev/null; pkill -x rogue 2>/dev/null; sleep 1
  # REVIEW=1: the staged review (§10.3) — a captured tier 1 that no one appeals or challenges, drawn for
  # review (the phone's caller sets REVIEW_PCT=100), three independent panels of 5 drawn from 26 arbitrators
  if [ "$REVIEW" = 1 ]; then CHALLENGE=0; STALL=0; CAPTURE=1; ARBS=${ARBS:-26}; fi
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
  if [ "$CHAIN" = public ]; then
    $CLI getblockchaininfo | grep -q '"initialblockdownload": false' || { echo "WINDOWS_SIGNET_NODE_NOT_READY (not running, or still syncing)"; exit 1; }
    $CLI loadwallet bitaid >/dev/null 2>&1; SRC=bitaid
    for w in w caller r1 r3 r4; do $CLI createwallet $w >/dev/null 2>&1 || $CLI loadwallet $w >/dev/null 2>&1; done
    echo "faucet wallet: $($CLI -rpcwallet=bitaid getbalance) signet BTC"
    consolidate || exit 1
    # coins left in the test wallets by earlier runs count: each is only topped up to what it needs
    # the arbitrators' wallet scales with their number (ten: 0.015 in 12 coins and 25 fee coins)
    A=${ARBS:-10}
    topup w $(python3 -c "print('%.4f' % (0.0015*$A + 0.0006))") $(( A * 5 / 2 )) $(( A + 2 )); for w in caller r3 r4; do topup $w 0.001 6; done; topup r1 0.001 12  # r1 escalates: tier fees and units take fee coins too
    echo "wallets funded; waiting for the funding to confirm (about 10 minutes, sometimes more)"
    wait_funded
  else
  mkdir -p $D
  # a node of the other chain still answering on the RPC port (an earlier run): stop it first
  WANT=regtest; [ "$CHAIN" = signet ] && WANT=signet
  GOT=$($CLI getblockchaininfo 2>/dev/null | sed -n 's/.*"chain": "\([a-z]*\)".*/\1/p')
  if [ -n "$GOT" ] && [ "$GOT" != "$WANT" ]; then echo "stopping the $GOT node from an earlier run"; $CLI stop >/dev/null 2>&1; sleep 8; fi
  # TXINDEX=0: no transaction index, as on a pruned node (a rehearsal of the public signet)
  $CLI getblockcount >/dev/null 2>&1 || $B/bitcoind $NET -datadir=$D -rpcuser=bitaid -rpcpassword=regtest -rpcport=18443 \
      -rpcbind=127.0.0.1 -rpcallowip=127.0.0.1 -port=$P2P -listen=0 -fallbackfee=0.0001 -txindex=${TXINDEX:-1} -daemon
  for i in $(seq 1 60); do $CLI getblockcount >/dev/null 2>&1 && break; sleep 2; done
  $CLI createwallet w >/dev/null 2>&1 || $CLI loadwallet w >/dev/null 2>&1
  # (on signet each block needs real proof of work, a few seconds each: hence the high maxtries)
  H=$($CLI getblockcount); [ "$H" -lt 110 ] && { echo "mining the first $((110-H)) blocks (signet: several minutes, once)"; $CLI -rpcwallet=w generatetoaddress $((110-H)) $($CLI -rpcwallet=w getnewaddress) 1000000000 >/dev/null; }
  # protocol deadlines are block heights, so blocks come on a clock: every BLOCK seconds (signet: 20,
  # with real proof of work; regtest: 15, besides the blocks nodes mine on demand)
  pkill -f block_producer.sh 2>/dev/null
  [ "$CHAIN" = signet ] || BLOCK=${BLOCK:-15}
  CLI="$CLI" BLOCK=$BLOCK nohup sh scripts/block_producer.sh >/dev/null 2>&1 </dev/null &
  for w in caller r1 r3 r4; do
    $CLI createwallet $w >/dev/null 2>&1 || $CLI loadwallet $w >/dev/null 2>&1
    if [ "$SMALL" = 1 ]; then SRC=w; fund_small $w 0.002 12
    else for i in 1 2 3; do $CLI -rpcwallet=w sendtoaddress $($CLI -rpcwallet=$w getnewaddress) 3 >/dev/null; done; fi
  done
  # (SMALL=1: w also splits off small coins to itself, as on the public signet)
  [ "$SMALL" = 1 ] && { SRC=w; fund_small w 0.015 40; }
  if [ "$CHAIN" = signet ]; then h=$($CLI getblockcount); while [ $($CLI getblockcount) -le $h ]; do sleep 2; done; wait_funded
  else $CLI -rpcwallet=w generatetoaddress 1 $($CLI -rpcwallet=w getnewaddress) >/dev/null; fi
  fi
  echo "chain: $($CLI getblockchaininfo | sed -n 's/.*"chain": "\([a-z]*\)".*/\1/p') height $($CLI getblockcount)"
  # APP=1: the app as a light client of the Core (phone-light): pool1 and pool2 answer as its 2 tip sources
  TP=""; [ "$APP" = 1 ] && TP="7701 7702"
  OUT=$(sh scripts/tor_up.sh 7700 7480 18443:$RPCPORT $TP) || { echo "$OUT"; exit 1; }
  ONION=$(echo "$OUT" | sed -n 's/^ONION=//p')
  [ -z "$NO_TOR" ] && export BITAID_SOCKS=127.0.0.1:${TOR_SOCKS:-9160}
  export BITAID_RPC=http://bitaid:$PASS@127.0.0.1:$RPCPORT BITAID_SELF_ONION=$ONION
  # faucet coins (public signet): every bond's and funding output's keys are kept, so what a run leaves
  # under them can be taken back a day later (sh scripts/net_pc.sh reclaim)
  [ "$CHAIN" = public ] && { mkdir -p "$WIN/keys"; export BITAID_KEYFILE="$WIN/keys/bitaid_keys_pc.jsonl"; }
  # nodes without a transaction index read the blocks of the run themselves, from this height on
  export BITAID_INDEX_FROM=${INDEX_FROM:-$(( $($CLI getblockcount) - 1 ))}
  # timed messages are anchored by a checkpoint every block on a test run
  export BITAID_CHECKPOINT_BLOCKS=${CHECKPOINT_BLOCKS:-1}
# over Tor no wait on a reply is shorter than the links' worst (see lib.rs `reply`)
export BITAID_REPLY_MIN=${REPLY_MIN:-900}
  X="--exit-after ${WAIT:-10800}"; P="--peer 127.0.0.1:7700 --pool ${POOL:-tor1}"
  rm -f "$L"/*.log "$L"/*.out
  # bonded links: the Core demands a proof of stake from every peer; a proof names the address the
  # peer dialled, so the Core accepts its own onion address besides the local port
  BITAID_PUBKEY_FILE="$L/core.pub" BITAID_LINK_NAMES="${ONION%.onion}.onion:7700" BITAID_WALLET=w nohup target/release/bitaid-node --role core --name core-pc --listen-gossip 127.0.0.1:7700 >/dev/null 2>"$L/core.log" </dev/null &
  sleep 1
  # (APP=1: pool1 and pool2 also listen on gossip, each with its own onion port, and answer the app's
  # tip checks: the light client signs only when 2 independent sources agree with its Core)
  # (the keys go to a folder without spaces: $L is under "Files for Claude", and $(lk) is word-split)
  K=$HOME/bitaid-light; mkdir -p "$K"; rm -f "$K"/*.pub
  lg() { [ "$APP" = 1 ] && [ $1 -le 2 ] && echo "--listen-gossip 127.0.0.1:770$1"; }
  lk() { [ "$APP" = 1 ] && [ $1 -le 2 ] && echo "BITAID_PUBKEY_FILE=$K/pool$1.pub BITAID_LINK_NAMES=${ONION%.onion}.onion:770$1"; }
  env $(lk 1) BITAID_WALLET=w nohup target/release/bitaid-node --role pool-member --name pool1-pc --id 1 --n 4 --t 3 $(lg 1) --setup-wait ${WAIT:-10800} $P $X >/dev/null 2>"$L/pool1.log" </dev/null &
  if [ "$APP" = 1 ]; then
    # the app's run: the whole pool on this machine, none stalling (the devices run none of it)
    for m in 2 3 4; do
      env $(lk $m) BITAID_WALLET=w nohup target/release/bitaid-node --role pool-member --name pool$m-pc --id $m --n 4 --t 3 $(lg $m) --setup-wait ${WAIT:-10800} $P $X >/dev/null 2>"$L/pool$m.log" </dev/null &
    done
  else
  BITAID_WALLET=w nohup target/release/bitaid-node --role pool-member --name pool2-pc-stall --id 2 --n 4 --t 3 --stall --setup-wait ${WAIT:-10800} $P $X >/dev/null 2>"$L/pool2.log" </dev/null &
  fi
  BITAID_WALLET=w nohup target/release/bitaid-node --role archivist --name archivist-pc --listen 127.0.0.1:7480 --public-url http://$ONION:7480 $P $X >"$L/archivist.out" 2>"$L/archivist.log" </dev/null &
  [ "$APP" = 1 ] && { ARBS=${ARBS:-3}; CAPTURE=0; CHALLENGE=0; STALL=0; CORRUPT=""; }
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
  # (APP=1: no responder here; the app's is the only one, so the alert reaches it and it accepts)
  [ "$APP" = 1 ] || BITAID_WALLET=r3 nohup target/release/bitaid-node --role responder --name r3-pc $P --mine --act I --claim I --others D $R3APPEAL --offer-window 40 --settle-wait 1800 --lat 13.6920 --lon -89.2170 $X >"$L/r3.out" 2>"$L/r3.log" </dev/null &
  [ "$APP" = 1 ] || BITAID_WALLET=r4 nohup target/release/bitaid-node --role responder --name r4-pc-cheat $P --mine --claim I --others D --bad-partial --accept-delay-ms 800 $X >"$L/r4.out" 2>"$L/r4.log" </dev/null &
  sleep 3
  # ROGUE=1: a hostile stranger attacks the Core's gossip port ROGUE_WAIT seconds in, while the case
  # runs (examples/rogue.rs): oversized and malformed messages, stale and future-dated ones, a replay,
  # a height from the future, a flood and a connection storm; the honest nodes must still finish
  if [ "${ROGUE:-0}" = 1 ] && [ -x target/release/examples/rogue ]; then
    BITAID_WALLET=w nohup target/release/examples/rogue --peer 127.0.0.1:7700 --wait ${ROGUE_WAIT:-7200} >"$L/rogue.out" 2>"$L/rogue.log" </dev/null &
  fi
  # HOSTILE=1: an outsider with coins and a link forges what the chain's records might seem to allow
  # (see m3_arb_local.sh): the case must be heard as if none of it existed
  if [ "${HOSTILE:-0}" = 1 ]; then
    BITAID_WALLET=w nohup target/release/bitaid-node --role hostile --name hostile-pc $P --wait 7200 >"$L/hostile.out" 2>"$L/hostile.log" </dev/null &
  fi
  echo "$ONION" > "$L/onion.txt"; echo "$BITAID_INDEX_FROM" > "$L/index_from.txt"
  echo "PC_READY  onion: $ONION  TIME_SCALE=$BITAID_TIME_SCALE SAT_SCALE=$BITAID_SAT_SCALE INDEX_FROM=$BITAID_INDEX_FROM"
  [ "$APP" = 1 ] && echo "APP_SETTINGS  peer: $ONION:7700  rpc: http://bitaid:$PASS@$ONION:18443  wallet: r1  pool: ${POOL:-tor1}  lat: ${APP_LAT:-13.6929}  lon: ${APP_LON:--89.2182}"
  if [ "$APP" = 1 ]; then
    # the light client's three fields (Settings): written to app_light.txt in the Windows folder too,
    # to copy to the phone instead of typing 64-character keys
    for _ in $(seq 1 20); do [ -s "$L/core.pub" ] && [ -s "$K/pool1.pub" ] && [ -s "$K/pool2.pub" ] && break; sleep 1; done
    AH=$(( $($CLI getblockcount) - 12 )); [ $AH -lt 0 ] && AH=0
    { echo "Core pubkey: $(cat "$L/core.pub")"
      echo "Tip sources: $(cat "$K/pool1.pub")@$ONION:7701,$(cat "$K/pool2.pub")@$ONION:7702"
      echo "Anchor: $AH:$($CLI getblockhash $AH)"; } > "$WIN/app_light.txt"
    echo "APP_LIGHT (Settings; also in app_light.txt):"; sed 's/^/  /' "$WIN/app_light.txt"
  fi
  [ "$CHAIN" = public ] && echo "RPC_PASS=$PASS"
  ;;
alert)
  # the app's run (APP=1): a caller on this machine at the position the app was set to, once the app
  # shows on duty. It alerts, takes the app's acceptance and goes on to settlement.
  POOL=${POOL:-bitaid}
  export BITAID_RPC=http://bitaid:$PASS@127.0.0.1:$RPCPORT BITAID_REPLY_MIN=${REPLY_MIN:-900}
  export BITAID_SELF_ONION=$(cat "$L/onion.txt" 2>/dev/null); [ -z "$NO_TOR" ] && export BITAID_SOCKS=127.0.0.1:${TOR_SOCKS:-9160}
  P="--peer 127.0.0.1:7700 --pool ${POOL:-tor1}"
  BITAID_WALLET=caller target/release/bitaid-node --role caller --name caller-pc $P --mine --window ${WINDOW:-120} \
      --dispute-blocks ${DISPUTE_BLOCKS:-3} --commit-blocks ${COMMIT_BLOCKS:-20} --reveal-blocks ${REVEAL_BLOCKS:-6} \
      --settle-wait 1800 --min-arbs 0 --lat ${APP_LAT:-13.6929} --lon ${APP_LON:--89.2182} \
      2>"$L/caller.log" | tee "$L/caller.out"
  ;;
audit)
  # two nodes that saw nothing of the run read every arbitrator's record: one from its links, one from
  # the chain and the archivist's logs alone. Run while the PC side is still up; INDEX_FROM as printed.
  export BITAID_RPC=http://bitaid:$PASS@127.0.0.1:$RPCPORT BITAID_INDEX_FROM=${INDEX_FROM:-$(cat "$L/index_from.txt")} BITAID_CHECKPOINT_BLOCKS=${CHECKPOINT_BLOCKS:-1}
  # the archivist announces its onion address: this machine's own, read locally, any other through Tor
  export BITAID_SELF_ONION=$(cat "$L/onion.txt" 2>/dev/null); [ -z "$NO_TOR" ] && export BITAID_SOCKS=127.0.0.1:${TOR_SOCKS:-9160}
  P="--peer 127.0.0.1:7700 --pool ${POOL:-tor1}"
  # the pool named by its keys, as the PC's member logged them: no wait for every member to be online
  PID=$(grep -h "pool keys:" "$L/pool1.log" 2>/dev/null | head -1 | sed 's/.*attestation \([0-9a-f]*\), co-signing \([0-9a-f]*\).*/\2\1/')
  [ -n "$PID" ] && P="$P --pool-id $PID"
  BITAID_WALLET=w target/release/bitaid-node --role audit --name audit-links $P --links >"$L/audit-links.out" 2>"$L/audit-links.log"
  BITAID_WALLET=w target/release/bitaid-node --role audit --name audit-archive $P >"$L/audit-archive.out" 2>"$L/audit-archive.log"
  ra=$(grep '^record' "$L/audit-links.out" | sort | sha256sum); rb=$(grep '^record' "$L/audit-archive.out" | sort | sha256sum)
  grep -h "PASS\|FAIL" "$L/audit-links.out" "$L/audit-archive.out"
  if [ "$ra" = "$rb" ] && grep -q '^record momentum' "$L/audit-archive.out"; then echo "AUDIT_PASS: the record read from the archive alone equals the record read from the links ($(grep -c '^record tier' "$L/audit-archive.out") tiers)"; else echo "AUDIT_FAIL: the two records differ"; fi | tee "$L/audit.out"
  ;;
consolidate)
  # the faucet wallet's coins merged (run while no test runs; it needs START_bitaid_signet.bat)
  $CLI loadwallet bitaid >/dev/null 2>&1; SRC=bitaid
  consolidate && echo CONSOLIDATED
  ;;
report)
  cat "$L"/hostile.out "$L"/audit.out 2>/dev/null
  cat "$L"/rogue.out 2>/dev/null; grep -h "refused .* claims height" "$L"/*.log 2>/dev/null | head -3; grep -hc "flooding\|longer than the limit\|malformed" "$L"/core.log 2>/dev/null
  cat "$L"/r*.out "$L"/arb1.out "$L"/archivist.out 2>/dev/null; grep -h "review\|unit of\|FAIL" "$L"/arb*.out 2>/dev/null | sed 's/arb[0-9]*-pc //' | sed 's/ — .*//' | sort | uniq -c; grep -h "link up\|link down\|pool key\|pool ready\|reserved\|co-signed\|stalling\|attestation share\|deemed" "$L"/*.log | tail -30
  ;;
attack)
  # the hostile peer against a lone Core on this machine: every attack of examples/rogue.rs, the
  # bonded-link ones included. The Core checks stakes on the chain (CHAIN=public: the Windows signet
  # node), and the rogue pays its own stakes from wallet w (once; kept in ~/.bitaid and reused)
  export BITAID_RPC=http://bitaid:$PASS@127.0.0.1:$RPCPORT BITAID_WALLET=w
  $CLI loadwallet w >/dev/null 2>&1
  nohup target/release/bitaid-node --role core --name core-attack --listen-gossip 127.0.0.1:7790 >/dev/null 2>"$L/core_attack.log" </dev/null &
  sleep 3
  for i in 1 2; do
    # (the first round may wait a block for the rogue's stakes: 40 minutes allowed)
    timeout 2400 target/release/examples/rogue --peer 127.0.0.1:7790 2>&1 | tee "$L/rogue_attack_$i.out" | grep -E "PASS|FAIL|passed"
  done
  pkill -f "core-attack"
  echo "ATTACK_DONE"
  ;;
reclaim)
  # coins left under this PC's bonds and funding outputs by earlier runs, back to the faucet wallet once
  # their fallback height has passed (a day on the public signet); also the devices' key files if they
  # were copied into the keys folder
  export BITAID_RPC=http://bitaid:$PASS@127.0.0.1:$RPCPORT BITAID_WALLET=bitaid
  $CLI loadwallet bitaid >/dev/null 2>&1
  for f in "$WIN"/keys/*.jsonl; do [ -f "$f" ] && { echo "== $f"; target/release/bitaid-node --role reclaim --keys "$f"; }; done
  # the devices reclaim their own through this PC's onion address: the chain's RPC published again
  OUT=$(sh scripts/tor_up.sh 7700 7480 18443:$RPCPORT) || { echo "$OUT"; exit 1; }
  echo; echo "DEVICES_MAY_RECLAIM_NOW (onion: $(echo "$OUT" | sed -n 's/^ONION=//p')) - keep this window open until they finish"
  ;;
balances|sweep)
  # where the test coins are: every test wallet on the Windows node (payouts, returned bonds and released
  # units go back to these, not to the faucet wallet; each run only tops them up), the coins still under
  # the key files' bonds and funding outputs (from the reclaim, which also takes back what is due), and,
  # with "sweep", everything in the test wallets sent back to the faucet wallet
  export BITAID_RPC=http://bitaid:$PASS@127.0.0.1:$RPCPORT BITAID_WALLET=bitaid
  $CLI loadwallet bitaid >/dev/null 2>&1
  bal() { $CLI -rpcwallet=$1 getbalances 2>/dev/null | python3 -c "import json,sys
try:
    d=json.load(sys.stdin)['mine']; print('%.8f confirmed, %.8f unconfirmed, %.8f immature' % (d['trusted'], d['untrusted_pending'], d['immature']))
except Exception: print('not loaded')"; }
  echo "faucet wallet (bitaid): $(bal bitaid)"
  for w in w caller r1 r3 r4; do $CLI loadwallet $w >/dev/null 2>&1; echo "test wallet $w: $(bal $w)"; done
  for f in "$WIN"/keys/*.jsonl; do [ -f "$f" ] && target/release/bitaid-node --role reclaim --keys "$f" ; done
  if [ "$1" = sweep ]; then
    A=$($CLI -rpcwallet=bitaid getnewaddress)
    for w in w caller r1 r3 r4; do
      R=$($CLI -rpcwallet=$w sendall "[\"$A\"]" 2>&1) && echo "swept $w: $(echo "$R" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("txid","?"))' 2>/dev/null)" || echo "$w: nothing to sweep ($(echo "$R" | tail -1))"
    done
    echo "SWEPT: the coins reach the faucet wallet once the next block confirms them (about 10 minutes)"
  fi
  ;;
stop)
  pkill -x bitaid-node; pkill -f block_producer.sh 2>/dev/null; [ "$CHAIN" = public ] || $CLI stop >/dev/null 2>&1; pkill -f "tor -f $HOME/bitaid-tor/torrc"; echo stopped
  ;;
esac
