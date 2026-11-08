#!/bin/sh
# The escrows on the real Liquid testnet, from the PC (WSL). Runs an Elements node on liquidtestnet in
# WSL, with its own wallet, and the escrow test tools/liquid/t18_liquid.py against it: funding output,
# incident transaction (scoped key + FROST co-signature), the pre-signed set with explicit fees,
# attested payouts, a wrong attestation refused by the node, slices, bond forfeiture, fallback.
#
#   sh scripts/liquid_pc.sh setup    # install Elements (from the tarball in the Windows folder), start, make the wallet
#   sh scripts/liquid_pc.sh status   # sync progress, balance, the address for the faucet
#   sh scripts/liquid_pc.sh run      # the test (needs the node synced and about 0.0015 L-BTC from the faucet)
#   sh scripts/liquid_pc.sh stop
#
# Test chains only: el.py refuses Liquid mainnet.
WIN=${WIN:-"/mnt/c/Users/alber/OneDrive/Documentos/Bitaid/10/v6/Files for Claude"}
V=elements-23.3.4
BIN="$HOME/$V/bin"
DD="$HOME/.elements-testnet"
CONF="$DD/elements.conf"
cli() { "$BIN/elements-cli" -datadir="$DD" "$@"; }
# waits for the node to answer (it can take minutes to reload its block index after a restart),
# then makes sure the wallet is open; quiet when it already is
ready() {
  "$BIN/elements-cli" -datadir="$DD" -rpcwait -rpcwaittimeout=1800 getblockcount >/dev/null 2>&1 || { echo "NOT_READY: the node does not answer"; exit 1; }
  cli -rpcwallet=w getwalletinfo >/dev/null 2>&1 || cli loadwallet w >/dev/null 2>&1 || cli createwallet w >/dev/null 2>&1
}
num() { python3 -c "import json,sys
try:
    d=json.load(sys.stdin); print(d.get('bitcoin', d) if isinstance(d, dict) else d)
except Exception: print('?')"; }
LOG="$WIN/pc_logs"
# one faucet address, kept (any address of the wallet works; showing the same one avoids confusion)
addr() { [ -s "$DD/faucet_address" ] || cli -rpcwallet=w getnewaddress > "$DD/faucet_address"; cat "$DD/faucet_address"; }

case "$1" in
setup)
  if [ ! -x "$BIN/elementsd" ]; then
    # unpacked with Python: the tar of recent Ubuntu uses a system call WSL1 lacks ("Function not implemented")
    python3 -c "import sys, tarfile; tarfile.open(sys.argv[1]).extractall(sys.argv[2])" \
      "$WIN/$V-x86_64-linux-gnu.tar.gz" "$HOME" || { echo "SETUP_FAILED: cannot unpack $V"; exit 1; }
    [ -x "$BIN/elementsd" ] || { echo "SETUP_FAILED: $BIN/elementsd missing after unpacking"; exit 1; }
  fi
  mkdir -p "$DD"
  if [ ! -f "$CONF" ]; then
    P=$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')
    cat > "$CONF" <<EOF
chain=liquidtestnet
[liquidtestnet]
# no Bitcoin node to check peg-ins against: this node only follows the Liquid testnet
validatepegin=0
# keep the last ~2 GB of blocks only
prune=2000
fallbackfee=0.00000100
server=1
daemon=1
rpcbind=127.0.0.1
rpcallowip=127.0.0.1
rpcport=18892
rpcuser=bitaid
rpcpassword=$P
# open the wallet whenever the node starts (after a power cut too)
wallet=w
EOF
  fi
  grep -q '^wallet=w' "$CONF" || echo "wallet=w" >> "$CONF"
  if cli getblockcount >/dev/null 2>&1 || cli getblockcount 2>&1 | grep -q "Loading"; then
    echo "(the node is already running)"
  else
    "$BIN/elementsd" -datadir="$DD" || { echo "SETUP_FAILED: elementsd did not start"; exit 1; }
  fi
  ready
  echo "LIQUID_NODE_STARTED"
  echo "Faucet address (paste at https://liquidtestnet.com/faucet, L-BTC, two or three times):"
  addr
  echo "Sync: sh scripts/liquid_pc.sh status   (wait for 'synced: yes')"
  ;;
status)
  ready
  cli getblockchaininfo | python3 -c "import json,sys; d=json.load(sys.stdin); print('blocks', d['blocks'], 'headers', d['headers'], 'progress %.4f' % d['verificationprogress'], 'synced:', 'yes' if not d['initialblockdownload'] and d['blocks'] >= d['headers'] - 2 else 'no')"
  echo "balance: $(cli -rpcwallet=w getbalance | num) L-BTC (confirmed), $(cli -rpcwallet=w getunconfirmedbalance | num) unconfirmed (coins show once the sync passes their block)"
  echo "faucet address: $(addr)"
  ;;
run)
  ready
  IBD=$(cli getblockchaininfo | python3 -c "import json,sys; print(json.load(sys.stdin)['initialblockdownload'])")
  [ "$IBD" = False ] || { echo "NOT_READY: the node is still syncing (sh scripts/liquid_pc.sh status)"; exit 1; }
  mkdir -p "$LOG" && cd "$LOG" || exit 1
  ECLI="$BIN/elements-cli -datadir=$DD" CHAIN=liquidtestnet SCALE=${SCALE:-10} \
    python3 "$HOME/bitaid-prototype/tools/liquid/t18_liquid.py" 2>&1 | tee "$LOG/liquid_t18.txt"
  echo "LIQUID_DONE (output in pc_logs/liquid_t18.txt)"
  ;;
check)
  # what Claude needs to see when the wallet will not open; saved to pc_logs/liquid_check.txt
  mkdir -p "$LOG"
  {
    date
    echo "--- conf"; grep -v rpcpassword "$CONF"
    echo "--- blocks"; cli getblockcount 2>&1
    echo "--- listwallets"; cli listwallets 2>&1
    echo "--- listwalletdir"; cli listwalletdir 2>&1
    echo "--- wallet files"; ls -la "$DD/liquidtestnet/wallets/" "$DD/liquidtestnet/wallets/w" 2>&1
    echo "--- loadwallet w"; cli loadwallet w 2>&1
    echo "--- getwalletinfo"; cli -rpcwallet=w getwalletinfo 2>&1
    echo "--- balances"; cli -rpcwallet=w getbalances 2>&1
    echo "--- debug.log, wallet and error lines"; grep -i "wallet\|error" "$DD/liquidtestnet/debug.log" | tail -30
  } > "$LOG/liquid_check.txt" 2>&1
  cat "$LOG/liquid_check.txt"
  ;;
stop)
  cli stop
  ;;
*)
  echo "usage: sh scripts/liquid_pc.sh setup|status|run|check|stop"; exit 1
  ;;
esac
