#!/bin/sh
# One-time setup of the Bitaid test node inside WSL2 (Ubuntu) on a Windows PC.
#   curl -sSfL https://raw.githubusercontent.com/FaithStandard/Bitaid-prototype/main/scripts/wsl_setup.sh | sh
# Installs build tools and Tor (asks for your Ubuntu password once), Rust, Bitcoin Core 31.1 (checksum
# verified), fetches the prototype and builds it. Regtest only: no real funds anywhere.
set -e
sudo apt-get update -qq && sudo apt-get install -y -qq build-essential pkg-config curl git tor python3 >/dev/null
sudo systemctl disable --now tor >/dev/null 2>&1 || true   # our scripts run their own Tor instance
if ! command -v cargo >/dev/null 2>&1; then
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal >/dev/null
fi
. "$HOME/.cargo/env"
V=31.1; F=bitcoin-$V-x86_64-linux-gnu.tar.gz
if [ ! -x "$HOME/bitcoin-$V/bin/bitcoind" ]; then
  cd "$HOME"
  curl -sSfO https://bitcoincore.org/bin/bitcoin-core-$V/$F && curl -sSfO https://bitcoincore.org/bin/bitcoin-core-$V/SHA256SUMS
  grep " $F\$" SHA256SUMS | sha256sum -c - && python3 -c "import tarfile,sys; tarfile.open(sys.argv[1]).extractall(sys.argv[2])" $F "$HOME" && rm -f $F
fi
cd "$HOME"
[ -d bitaid-prototype/.git ] || git clone -q https://github.com/FaithStandard/Bitaid-prototype bitaid-prototype
cd bitaid-prototype && git pull -q
cargo build --release -p bitaid-node 2>&1 | tail -1
echo "SETUP_DONE"
