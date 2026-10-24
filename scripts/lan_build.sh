#!/bin/sh
# Builds the oracle binaries on this machine (Raspberry Pi / Linux, or a phone in Termux).
set -e
cd "$(dirname "$0")/.."
if ! command -v cargo >/dev/null 2>&1; then
  if [ -n "$PREFIX" ] && echo "$PREFIX" | grep -q com.termux; then
    pkg install -y rust
  else
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
    . "$HOME/.cargo/env"
  fi
fi
if ! command -v cc >/dev/null 2>&1; then
  echo "No C compiler found. On the Pi run:  sudo apt install -y build-essential   then run this again."; exit 1
fi
echo "Building (10-30 minutes on a Pi or phone the first time)..."
# One job at a time: avoids Android's "Text file busy" race on build scripts, and fits a Pi's memory.
CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS:-1} cargo build --release -p bitaid-oracle
echo BUILD_DONE
