#!/bin/sh
# Phone side: members 5-7 (member 6 lies on attestation), connecting to the Pi's relay.
# Usage: sh scripts/lan_phone.sh [PI_IP]   (default 192.168.1.147)
cd "$(dirname "$0")/.."
PI=${1:-192.168.1.147}
for i in 5 6 7; do
  extra=""; [ $i = 6 ] && extra="--liar"
  target/release/bitaid-oracle-node --hub $PI:7400 --id $i --n 7 --t 4 --batch 20 $extra &
done
echo "Members 5-7 running against $PI. Press Ctrl+C when the Pi says Done."
wait
