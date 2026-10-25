#!/bin/sh
# Starts this device's own Tor (separate from any system Tor) with an onion service for the given
# local ports, and prints the onion address.  sh scripts/tor_up.sh 7700 7480
# Tor's SOCKS port for outgoing onion connections is TOR_SOCKS (default 9160).
D=$HOME/bitaid-tor; S=${TOR_SOCKS:-9160}
command -v tor >/dev/null || { [ -n "$PREFIX" ] && pkg install -y tor; }
command -v tor >/dev/null || { echo "TOR_NOT_INSTALLED"; exit 1; }
mkdir -p $D/hs $D/data; chmod 700 $D/hs
{
  echo "SocksPort $S"; echo "DataDirectory $D/data"; echo "Log notice file $D/tor.log"; echo "RunAsDaemon 1"
  if [ $# -gt 0 ]; then echo "HiddenServiceDir $D/hs"; for p in "$@"; do echo "HiddenServicePort $p 127.0.0.1:$p"; done; fi
} > $D/torrc
pkill -f "tor -f $D/torrc" 2>/dev/null; sleep 1
tor -f $D/torrc >/dev/null 2>&1
for i in $(seq 1 90); do grep -q "Bootstrapped 100" $D/tor.log 2>/dev/null && break; sleep 2; done
grep -q "Bootstrapped 100" $D/tor.log || { echo "TOR_NOT_BOOTSTRAPPED"; tail -5 $D/tor.log; exit 1; }
[ $# -gt 0 ] && for i in $(seq 1 30); do [ -s $D/hs/hostname ] && break; sleep 1; done
echo "TOR_READY socks 127.0.0.1:$S"
[ -s $D/hs/hostname ] && echo "ONION=$(cat $D/hs/hostname)"
exit 0
