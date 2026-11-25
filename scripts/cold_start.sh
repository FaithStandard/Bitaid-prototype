#!/bin/sh
# The caller's cold start over Tor (prototype issue #2): how long from pressing the alert, with no
# Tor running, until a Core's onion service answers. Termux, on the phone, with the PC's Core up.
#   PC=<pc onion> sh scripts/cold_start.sh wipe 10      Tor's cache wiped first (worst case)
#   PC=<pc onion> sh scripts/cold_start.sh restart 10   Tor restarted, cache kept (an app killed)
#   PC=<pc onion> sh scripts/cold_start.sh warm 10      Tor kept running (a reference)
# For a network switch, run "warm" and toggle airplane mode or Wi-Fi off during the pause it asks for.
# Each trial prints the marks of the issue, in seconds from T0 (the alert pressed):
#   T1 Tor bootstrapped 100%   T3 stream open to the Core's onion (a bare TCP connect through SOCKS)
#   T4 the Core's first byte back
# (T2, the onion descriptor fetched, is inside T3 without Tor's control port.) Results are appended
# to $HOME/cold_start.txt with the network type, if termux-api can tell it.
cd "$(dirname "$0")/.."
MODE=${1:-restart}; N=${2:-10}
D=$HOME/bitaid-tor; S=${TOR_SOCKS:-9160}
PC=${PC:-$CORE}; [ -n "$PC" ] || { echo "set PC to the PC's onion address"; exit 1; }
case "$PC" in *.*) ;; *) PC=$PC.onion ;; esac
OUT=$HOME/cold_start.txt
now() { date +%s.%N; }
since() { awk -v a="$1" -v b="$(now)" 'BEGIN { printf "%.2f", b - a }'; }
net() { termux-telephony-deviceinfo 2>/dev/null | grep -o '"network_type": *"[^"]*"' | cut -d'"' -f4; }
# a reference run first, so the torrc exists
[ -f $D/torrc ] || sh scripts/tor_up.sh >/dev/null || exit 1
echo "# $(date -u +%FT%TZ) mode=$MODE net=$(net) wifi=$(termux-wifi-connectioninfo 2>/dev/null | grep -o '"ssid": *"[^"]*"' | cut -d'"' -f4)" >> $OUT
for i in $(seq 1 $N); do
  if [ "$MODE" != warm ]; then
    pkill -f "tor -f $D/torrc" 2>/dev/null; sleep 2
    [ "$MODE" = wipe ] && rm -rf $D/data/cached-* $D/data/state $D/data/diff-cache
  else
    echo "trial $i: pause 5 s (switch the network now if testing a handoff)"; sleep 5
  fi
  T0=$(now)
  if [ "$MODE" != warm ]; then
    : > $D/tor.log
    tor -f $D/torrc >/dev/null 2>&1
    for j in $(seq 1 600); do grep -q "Bootstrapped 100" $D/tor.log 2>/dev/null && break; sleep 0.3; done
  fi
  T1=$(since $T0)
  # T3: a bare SOCKS5 CONNECT to the Core's gossip port, which returns once Tor has the rendezvous
  # (curl's own connect time stops at the local proxy)
  S0=$(now)
  python3 - "$S" "$PC" <<'PY' >/dev/null 2>&1
import socket, sys
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=180)
s.sendall(b"\x05\x01\x00"); s.recv(2)
h = sys.argv[2].encode()
s.sendall(b"\x05\x01\x00\x03" + bytes([len(h)]) + h + (7700).to_bytes(2, "big")); r = s.recv(10)
sys.exit(0 if len(r) > 1 and r[1] == 0 else 1)
PY
  T3=$(awk -v t1="$T1" -v c="$(since $S0)" 'BEGIN { printf "%.2f", t1 + c }')
  command -v python3 >/dev/null || T3=-
  # T4: the archive's first byte back over the same onion (the Core's machine), on the circuit T3 built
  R=$(curl -s -o /dev/null --max-time 180 --socks5-hostname 127.0.0.1:$S \
        -w '%{time_connect} %{time_starttransfer} %{http_code}' "http://$PC:7480/" 2>/dev/null)
  T4=$(since $T0)
  CODE=$(echo $R | cut -d' ' -f3)
  LINE="trial $i mode=$MODE T1=$T1 T3=$T3 T4=$T4 http=$CODE"
  echo "$LINE"; echo "$LINE" >> $OUT
done
# median, p95 and max of each mark over this run's trials
tail -n $N $OUT | awk -v n=$N '
  { for (k = 4; k <= 6; k++) { split($k, kv, "="); v[kv[1], NR] = kv[2] } }
  END {
    split("T1 T3 T4", ks, " ")
    for (q = 1; q <= 3; q++) {
      m = ks[q]; c = 0
      for (r = 1; r <= NR; r++) a[++c] = v[m, r] + 0
      for (x = 1; x <= c; x++) for (y = x + 1; y <= c; y++) if (a[y] < a[x]) { t = a[x]; a[x] = a[y]; a[y] = t }
      printf "%s median %.1f s  p95 %.1f s  max %.1f s\n", m, a[int((c + 1) / 2)], a[int(c * 0.95 + 0.999)], a[c]
    }
  }' | tee -a $OUT
