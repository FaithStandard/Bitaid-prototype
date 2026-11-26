#!/bin/sh
# M4 step 2 on a real device: the app's in-process Tor (Arti, crates/bitaid-tor) against C Tor, by the
# same marks as scripts/cold_start.sh. Termux on the phone, with the PC's run up (its onion answering).
#   cargo build --release -p bitaid-tor             once (Arti is large: allow 30-60 minutes on a phone)
#   PC=<pc onion> sh scripts/arti_check.sh 10       10 trials, Arti restarted each time, its cache kept
# Each trial: T1 = Arti bootstrapped (TOR_READY), T4 = the PC's archive answered through Arti's
# authenticated SOCKS listener; plus a check that the listener refuses a client without its secret.
# Results appended to $HOME/arti_check.txt; a failed trial's Arti log is kept as $HOME/arti_fail_<n>.log.
cd "$(dirname "$0")/.."
N=${1:-10}
PC=${PC:-$CORE}; [ -n "$PC" ] || { echo "set PC to the PC's onion address"; exit 1; }
case "$PC" in *.*) ;; *) PC=$PC.onion ;; esac
BIN=target/release/bitaid-tor; [ -x $BIN ] || { echo "build it first: cargo build --release -p bitaid-tor"; exit 1; }
OUT=$HOME/arti_check.txt; LOG=$HOME/arti_check.log
now() { date +%s.%N; }
since() { awk -v a="$1" -v b="$(now)" 'BEGIN { printf "%.2f", b - a }'; }
echo "# $(date -u +%FT%TZ) arti restart" >> $OUT
for i in $(seq 1 $N); do
  pkill -f "$BIN" 2>/dev/null; sleep 2
  T0=$(now)
  $BIN --debug > $LOG 2>&1 &
  for j in $(seq 1 600); do grep -q "TOR_READY\|TOR_FAILED" $LOG 2>/dev/null && break; sleep 0.3; done
  T1=$(since $T0)
  SOCKS=$(grep -o "BITAID_SOCKS=.*" $LOG | cut -d= -f2)
  CRED=${SOCKS%@*}; ADDR=${SOCKS#*@}
  # the secret gets through; no secret is refused
  CODE=$(curl -s -o /dev/null --max-time 180 --socks5-hostname "$ADDR" --proxy-user "$CRED" -w '%{http_code}' "http://$PC:7480/" 2>/dev/null)
  T4=$(since $T0)
  REFUSED=$(curl -s -o /dev/null --max-time 20 --socks5-hostname "$ADDR" -w '%{http_code}' "http://$PC:7480/" 2>/dev/null)
  LINE="trial $i mode=arti T1=$T1 T3=- T4=$T4 http=$CODE without_secret=$REFUSED"
  echo "$LINE"; echo "$LINE" >> $OUT
  # a failed trial keeps Arti's log (no secret in it)
  [ "$CODE" = 200 ] || cp $LOG $HOME/arti_fail_$i.log
done
pkill -f "$BIN" 2>/dev/null
tail -n $N $OUT | awk '
  { for (k = 4; k <= 6; k++) { split($k, kv, "="); v[kv[1], NR] = kv[2] } }
  END {
    split("T1 T4", ks, " ")
    for (q = 1; q <= 2; q++) {
      m = ks[q]; c = 0
      for (r = 1; r <= NR; r++) a[++c] = v[m, r] + 0
      for (x = 1; x <= c; x++) for (y = x + 1; y <= c; y++) if (a[y] < a[x]) { t = a[x]; a[x] = a[y]; a[y] = t }
      printf "%s median %.1f s  p95 %.1f s  max %.1f s\n", m, a[int((c + 1) / 2)], a[int(c * 0.95 + 0.999)], a[c]
    }
  }' | tee -a $OUT
