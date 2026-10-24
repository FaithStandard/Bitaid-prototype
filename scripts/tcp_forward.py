#!/usr/bin/env python3
"""Forwards a TCP port to another host, for networks whose Wi-Fi clients cannot reach each other.
   python3 scripts/tcp_forward.py LISTEN_PORT TARGET_HOST TARGET_PORT"""
import socket, sys, threading

def pipe(a, b):
    try:
        while True:
            d = a.recv(65536)
            if not d:
                break
            b.sendall(d)
    except OSError:
        pass
    finally:
        for s in (a, b):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

def main():
    lp, host, tp = int(sys.argv[1]), sys.argv[2], int(sys.argv[3])
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", lp))
    srv.listen(64)
    print(f"forwarding :{lp} -> {host}:{tp}", flush=True)
    while True:
        c, _ = srv.accept()
        try:
            t = socket.create_connection((host, tp), timeout=10)
            t.settimeout(None)
        except OSError as e:
            print(f"target unreachable: {e}", flush=True)
            c.close()
            continue
        for a, b in ((c, t), (t, c)):
            threading.Thread(target=pipe, args=(a, b), daemon=True).start()

main()
