#!/usr/bin/env python3
"""Toy TCP echo service, used only to test the tunnel end-to-end."""
import socket
import sys
import threading

port = int(sys.argv[1]) if len(sys.argv) > 1 else 9000
srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", port))
srv.listen(5)
print(f"[echo] listening on 127.0.0.1:{port}")

def handle(conn):
    with conn:
        while True:
            data = conn.recv(4096)
            if not data:
                break
            conn.sendall(data)

while True:
    conn, addr = srv.accept()
    threading.Thread(target=handle, args=(conn,), daemon=True).start()
