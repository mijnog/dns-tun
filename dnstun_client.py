#!/usr/bin/env python3
"""
dnstun_client.py -- DNS-tunneling PoC client.

Opens a local TCP listener. Each connection to it gets tunneled, byte for
byte, through DNS queries to the dnstun_server.py instance, which relays
it to the real target service. From the point of view of anything between
this client and the tunnel server, all traffic looks like DNS queries and
responses on port 53 (or whatever --server-port you point it at).

Usage:
    python3 dnstun_client.py --listen 127.0.0.1:2022 \
        --server 203.0.113.10:53 --domain tunnel.test

Then: ssh -p 2022 user@127.0.0.1   (or point any client at the local port)

Research / authorized-testing use only.
"""
import argparse
import queue
import socket
import struct
import threading
import time

import dnstun_proto as proto

POLL_INTERVAL = 0.05  # seconds between downstream polls when idle


class TunnelSession:
    def __init__(self, server_addr, domain_suffix, local_sock, session_id):
        self.server_addr = server_addr
        self.domain = domain_suffix
        self.local_sock = local_sock
        self.session_id = session_id
        self.seq = 0
        self.closed = False
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.settimeout(2.0)
        self.send_lock = threading.Lock()

    def _query(self, flags, payload: bytes) -> bytes:
        """Send one framed DNS query, return the downstream payload bytes."""
        with self.send_lock:
            self.seq = (self.seq + 1) % 0x10000
            pkt, qid = proto.make_upstream_query(
                self.domain, self.session_id, self.seq, flags, payload)
            try:
                self.udp.sendto(pkt, self.server_addr)
                resp, _ = self.udp.recvfrom(4096)
            except socket.timeout:
                return b""
            try:
                _, txt = proto.parse_txt_response(resp)
            except Exception:
                return b""
            return txt

    def run(self):
        # SYN: open the session on the server
        self._query(proto.FLAG_SYN, b"")

        upstream_thread = threading.Thread(target=self._pump_local_to_dns, daemon=True)
        upstream_thread.start()
        self._pump_dns_to_local()  # runs (polls) until closed

    def _pump_local_to_dns(self):
        try:
            while not self.closed:
                data = self.local_sock.recv(proto.MAX_UPSTREAM_RAW_PAYLOAD)
                if not data:
                    break
                for i in range(0, len(data), proto.MAX_UPSTREAM_RAW_PAYLOAD):
                    chunk = data[i:i + proto.MAX_UPSTREAM_RAW_PAYLOAD]
                    down = self._query(0, chunk)
                    if down:
                        try:
                            self.local_sock.sendall(down)
                        except OSError:
                            break
        except OSError:
            pass
        finally:
            self.close()

    def _pump_dns_to_local(self):
        try:
            while not self.closed:
                down = self._query(proto.FLAG_POLL, b"")
                if down:
                    try:
                        self.local_sock.sendall(down)
                    except OSError:
                        break
                else:
                    time.sleep(POLL_INTERVAL)
        finally:
            self.close()

    def close(self):
        if self.closed:
            return
        self.closed = True
        try:
            self._query(proto.FLAG_FIN, b"")
        except Exception:
            pass
        try:
            self.local_sock.close()
        except OSError:
            pass


class DnsTunnelClient:
    def __init__(self, listen_host, listen_port, server_addr, domain_suffix):
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.server_addr = server_addr
        self.domain_suffix = domain_suffix.strip(".").lower()
        self.next_session_id = 1

    def serve_forever(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((self.listen_host, self.listen_port))
        srv.listen(5)
        print(f"[client] local listener on {self.listen_host}:{self.listen_port}, "
              f"tunneling to {self.server_addr} via '.{self.domain_suffix}'")
        while True:
            conn, addr = srv.accept()
            session_id = self.next_session_id
            self.next_session_id = (self.next_session_id + 1) % 256
            print(f"[client] new local connection from {addr}, session {session_id}")
            sess = TunnelSession(self.server_addr, self.domain_suffix, conn, session_id)
            threading.Thread(target=sess.run, daemon=True).start()


def main():
    ap = argparse.ArgumentParser(description="DNS tunneling PoC client (research use)")
    ap.add_argument("--listen", default="127.0.0.1:2022",
                     help="local host:port to listen on")
    ap.add_argument("--server", required=True,
                     help="tunnel server host:port (the dnstun_server.py instance)")
    ap.add_argument("--domain", required=True,
                     help="tunnel domain suffix, e.g. tunnel.test (must match server)")
    args = ap.parse_args()

    lhost, lport = args.listen.rsplit(":", 1)
    shost, sport = args.server.rsplit(":", 1)
    client = DnsTunnelClient(lhost, int(lport), (shost, int(sport)), args.domain)
    client.serve_forever()


if __name__ == "__main__":
    main()
