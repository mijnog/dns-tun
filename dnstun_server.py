#!/usr/bin/env python3
"""
dnstun_server.py -- DNS-tunneling PoC server.

Listens for DNS queries (normally UDP/53) and treats the encoded query
names as a tunneled byte stream. For each "session id" it sees, it opens
a real TCP connection to a fixed upstream target (host:port you configure)
and relays bytes in both directions:

    client --(DNS query name, upstream bytes)--> server --(TCP)--> target
    client <--(DNS TXT answer, downstream bytes)-- server <--(TCP)-- target

Research / authorized-testing use only: run this on a box you control,
pointed at a target service you're also authorized to reach, to evaluate
whether DNS-only egress from a restrictive network can be abused to carry
arbitrary TCP traffic.

Usage:
    sudo python3 dnstun_server.py --listen 0.0.0.0:53 --domain tunnel.test \
        --target 127.0.0.1:2222
"""
import argparse
import queue
import socket
import threading
import time

import dnstun_proto as proto


class Session:
    def __init__(self, session_id, target_host, target_port):
        self.id = session_id
        self.out_queue = queue.Queue()  # bytes queued to send downstream to client
        self.last_seen = time.time()
        self.closed = False
        self.sock = socket.create_connection((target_host, target_port), timeout=5)
        self.sock.settimeout(None)
        self._reader = threading.Thread(target=self._read_target, daemon=True)
        self._reader.start()

    def _read_target(self):
        try:
            while not self.closed:
                data = self.sock.recv(4096)
                if not data:
                    break
                # split into downstream-sized chunks for queuing
                for i in range(0, len(data), proto.MAX_DOWNSTREAM_PAYLOAD):
                    self.out_queue.put(data[i:i + proto.MAX_DOWNSTREAM_PAYLOAD])
        except OSError:
            pass
        finally:
            self.closed = True

    def send_to_target(self, data: bytes):
        if data:
            try:
                self.sock.sendall(data)
            except OSError:
                self.closed = True

    def pop_downstream(self) -> bytes:
        try:
            return self.out_queue.get_nowait()
        except queue.Empty:
            return b""

    def close(self):
        self.closed = True
        try:
            self.sock.close()
        except OSError:
            pass


class DnsTunnelServer:
    def __init__(self, listen_host, listen_port, domain_suffix, target_host, target_port):
        self.domain_suffix = domain_suffix.strip(".").lower()
        self.target_host = target_host
        self.target_port = target_port
        self.sessions = {}
        self.lock = threading.Lock()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((listen_host, listen_port))
        print(f"[server] listening on {listen_host}:{listen_port}, "
              f"domain suffix '.{self.domain_suffix}', "
              f"forwarding to {target_host}:{target_port}")

    def get_or_create_session(self, session_id):
        with self.lock:
            sess = self.sessions.get(session_id)
            if sess is None or sess.closed:
                sess = Session(session_id, self.target_host, self.target_port)
                self.sessions[session_id] = sess
                print(f"[server] session {session_id}: opened -> "
                      f"{self.target_host}:{self.target_port}")
            return sess

    def close_session(self, session_id):
        with self.lock:
            sess = self.sessions.pop(session_id, None)
        if sess:
            sess.close()
            print(f"[server] session {session_id}: closed")

    def handle_packet(self, data, addr):
        try:
            q = proto.parse_query(data)
        except Exception:
            return
        labels = q["labels"]
        suffix = ".".join(labels[-len(self.domain_suffix.split(".")):]).lower() \
            if labels else ""
        if suffix != self.domain_suffix:
            return  # not for us

        try:
            session_id, seq, flags, payload = proto.parse_upstream_query(
                labels, self.domain_suffix)
        except Exception as e:
            print(f"[server] bad frame from {addr}: {e}")
            return

        if flags & proto.FLAG_FIN:
            self.close_session(session_id)
            down = b""
        else:
            sess = self.get_or_create_session(session_id)
            if payload:
                sess.send_to_target(payload)
            down = sess.pop_downstream()

        resp = proto.build_txt_response(q["id"], labels, q["qtype"], down)
        self.sock.sendto(resp, addr)

    def serve_forever(self):
        while True:
            data, addr = self.sock.recvfrom(4096)
            try:
                self.handle_packet(data, addr)
            except Exception as e:
                print(f"[server] error handling packet from {addr}: {e}")


def main():
    ap = argparse.ArgumentParser(description="DNS tunneling PoC server (research use)")
    ap.add_argument("--listen", default="0.0.0.0:53",
                     help="host:port to listen on (default 0.0.0.0:53, needs root)")
    ap.add_argument("--domain", required=True,
                     help="tunnel domain suffix, e.g. tunnel.test")
    ap.add_argument("--target", required=True,
                     help="real TCP target to forward tunneled traffic to, host:port")
    args = ap.parse_args()

    lhost, lport = args.listen.rsplit(":", 1)
    thost, tport = args.target.rsplit(":", 1)
    srv = DnsTunnelServer(lhost, int(lport), args.domain, thost, int(tport))
    srv.serve_forever()


if __name__ == "__main__":
    main()
