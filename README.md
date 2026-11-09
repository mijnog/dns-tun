# DNS Tunneling PoC (client/server)

A minimal TCP-over-DNS tunnel, for research into whether DNS-only egress
through a restrictive firewall can be abused to carry arbitrary TCP
traffic. Pure Python standard library, no dependencies.

**Tested end-to-end on loopback** (small text message and 5000 bytes of
random binary data), round-tripped byte-for-byte through a toy TCP echo
service.

## How it works

```
 local app <--TCP--> dnstun_client.py <--DNS queries/UDP:53--> dnstun_server.py <--TCP--> real target
```

- `dnstun_client.py` opens a local TCP listener. Each connection becomes a
  "session" (1-byte session id).
- Upstream (client -> server): payload bytes + a small header (session id,
  sequence number, flags) are base32-encoded and packed into the labels of
  a DNS query name, e.g. `<encoded>.tunnel.test`. Flags: `SYN` on first
  packet, `FIN` on close, `POLL` for empty polling queries.
- Downstream (server -> client): the server answers with a `TXT` record
  whose RDATA is the raw queued bytes for that session (TXT RDATA is
  binary-safe, so no need to re-encode). Since DNS is request/response, the
  client also polls continuously for queued downstream data when it isn't
  actively sending.
- The server maintains one real TCP connection per session to a single,
  fixed upstream target you configure (e.g. an SSH server), and relays
  bytes in both directions.

Files:
- `dnstun_proto.py` — shared DNS wire-format + framing helpers.
- `dnstun_server.py` — the tunnel endpoint; forwards to a real TCP target.
- `dnstun_client.py` — local TCP listener that tunnels connections out via DNS.
- `echo_target.py` — toy TCP echo service used only for testing.

## Usage

On the server box (needs to be reachable over UDP from the client; binding
port 53 needs root/CAP_NET_BIND_SERVICE):

```bash
sudo python3 dnstun_server.py --listen 0.0.0.0:53 \
    --domain tunnel.test \
    --target 127.0.0.1:22        # whatever service you want to reach
```

On the client box (behind the firewall you're testing):

```bash
python3 dnstun_client.py --listen 127.0.0.1:2022 \
    --server <server_ip>:53 \
    --domain tunnel.test
ssh -p 2022 user@127.0.0.1
```

## Two deployment modes for the firewall test

1. **Direct UDP/53 egress allowed to arbitrary IPs** (common on networks
   that "allow DNS" by just opening port 53 outbound to any host): point
   `--server` straight at your server's IP. This is what's tested above.
2. **Only the network's own resolver is reachable**, and queries must
   actually be recursively resolved: you'd need to register/delegate the
   `--domain` suffix to your server as its authoritative nameserver (NS
   record for `tunnel.test` pointing at the server's IP), so recursive
   resolvers forward queries for that zone to you. The protocol code is
   unchanged either way — only how `--server`'s packets reach the client
   differs (direct UDP vs. via the network's resolver and real DNS
   delegation).

## Known limitations (it's a PoC, not iodine/dnscat2)

- Throughput is low: ~90 bytes/query upstream, ~200 bytes/response
  downstream, polled every 50ms when idle — fine for SSH/shells, slow for
  bulk transfer.
- No encryption of the tunneled payload itself (DNS queries/responses
  aren't encrypted either way, so don't put sensitive cleartext through
  this without wrapping it in something encrypted, e.g. tunnel SSH through
  it as shown above).
- One fixed target per server instance; no in-band target selection.
- Session ids are a single byte (256 concurrent sessions max) and are not
  authenticated — anyone who can reach the server's UDP port and guess/
  brute-force a session id could inject into or read from that session.
  Add a shared-secret/HMAC check in `parse_upstream_query` before using
  this anywhere non-isolated.
- No packet-loss/retransmission handling beyond a simple timeout-and-drop;
  fine on loopback/LAN, would need real reliability logic over a lossy WAN.

## What this demonstrates for your research

If you can run `dnstun_client.py` from inside the restricted network and
reach your `dnstun_server.py` on UDP/53 (directly or via the network's own
resolver with real NS delegation), and the round-trip test above works
the same way there, that firewall's "DNS-only egress" policy is not
actually containing traffic to DNS lookups — it's containing it to port 53,
which is a different thing. That's the gap worth writing up (and the fix
is a DNS-aware proxy/firewall that inspects query names/response sizes/
query entropy and rate, not just the port number).
