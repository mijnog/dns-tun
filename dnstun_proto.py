"""
dnstun_proto.py -- minimal shared DNS wire-format + tunneling protocol helpers
for the research DNS-tunneling PoC (client/server).

This is NOT a general-purpose DNS library. It builds/parses just enough of
the DNS packet format to carry our own tunneled bytes inside query names
(upstream, client -> server) and inside TXT answer RDATA (downstream,
server -> client). Standard library only.

Wire framing for a tunneled query name:
    <b32-session-and-header-and-payload-labels>.<domain-suffix>

Each query carries one "frame":
    byte 0       : session id (0-255)
    bytes 1-2    : sequence number, big-endian uint16 (per-session, upstream)
    byte 3       : flags bitmask
                     0x01 SYN  - open a new session (first packet)
                     0x02 FIN  - close the session (last packet)
                     0x04 POLL - pure poll, no new upstream payload;
                                 just asking "anything queued for me?"
    bytes 4..    : upstream payload (may be empty, e.g. for POLL/FIN)

The frame is base32-encoded (RFC4648, no padding) so it only contains
characters that are safe in a DNS label/hostname, then split across
multiple 63-byte labels if needed.

Downstream (TXT RDATA) is NOT base32-encoded -- TXT strings are
length-prefixed binary blobs, so we just put the raw frame bytes in
directly (same byte layout: session id, seq, flags, payload), which is
more space-efficient.
"""
import base64
import random
import struct

FLAG_SYN = 0x01
FLAG_FIN = 0x02
FLAG_POLL = 0x04

MAX_LABEL_LEN = 63
# Keep comfortably under the 255-byte total name limit once the domain
# suffix is appended.
MAX_UPSTREAM_RAW_PAYLOAD = 90

# Keep comfortably under the 255-byte max length of a single TXT string.
MAX_DOWNSTREAM_PAYLOAD = 200


def b32_encode_nopad(data: bytes) -> str:
    return base64.b32encode(data).decode("ascii").rstrip("=").lower()


def b32_decode_nopad(s: str) -> bytes:
    s = s.upper()
    pad = (-len(s)) % 8
    return base64.b32decode(s + "=" * pad)


def chunk_label(s: str, size: int = MAX_LABEL_LEN):
    return [s[i:i + size] for i in range(0, len(s), size)] or [""]


# ---------------------------------------------------------------------------
# Raw DNS packet construction / parsing (query + TXT answer only)
# ---------------------------------------------------------------------------

def encode_name(labels):
    out = b""
    for lab in labels:
        b = lab.encode("ascii")
        out += bytes([len(b)]) + b
    return out + b"\x00"


def decode_name(data: bytes, offset: int):
    """Decode a (possibly compressed) name starting at offset.
    Returns (labels, next_offset)."""
    labels = []
    seen_pointer = False
    start_offset = offset
    while True:
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0 == 0xC0:
            # compression pointer
            ptr = ((length & 0x3F) << 8) | data[offset + 1]
            if not seen_pointer:
                start_offset = offset + 2
            seen_pointer = True
            offset = ptr
            continue
        offset += 1
        labels.append(data[offset:offset + length].decode("ascii"))
        offset += length
    end_offset = offset if not seen_pointer else start_offset
    return labels, end_offset


def build_query(qname_labels, qtype=16, qid=None):
    """Build a DNS query packet. qtype 16 = TXT."""
    if qid is None:
        qid = random.randint(0, 0xFFFF)
    flags = 0x0100  # standard query, recursion desired
    header = struct.pack(">HHHHHH", qid, flags, 1, 0, 0, 0)
    question = encode_name(qname_labels) + struct.pack(">HH", qtype, 1)
    return header + question, qid


def parse_query(data: bytes):
    qid, flags, qdcount, ancount, nscount, arcount = struct.unpack(">HHHHHH", data[:12])
    labels, offset = decode_name(data, 12)
    qtype, qclass = struct.unpack(">HH", data[offset:offset + 4])
    return {"id": qid, "labels": labels, "qtype": qtype, "qclass": qclass}


def build_txt_response(qid, qname_labels, qtype, txt_bytes: bytes, ttl=0):
    header = struct.pack(">HHHHHH", qid, 0x8180, 1, 1, 0, 0)  # QR=1, RA=1, RCODE=0
    question = encode_name(qname_labels) + struct.pack(">HH", qtype, 1)
    # Answer: name = pointer to offset 12 (start of question name)
    name_ptr = b"\xc0\x0c"
    rdata = bytes([len(txt_bytes)]) + txt_bytes if txt_bytes else b"\x00"
    rtype = 16  # TXT
    rclass = 1
    answer = name_ptr + struct.pack(">HH", rtype, rclass) + struct.pack(">I", ttl) + \
        struct.pack(">H", len(rdata)) + rdata
    return header + question + answer


def parse_txt_response(data: bytes):
    """Parse our own TXT response packet; returns raw TXT string bytes (or b'')."""
    qid, flags, qdcount, ancount, nscount, arcount = struct.unpack(">HHHHHH", data[:12])
    _, offset = decode_name(data, 12)
    offset += 4  # qtype+qclass
    if ancount == 0:
        return qid, b""
    _, offset = decode_name(data, offset)
    rtype, rclass, ttl, rdlen = struct.unpack(">HHIH", data[offset:offset + 10])
    offset += 10
    rdata = data[offset:offset + rdlen]
    if not rdata:
        return qid, b""
    txt_len = rdata[0]
    return qid, rdata[1:1 + txt_len]


# ---------------------------------------------------------------------------
# Tunnel frame <-> DNS query name
# ---------------------------------------------------------------------------

def make_upstream_query(domain_suffix, session_id, seq, flags, payload: bytes):
    frame = bytes([session_id]) + struct.pack(">H", seq) + bytes([flags]) + payload
    encoded = b32_encode_nopad(frame)
    labels = chunk_label(encoded)
    labels += domain_suffix.split(".")
    pkt, qid = build_query(labels, qtype=16)
    return pkt, qid


def parse_upstream_query(labels, domain_suffix):
    suffix_labels = domain_suffix.split(".")
    n = len(suffix_labels)
    data_labels = labels[:-n] if n else labels
    encoded = "".join(data_labels)
    frame = b32_decode_nopad(encoded)
    session_id = frame[0]
    seq = struct.unpack(">H", frame[1:3])[0]
    flags = frame[3]
    payload = frame[4:]
    return session_id, seq, flags, payload
