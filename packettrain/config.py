"""Configuration and captured-file access limits."""
import os
from pathlib import Path

from flask import abort

PCAP_DIR = Path(os.environ.get("PCAP_DIR", "/pcaps")).resolve()
MAX_BYTES = int(os.environ.get("MAX_PCAP_BYTES", str(256 * 1024**2)))
MAX_PACKETS = int(os.environ.get("MAX_PACKETS", "100000"))
EXTENSIONS = {".pcap", ".pcapng", ".cap"}

# Fields requested from TShark, in order. parse_rows zips these with each row.
FIELDS = [
    "frame.number", "frame.time_epoch", "ip.src", "ipv6.src", "ip.dst", "ipv6.dst",
    "tcp.srcport", "tcp.dstport", "tcp.stream", "tcp.seq_raw", "tcp.ack_raw",
    "tcp.len", "frame.len", "frame.cap_len", "tcp.flags", "tcp.flags.syn", "tcp.flags.ack", "tcp.flags.fin",
    "tcp.flags.reset", "tcp.flags.push", "tcp.analysis.retransmission",
    "tcp.analysis.fast_retransmission", "tcp.analysis.spurious_retransmission",
    "tcp.analysis.duplicate_ack", "tcp.options.sack_le", "tcp.window_size",
    "tcp.analysis.ack_rtt", "tcp.options.mss_val",
    "tls.handshake.type", "tls.record.content_type", "tls.handshake.extensions_server_name",
    "tls.handshake.extensions_alpn_str", "tls.handshake.version",
]


def capture_dir():
    """Return the current capture directory.

    Read at call time, not import time, so an override stays visible to every
    caller. Binding PCAP_DIR directly into another module would freeze the value
    and silently ignore later changes.
    """
    return PCAP_DIR


def capture_path(name):
    """Resolve a capture filename inside PCAP_DIR, rejecting escapes and oversize files."""
    if not name or Path(name).name != name or Path(name).suffix.lower() not in EXTENSIONS:
        abort(400, "Invalid capture filename")
    candidate = PCAP_DIR / name
    if candidate.is_symlink() or not candidate.is_file() or candidate.resolve().parent != PCAP_DIR:
        abort(404, "Capture not found")
    if candidate.stat().st_size > MAX_BYTES:
        abort(413, "Capture exceeds MAX_PCAP_BYTES")
    return candidate
