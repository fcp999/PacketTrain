"""Turn TShark field output into packet dictionaries."""
import subprocess

from flask import abort

from .config import FIELDS, MAX_PACKETS


def num(value, default=0):
    try:
        return int(value)
    except (ValueError, TypeError):
        return default


def flag_bits(value):
    try:
        return int(value, 0) if value else None
    except ValueError:
        return None


def flag_set(fields, bitmask, field, bit):
    if bitmask is not None:
        return bool(bitmask & bit)
    return fields[field].strip().lower() in {"1", "true", "yes", "set"}


def decimal(value):
    try:
        return float(value)
    except (ValueError, TypeError):
        return None


def parse_rows(lines):
    packets = []
    for line in lines:
        columns = line.rstrip("\r\n").split("\t")
        columns += [""] * (len(FIELDS) - len(columns))
        p = dict(zip(FIELDS, columns))
        ts = decimal(p["frame.time_epoch"])
        if ts is None or not p["tcp.stream"]:
            continue
        bits = flag_bits(p["tcp.flags"])
        packets.append({
            "frame": num(p["frame.number"]), "ts": ts, "stream": num(p["tcp.stream"]),
            "src": p["ip.src"] or p["ipv6.src"], "dst": p["ip.dst"] or p["ipv6.dst"],
            "sport": num(p["tcp.srcport"]), "dport": num(p["tcp.dstport"]),
            "seq": num(p["tcp.seq_raw"]), "ack": num(p["tcp.ack_raw"]),
            "length": num(p["tcp.len"]), "frame_length": num(p["frame.len"]),
            "cap_length": num(p["frame.cap_len"]),
            "sliced": (num(p["frame.cap_len"]) > 0
                       and num(p["frame.cap_len"]) < num(p["frame.len"])),
            "flags_raw": bits,
            "syn": flag_set(p, bits, "tcp.flags.syn", 0x02),
            "ack_flag": flag_set(p, bits, "tcp.flags.ack", 0x10),
            "fin": flag_set(p, bits, "tcp.flags.fin", 0x01),
            "rst": flag_set(p, bits, "tcp.flags.reset", 0x04),
            "psh": flag_set(p, bits, "tcp.flags.push", 0x08),
            "retrans": any(p[field] for field in (
                "tcp.analysis.retransmission", "tcp.analysis.fast_retransmission",
                "tcp.analysis.spurious_retransmission")),
            "dup_ack": bool(p["tcp.analysis.duplicate_ack"]),
            "sack": bool(p["tcp.options.sack_le"]),
            "window": num(p["tcp.window_size"]),
            "ack_rtt_ms": (decimal(p["tcp.analysis.ack_rtt"]) or 0) * 1000,
            "mss": num(p["tcp.options.mss_val"]),
            "tls_handshake": p["tls.handshake.type"],
            "tls_record": p["tls.record.content_type"],
            "tls_sni": p["tls.handshake.extensions_server_name"],
            "tls_alpn": p["tls.handshake.extensions_alpn_str"],
            "tls_version": p["tls.handshake.version"],
            "ttl": num(p["ip.ttl"]) or num(p["ipv6.hlim"]),
        })
    return packets



def slicing_report(packets):
    """Describe packet slicing (snaplen truncation) for a capture.

    A sliced capture stores fewer bytes than the frame claimed on the wire.
    When the cut lands inside a record, the decoder sees a valid header with an
    incomplete body and correctly declines to dissect it, so fields such as SNI
    or ALPN come back empty even though the traffic is real. Reporting the loss
    distinguishes "nothing there" from "not captured".
    """
    total = len(packets)
    if not total:
        return {"sliced": False, "total": 0, "sliced_frames": 0, "lost_bytes": 0,
                "sliced_fraction": 0.0, "advice": None}
    sliced = [p for p in packets if p["sliced"]]
    lost = sum(p["frame_length"] - p["cap_length"] for p in sliced)
    fraction = len(sliced) / total
    if not sliced:
        advice = None
    elif fraction >= 0.5:
        advice = ("This capture is heavily sliced: most frames are stored shorter than "
                  "they were on the wire, so payload records and TLS fields may be "
                  "unreadable. Recapture with a full snaplen (-s 0).")
    else:
        advice = ("Some frames are stored shorter than they were on the wire. Any field "
                  "missing from a sliced frame was never captured; recapture with "
                  "-s 0 to recover it.")
    return {"sliced": bool(sliced), "total": total, "sliced_frames": len(sliced),
            "lost_bytes": lost, "sliced_fraction": round(fraction, 4), "advice": advice}


def read_capture(path):
    command = ["tshark", "-n", "-r", str(path), "-Y", "tcp", "-T", "fields"]
    for field in FIELDS:
        command += ["-e", field]
    command += ["-E", "occurrence=f", "-E", "quote=n"]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=180,
                                check=False, errors="replace")
    except subprocess.TimeoutExpired:
        abort(504, "TShark timed out")
    except FileNotFoundError:
        abort(500, "TShark is unavailable")
    if result.returncode:
        abort(422, "TShark could not read this capture: " + result.stderr[-500:])
    lines = result.stdout.splitlines()
    if len(lines) > MAX_PACKETS:
        abort(413, "Capture exceeds MAX_PACKETS; split or filter it first")
    return parse_rows(lines)


