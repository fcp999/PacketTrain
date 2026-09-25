import os
import re
import subprocess
from collections import defaultdict
from pathlib import Path
from statistics import median, pstdev

from flask import Flask, abort, jsonify, request, send_from_directory


ROOT = Path(__file__).resolve().parent
PCAP_DIR = Path(os.environ.get("PCAP_DIR", "/pcaps")).resolve()
MAX_BYTES = int(os.environ.get("MAX_PCAP_BYTES", str(256 * 1024**2)))
MAX_PACKETS = int(os.environ.get("MAX_PACKETS", "100000"))
EXTENSIONS = {".pcap", ".pcapng", ".cap"}
FIELDS = [
    "frame.number", "frame.time_epoch", "ip.src", "ipv6.src", "ip.dst", "ipv6.dst",
    "tcp.srcport", "tcp.dstport", "tcp.stream", "tcp.seq_raw", "tcp.ack_raw",
    "tcp.len", "frame.len", "tcp.flags", "tcp.flags.syn", "tcp.flags.ack", "tcp.flags.fin",
    "tcp.flags.reset", "tcp.flags.push", "tcp.analysis.retransmission",
    "tcp.analysis.fast_retransmission", "tcp.analysis.spurious_retransmission",
    "tcp.analysis.duplicate_ack", "tcp.options.sack_le", "tcp.window_size",
    "tcp.analysis.ack_rtt", "tcp.options.mss_val",
]
app = Flask(__name__, static_folder=None)


def capture_path(name):
    if not name or Path(name).name != name or Path(name).suffix.lower() not in EXTENSIONS:
        abort(400, "Invalid capture filename")
    candidate = PCAP_DIR / name
    if candidate.is_symlink() or not candidate.is_file() or candidate.resolve().parent != PCAP_DIR:
        abort(404, "Capture not found")
    if candidate.stat().st_size > MAX_BYTES:
        abort(413, "Capture exceeds MAX_PCAP_BYTES")
    return candidate


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
        })
    return packets


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


def classify_stream(packets, client):
    """Classify observable traffic shape, never the application or file type."""
    data = sorted((p for p in packets if p["length"] > 0), key=lambda p: p["ts"])
    duration = max(0.0, packets[-1]["ts"] - packets[0]["ts"]) if packets else 0.0
    by_side = {"client": [], "server": []}
    for p in data:
        side = "client" if (p["src"], p["sport"]) == client else "server"
        by_side[side].append(p)
    bytes_by_side = {side: sum(p["length"] for p in group) for side, group in by_side.items()}
    total = sum(bytes_by_side.values())
    dominant = max(bytes_by_side, key=bytes_by_side.get)
    share = bytes_by_side[dominant] / total if total else 0.0

    # A burst is consecutive payload records from one side no more than 200 ms apart.
    bursts = []
    for p in data:
        side = "client" if (p["src"], p["sport"]) == client else "server"
        if bursts and bursts[-1]["side"] == side and p["ts"] - bursts[-1]["end"] <= 0.2:
            bursts[-1]["end"] = p["ts"]
            bursts[-1]["bytes"] += p["length"]
            bursts[-1]["records"] += 1
        else:
            bursts.append({"side": side, "start": p["ts"], "end": p["ts"],
                           "bytes": p["length"], "records": 1})
    turns = sum(a["side"] != b["side"] for a, b in zip(bursts, bursts[1:]))
    client_bursts = [b for b in bursts if b["side"] == "client"]
    client_intervals = [b["start"] - a["start"] for a, b in zip(client_bursts, client_bursts[1:])]
    interval_mean = sum(client_intervals) / len(client_intervals) if client_intervals else 0
    interval_cv = pstdev(client_intervals) / interval_mean if interval_mean else None
    response_delays = []
    for i, burst in enumerate(bursts):
        if burst["side"] == "client" and i + 1 < len(bursts) and bursts[i + 1]["side"] == "server":
            response_delays.append(bursts[i + 1]["start"] - burst["end"])
    typical_reply = median(response_delays) if response_delays else None
    sizes = [p["length"] for p in data]
    typical = median(sizes) if sizes else 0
    metrics = {"client_bytes": bytes_by_side["client"], "server_bytes": bytes_by_side["server"],
               "duration_s": round(duration, 3), "dominant_share": round(share, 3),
               "payload_records": len(data), "bursts": len(bursts), "turns": turns,
               "typical_payload_bytes": typical,
               "client_interval_s": round(interval_mean, 2) if interval_mean else None,
               "client_interval_cv": round(interval_cv, 2) if interval_cv is not None else None,
               "typical_reply_s": round(typical_reply, 2) if typical_reply is not None else None}

    if not data:
        incomplete = any(p["syn"] and not p["ack_flag"] for p in packets) and not any(
            p["syn"] and p["ack_flag"] for p in packets)
        label = "Connection attempt" if incomplete else "Control-only / idle"
        evidence = ["No TCP payload observed", f"{len(packets)} captured TCP records"]
        confidence = "moderate"
    elif total >= 256_000 and share >= 0.85:
        label = "Bulk download pattern" if dominant == "server" else "Bulk upload pattern"
        evidence = [f"{bytes_by_side[dominant]:,} payload bytes from {dominant}",
                    f"{share:.0%} of payload in one direction"]
        confidence = "high" if share >= 0.95 else "moderate"
    elif (len(client_bursts) >= 4 and len(by_side["server"]) >= 3
          and interval_mean >= 1 and interval_cv is not None and interval_cv <= 0.35
          and typical_reply is not None and typical_reply <= min(0.5, interval_mean * 0.25)
          and typical < 8_192):
        label, confidence = "Periodic polling pattern", "moderate"
        evidence = [f"{len(client_bursts)} client request bursts",
                    f"Mean interval {interval_mean:.1f}s; variation {interval_cv:.2f}"]
    elif (duration >= 5 and len(by_side["client"]) >= 3 and len(by_side["server"]) >= 3
          and turns >= 4 and typical <= 1_024
          and (len(bursts) < 2 or median([b["start"] - a["start"]
                                        for a, b in zip(bursts, bursts[1:])]) >= 0.5)):
        label, confidence = "Interactive exchange pattern", "moderate"
        evidence = [f"{turns} direction changes", f"Typical payload {typical:g} bytes",
                    f"Activity spans {duration:.1f}s"]
    elif (duration >= 10 and share >= 0.85 and len(bursts) >= 3 and total < 256_000
          and median([b["start"] - a["start"] for a, b in zip(bursts, bursts[1:])]) >= 2):
        label, confidence = "Sparse notifications pattern", "moderate"
        evidence = [f"{len(bursts)} separated bursts", f"{share:.0%} of payload from {dominant}"]
    elif bytes_by_side["client"] and bytes_by_side["server"]:
        label, confidence = "Request/response pattern", "moderate" if turns else "low"
        evidence = [f"{turns} direction changes", f"{bytes_by_side['client']:,} bytes client → server",
                    f"{bytes_by_side['server']:,} bytes server → client"]
    elif duration >= 10 and total >= 128_000:
        label, confidence = "Sustained one-way transfer", "low"
        evidence = [f"{total:,} payload bytes", f"Activity spans {duration:.1f}s"]
    else:
        label, confidence = "Insufficient pattern", "low"
        evidence = [f"{len(data)} payload records", f"Activity spans {duration:.1f}s"]
    return {"label": label, "confidence": confidence, "evidence": evidence,
            "metrics": metrics, "scope": "Traffic behavior only; encrypted payloads and partial captures limit application identification."}


def summarize(packets):
    groups = defaultdict(list)
    for packet in packets:
        groups[packet["stream"]].append(packet)
    results = []
    for stream, group in sorted(groups.items()):
        first = next((p for p in group if p["syn"] and not p["ack_flag"]), group[0])
        results.append({
            "id": stream, "client": first["src"], "server": first["dst"],
            "client_port": first["sport"], "server_port": first["dport"],
            "packets": len(group), "bytes": sum(p["length"] for p in group),
            "duration_ms": round((group[-1]["ts"] - group[0]["ts"]) * 1000, 2),
            "pattern": classify_stream(group, (first["src"], first["sport"]))["label"],
        })
    return results


def stream_detail(packets, stream):
    group = [p.copy() for p in packets if p["stream"] == stream]
    if not group:
        abort(404, "Stream not found")
    summary = next(s for s in summarize(group) if s["id"] == stream)
    first_ts = group[0]["ts"]
    pattern = classify_stream(group, (summary["client"], summary["client_port"]))
    for p in group:
        p["time_ms"] = round((p.pop("ts") - first_ts) * 1000, 3)
        p["direction"] = "out" if (p["src"], p["sport"]) == (
            summary["client"], summary["client_port"]) else "in"
    syn = next((p for p in group if p["syn"] and not p["ack_flag"] and p["direction"] == "out"), None)
    synack = next((p for p in group if p["syn"] and p["ack_flag"] and p["direction"] == "in"
                   and (syn is None or p["time_ms"] > syn["time_ms"])), None)
    third = next((p for p in group if p["ack_flag"] and not p["syn"] and p["direction"] == "out"
                  and synack and p["time_ms"] > synack["time_ms"]), None)
    leg1 = synack["time_ms"] - syn["time_ms"] if syn and synack else None
    leg2 = third["time_ms"] - synack["time_ms"] if third and synack else None
    side = "unknown"
    if leg1 is not None and leg2 is not None and min(leg1, leg2) >= 0:
        if leg1 >= 3 * max(leg2, 0.001):
            side = "client"  # SYN travels and SYN-ACK returns; final ACK is nearby.
        elif leg2 >= 3 * max(leg1, 0.001):
            side = "server"  # SYN-ACK is nearby; final ACK makes the round trip.
    rtts = sorted(p["ack_rtt_ms"] for p in group if 0 < p["ack_rtt_ms"] < 60_000)
    if side != "unknown":
        rtt = leg1 if side == "client" else leg2
        source = "three-way handshake estimate"
    elif rtts:
        rtt = rtts[len(rtts) // 2]
        source = "TShark ACK RTT median"
    else:
        rtt = None
        source = "unknown"
    payload_by_direction = {direction: sum(p["length"] for p in group if p["direction"] == direction)
                            for direction in ("out", "in")}
    data_direction = max(payload_by_direction, key=payload_by_direction.get)
    first_data = next((i for i, p in enumerate(group)
                       if p["direction"] == data_direction and p["length"] > 0), None)
    flight = []
    if first_data is not None:
        for p in group[first_data:]:
            if p["direction"] != data_direction and p["ack_flag"]:
                break
            if p["direction"] == data_direction and p["length"]:
                flight.append(p)
    mss = sorted({p["mss"] for p in group if p["syn"] and p["mss"]})
    sizes = sorted(p["frame_length"] for p in group if p["length"])
    facts = {"mss": mss, "max_payload": max((p["length"] for p in group), default=0),
             "typical_frame_bytes": sizes[len(sizes) // 2] if sizes else None,
             "large_capture_records": sum(p["length"] > 1460 for p in group),
             "first_flight_packets": len(flight),
             "first_flight_bytes": sum(p["length"] for p in flight),
             "first_flight_span_ms": round(flight[-1]["time_ms"] - flight[0]["time_ms"], 3)
             if flight else None,
             "retransmissions": sum(p["retrans"] for p in group),
             "sack_packets": sum(p["sack"] for p in group),
             "psh_packets": sum(p["psh"] for p in group)}
    return {"summary": summary, "rtt_ms": round(rtt, 2) if rtt is not None else None,
            "rtt_source": source, "capture_side": side,
            "handshake_legs_ms": [round(leg1, 3), round(leg2, 3)] if leg1 is not None and leg2 is not None else None,
            "packets": group, "facts": facts, "pattern": pattern,
            "note": "Incoming timestamps are arrival times at the capture point. One-way time is estimated as RTT/2; choose the capture side manually if the handshake is ambiguous."}


@app.get("/")
def index():
    return send_from_directory(ROOT, "index.html")


@app.get("/api/files")
def files():
    if not PCAP_DIR.is_dir():
        return jsonify({"files": [], "directory": str(PCAP_DIR), "error": "Directory not mounted"})
    entries = sorted((p for p in PCAP_DIR.iterdir() if p.is_file() and not p.is_symlink()
                      and p.suffix.lower() in EXTENSIONS and p.stat().st_size <= MAX_BYTES),
                     key=lambda p: p.name.lower())
    return jsonify({"files": [{"name": p.name, "bytes": p.stat().st_size} for p in entries],
                    "directory": str(PCAP_DIR)})


@app.get("/api/streams")
def streams():
    packets = read_capture(capture_path(request.args.get("file", "")))
    return jsonify({"streams": summarize(packets)})


@app.get("/api/flow")
def flow():
    raw = request.args.get("stream", "")
    if not re.fullmatch(r"\d{1,8}", raw):
        abort(400, "Invalid stream")
    packets = read_capture(capture_path(request.args.get("file", "")))
    return jsonify(stream_detail(packets, int(raw)))


@app.errorhandler(400)
@app.errorhandler(404)
@app.errorhandler(413)
@app.errorhandler(422)
@app.errorhandler(500)
@app.errorhandler(504)
def error(exc):
    return jsonify({"error": exc.description}), exc.code


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
