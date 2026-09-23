import os
import re
import subprocess
from collections import defaultdict
from pathlib import Path

from flask import Flask, abort, jsonify, request, send_from_directory


ROOT = Path(__file__).resolve().parent
PCAP_DIR = Path(os.environ.get("PCAP_DIR", "/pcaps")).resolve()
MAX_BYTES = int(os.environ.get("MAX_PCAP_BYTES", str(256 * 1024**2)))
MAX_PACKETS = int(os.environ.get("MAX_PACKETS", "100000"))
EXTENSIONS = {".pcap", ".pcapng", ".cap"}
FIELDS = [
    "frame.number", "frame.time_epoch", "ip.src", "ipv6.src", "ip.dst", "ipv6.dst",
    "tcp.srcport", "tcp.dstport", "tcp.stream", "tcp.seq_raw", "tcp.ack_raw",
    "tcp.len", "frame.len", "tcp.flags.syn", "tcp.flags.ack", "tcp.flags.fin",
    "tcp.flags.reset", "tcp.flags.push", "tcp.analysis.retransmission",
    "tcp.analysis.fast_retransmission", "tcp.analysis.spurious_retransmission",
    "tcp.analysis.duplicate_ack", "tcp.options.sack_le", "tcp.window_size",
    "tcp.analysis.ack_rtt",
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
        packets.append({
            "frame": num(p["frame.number"]), "ts": ts, "stream": num(p["tcp.stream"]),
            "src": p["ip.src"] or p["ipv6.src"], "dst": p["ip.dst"] or p["ipv6.dst"],
            "sport": num(p["tcp.srcport"]), "dport": num(p["tcp.dstport"]),
            "seq": num(p["tcp.seq_raw"]), "ack": num(p["tcp.ack_raw"]),
            "length": num(p["tcp.len"]), "frame_length": num(p["frame.len"]),
            "syn": p["tcp.flags.syn"] == "1", "ack_flag": p["tcp.flags.ack"] == "1",
            "fin": p["tcp.flags.fin"] == "1", "rst": p["tcp.flags.reset"] == "1",
            "psh": p["tcp.flags.push"] == "1",
            "retrans": any(p[field] for field in (
                "tcp.analysis.retransmission", "tcp.analysis.fast_retransmission",
                "tcp.analysis.spurious_retransmission")),
            "dup_ack": bool(p["tcp.analysis.duplicate_ack"]),
            "sack": bool(p["tcp.options.sack_le"]),
            "window": num(p["tcp.window_size"]),
            "ack_rtt_ms": (decimal(p["tcp.analysis.ack_rtt"]) or 0) * 1000,
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
        })
    return results


def stream_detail(packets, stream):
    group = [p.copy() for p in packets if p["stream"] == stream]
    if not group:
        abort(404, "Stream not found")
    summary = next(s for s in summarize(group) if s["id"] == stream)
    first_ts = group[0]["ts"]
    for p in group:
        p["time_ms"] = round((p.pop("ts") - first_ts) * 1000, 3)
        p["direction"] = "out" if (p["src"], p["sport"]) == (
            summary["client"], summary["client_port"]) else "in"
    rtts = sorted(p["ack_rtt_ms"] for p in group if 0 < p["ack_rtt_ms"] < 60_000)
    if rtts:
        rtt = rtts[len(rtts) // 2]
        source = "TShark ACK RTT median"
    else:
        syn = next((p for p in group if p["syn"] and not p["ack_flag"]), None)
        synack = next((p for p in group if p["syn"] and p["ack_flag"]), None)
        rtt = synack["time_ms"] - syn["time_ms"] if syn and synack else None
        source = "SYN to SYN-ACK estimate" if rtt is not None else "unknown"
    return {"summary": summary, "rtt_ms": round(rtt, 2) if rtt is not None else None,
            "rtt_source": source, "packets": group,
            "note": "Travel between endpoints is illustrative for a single capture. Packet times and flags come from the PCAP."}


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
