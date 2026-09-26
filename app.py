"""PacketTrain: PCAP flow explorer.

Thin Flask surface. Packet extraction lives in packettrain.decode, TCP summary
and capture-side inference in packettrain.accounting, traffic-shape rules in
packettrain.behavior, and TLS handling in packettrain.https.
"""
import re
import subprocess
from pathlib import Path

from flask import Flask, abort, jsonify, request, send_from_directory

from packettrain.accounting import stream_detail, summarize
from packettrain.behavior import classify_stream
from packettrain.config import EXTENSIONS, FIELDS, MAX_BYTES, capture_dir, capture_path  # noqa: F401
from packettrain.decode import (decimal, flag_bits, flag_set, num, parse_rows,
                               read_capture, slicing_report)
from packettrain.https import analyze_https

# Re-exported so callers that imported these from the app module keep working.
# The package modules are the real owners; this is a compatibility surface.
__all__ = [
    "app", "analyze_https", "capture_dir", "capture_path", "classify_stream", "decimal",
    "flag_bits", "flag_set", "num", "parse_rows", "read_capture", "slicing_report",
    "stream_detail", "summarize",
]

ROOT = Path(__file__).resolve().parent
app = Flask(__name__, static_folder=None)


@app.get("/")
def index():
    return send_from_directory(ROOT, "index.html")


@app.get("/api/files")
def files():
    directory = capture_dir()
    if not directory.is_dir():
        return jsonify({"files": [], "directory": str(directory), "error": "Directory not mounted"})
    entries = sorted((p for p in directory.iterdir() if p.is_file() and not p.is_symlink()
                      and p.suffix.lower() in EXTENSIONS and p.stat().st_size <= MAX_BYTES),
                     key=lambda p: p.name.lower())
    return jsonify({"files": [{"name": p.name, "bytes": p.stat().st_size} for p in entries],
                    "directory": str(directory)})


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


@app.get("/api/slicing")
def slicing():
    """Report packet slicing for one capture without reading full packet detail."""
    path = capture_path(request.args.get("file", ""))
    command = ["tshark", "-n", "-r", str(path), "-Y", "tcp", "-T", "fields",
               "-e", "frame.len", "-e", "frame.cap_len"]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=180,
                                check=False, errors="replace")
    except subprocess.TimeoutExpired:
        abort(504, "TShark timed out")
    if result.returncode:
        abort(422, "TShark could not read this capture: " + result.stderr[-500:])
    total = sliced = lost = 0
    for line in result.stdout.splitlines():
        columns = line.rstrip("\r\n").split("\t")
        if len(columns) < 2:
            continue
        total += 1
        claimed = num(columns[0])
        stored = num(columns[1])
        if 0 < stored < claimed:
            sliced += 1
            lost += claimed - stored
    fraction = (sliced / total) if total else 0.0
    if sliced and fraction >= 0.5:
        advice = ("This capture is heavily sliced: most frames are stored shorter than "
                  "they were on the wire, so payload records and TLS fields may be "
                  "unreadable. Recapture with a full snaplen (-s 0).")
    elif sliced:
        advice = ("Some frames are stored shorter than they were on the wire. Any field "
                  "missing from a sliced frame was never captured; recapture with "
                  "-s 0 to recover it.")
    else:
        advice = None
    return jsonify({"file": path.name, "total": total, "sliced_frames": sliced,
                    "lost_bytes": lost, "sliced_fraction": round(fraction, 4),
                    "sliced": bool(sliced), "advice": advice})


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
