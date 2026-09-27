"""PacketTrain: PCAP flow explorer.

Thin Flask surface. Packet extraction lives in packettrain.decode, TCP summary
and capture-side inference in packettrain.accounting, traffic-shape rules in
packettrain.behavior, and TLS handling in packettrain.https.
"""
import math
import re
import subprocess
from pathlib import Path

from flask import Flask, abort, jsonify, request, send_from_directory

from packettrain.accounting import stream_detail, summarize
from packettrain.behavior import classify_stream
from packettrain.config import EXTENSIONS, FIELDS, MAX_BYTES, capture_dir, capture_path  # noqa: F401
from packettrain.decode import (decimal, flag_bits, flag_set, num, parse_rows,
                               read_capture, read_capture_with_follow, slicing_report)
from packettrain.https import analyze_https
from packettrain.payload import (CONVERSATION_PREVIEW_BYTES, MAX_CONVERSATION_PAGE_BYTES,
                                 conversation_from_follow_output, decode_conversation, decode_segment)
from packettrain.accounting_tcp import tcp_accounting
from packettrain.position import infer_capture_side, position_evidence
from packettrain import accounting_tcp, fingerprint, idle, phases

# Re-exported so callers that imported these from the app module keep working.
# The package modules are the real owners; this is a compatibility surface.
__all__ = [
    "app", "analyze_https", "capture_dir", "capture_path", "classify_stream", "decimal",
    "flag_bits", "flag_set", "infer_capture_side", "num", "parse_rows", "position_evidence",
    "read_capture", "slicing_report", "stream_detail", "summarize", "decode_segment",
]

ROOT = Path(__file__).resolve().parent
app = Flask(__name__, static_folder=None)


@app.get("/")
def index():
    return send_from_directory(ROOT, "index.html")


@app.get("/static/<path:name>")
def static_assets(name):
    """Serve vendored front-end assets. Only static/ is reachable."""
    return send_from_directory(ROOT / "packettrain" / "static", name)


@app.get("/api/conversation-payload")
def conversation_payload():
    """TCP-reassembled payload transcript, previewed at 1,000 bytes by default."""
    path = capture_path(request.args.get("file", ""))
    raw = request.args.get("stream", "")
    if not re.fullmatch(r"\d{1,8}", raw):
        abort(400, "Invalid stream")
    full = request.args.get("full", "") == "1"
    limit = MAX_CONVERSATION_PAGE_BYTES if full else CONVERSATION_PREVIEW_BYTES
    offset_raw = request.args.get("offset", "0")
    if not re.fullmatch(r"\d{1,12}", offset_raw):
        abort(400, "Invalid payload offset")
    return jsonify(decode_conversation(path, int(raw), limit, int(offset_raw)))


@app.get("/api/payload")
def payload():
    """Raw and decoded payload for one captured frame.

    Read on demand rather than with the flow, so a large capture does not pay to
    hex-encode every segment it will never show.
    """
    path = capture_path(request.args.get("file", ""))
    frame = request.args.get("frame", "")
    if not frame.isdigit():
        abort(400, "frame must be a packet number")
    return jsonify(decode_segment(path, int(frame)))


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


@app.get("/api/bootstrap")
def bootstrap():
    """Stream index, selected flow, and payload preview from one TShark pass."""
    path = capture_path(request.args.get("file", ""))
    raw = request.args.get("stream", "0")
    if not re.fullmatch(r"\d{1,8}", raw):
        abort(400, "Invalid stream")
    selected = int(raw)
    packets, follow_output = read_capture_with_follow(path, selected)
    summaries = summarize(packets)
    if selected not in {item["id"] for item in summaries}:
        abort(404, "TCP stream not found")
    detail = stream_detail(packets, selected)
    rtt_ms = detail.get("rtt_ms")
    auto_speed = min(idle.SPEED_MAX, max(idle.SPEED_MIN, 500.0 / rtt_ms)) \
        if rtt_ms and rtt_ms > 0 else 1.0
    # Match the log slider's 0.05 step quantization so the browser can reuse
    # this model without triggering another capture scan.
    slider_step = 0.05
    slider_value = round(math.log10(auto_speed) / slider_step) * slider_step
    effective_speed = 10 ** slider_value
    detail["playback"] = idle.timeline(
        detail["packets"], mode="smart", speed=effective_speed
    )
    return jsonify({
        "streams": summaries,
        "flow": detail,
        "payload": conversation_from_follow_output(
            follow_output, selected, CONVERSATION_PREVIEW_BYTES, 0
        ),
        "tshark_passes": 1,
    })


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
    detail = stream_detail(packets, int(raw))
    # Compression is a playback concern, so it is computed only when asked for.
    mode = request.args.get("mode", "")
    # Validate speed whenever it is supplied, even without a mode, rather than
    # silently ignoring a value the caller took the trouble to send.
    speed_arg = request.args.get("speed", "")
    speed = 1.0
    if speed_arg:
        try:
            speed = float(speed_arg)
        except ValueError:
            abort(400, "Invalid speed")
        # Bounds come from the playback module so the slider range and this
        # validation cannot drift apart.
        if not idle.SPEED_MIN <= speed <= idle.SPEED_MAX:
            abort(400, "Speed out of range")
    if mode:
        if mode not in idle.MODES:
            abort(400, "Unknown playback mode")
        # Pass the packets unchanged: the gap classifier consults the same
        # sequence accounting as /api/flow, so a partial projection would break
        # the outstanding-payload check it relies on.
        detail["playback"] = idle.timeline(detail["packets"], mode=mode, speed=speed)
    return jsonify(detail)


@app.get("/api/match")
def match():
    """Cross-connection consistency for one capture.

    Fingerprints every stream, then reports which families recur. A family seen
    once is weak evidence; the same family across many connections is stronger.
    """
    packets = read_capture(capture_path(request.args.get("file", "")))
    per_stream = []
    for summary in summarize(packets):
        detail = stream_detail(packets, summary["id"])
        row = {"id": summary["id"], "client": summary["client"],
               "server": summary["server"], "port": summary["server_port"]}
        for side in ("client", "server"):
            fp = detail.get("fingerprint") or {}
            row[side] = fp.get(side) or {}
        per_stream.append(row)
    return jsonify({"streams": len(per_stream),
                    "entries": per_stream,
                    **fingerprint.cross_connection_consistency(per_stream)})


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
