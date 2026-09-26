"""Per-stream summaries, capture-side inference and stream detail."""
from collections import defaultdict

from flask import abort

from .decode import slicing_report
from .behavior import classify_stream
from .https import analyze_https
from .position import position_evidence
from .accounting_tcp import tcp_accounting
from .fingerprint import fingerprint_endpoint
from .phases import stream_phases, transport_symptoms


# A rate sample needs enough packets that one scheduling hiccup
# cannot dominate the elapsed time.
BURST_MIN_PACKETS = 5

def burst_rate(group, data_direction, min_packets=BURST_MIN_PACKETS):
    """Estimate link rate from a run of back-to-back packets.

    The first data flight is the worst sample available: it is slow start, so the
    sender is still probing and the spacing reflects congestion response rather
    than the link. This walks later runs instead, requiring a minimum number of
    consecutive same-direction payload packets with no intervening ACK, and
    reports where the sample came from.

    Two rates are returned. The capture rate uses capture timestamps, which can
    precede physical transmission. The tsval rate uses the sender's own clock, so
    it is independent of the capture point, but its resolution is coarse (Linux
    ticks at 1 ms), so it bounds a short burst rather than resolving it.
    """
    runs = []
    current = []
    for p in group:
        if p["direction"] == data_direction and p["length"] > 0:
            current.append(p)
            continue
        if p["direction"] != data_direction and p["ack_flag"]:
            if len(current) >= min_packets:
                runs.append(current)
            current = []
    if len(current) >= min_packets:
        runs.append(current)

    if not runs:
        return {"available": False,
                "reason": f"no run of {min_packets} consecutive payload packets",
                "min_packets": min_packets}

    # Prefer the longest run: the least sensitive to a single scheduling hiccup.
    # Runs before that one are the slow-start ramp, and its index is reported.
    best_index = max(range(len(runs)), key=lambda i: len(runs[i]))
    run = runs[best_index]
    first, last = run[0], run[-1]
    payload_bits = sum(p["length"] for p in run) * 8
    span_ms = last["time_ms"] - first["time_ms"]

    capture_rate = None
    if span_ms > 0:
        capture_rate = payload_bits / (span_ms / 1000.0)

    tsval_rate = None
    ts_reason = None
    ts_first = first.get("tsval")
    ts_last = last.get("tsval")
    present = [p.get("tsval") for p in run if p.get("tsval") is not None]
    if len(present) < 2:
        ts_reason = ("no TCP timestamp option on these packets, so the endpoint "
                     "clock cannot be used as a cross-check")
    elif ts_last is None or ts_first is None or ts_last <= ts_first:
        # A tick is 1 ms on Linux, so a burst under a millisecond lands in one
        # tick. Say so rather than returning nothing, which reads as a fault.
        ts_reason = ("the whole burst falls inside one timestamp tick, so the "
                     "sender clock cannot resolve it; the burst is under 1 ms")
    else:
        tsval_rate = payload_bits / ((ts_last - ts_first) / 1000.0)

    return {"available": True,
            "packets": len(run),
            "payload_bytes": sum(p["length"] for p in run),
            "span_ms": round(span_ms, 3),
            "capture_rate_mbps": round(capture_rate / 1e6, 2) if capture_rate else None,
            "tsval_rate_mbps": round(tsval_rate / 1e6, 2) if tsval_rate else None,
            "tsval_span_ms": (ts_last - ts_first) if tsval_rate is not None else None,
            "tsval_note": ts_reason,
            "tsval_resolution_ms": 1,
            "run_index": best_index,
            "runs_before": best_index,
            "sample_frame_range": [first["frame"], last["frame"]],
            "min_packets": min_packets,
            "note": ("Sampled after the slow-start ramp. The capture rate can exceed "
                     "the link because capture timestamps may precede transmission; "
                     "the tsval rate is quantised to the sender's tick and so bounds "
                     "the burst from below.")}


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
    https = analyze_https(group, (summary["client"], summary["client_port"]))
    # Accounting needs the original "ts", which the response drops below.
    accounting_input = [dict(p) for p in group]
    for p in group:
        p["time_ms"] = round((p.pop("ts") - first_ts) * 1000, 3)
        p["direction"] = "out" if (p["src"], p["sport"]) == (
            summary["client"], summary["client_port"]) else "in"
    for p, original in zip(accounting_input, group):
        p["time_ms"] = original["time_ms"]
        p["direction"] = original["direction"]
    syn = next((p for p in group if p["syn"] and not p["ack_flag"] and p["direction"] == "out"), None)
    synack = next((p for p in group if p["syn"] and p["ack_flag"] and p["direction"] == "in"
                   and (syn is None or p["time_ms"] > syn["time_ms"])), None)
    third = next((p for p in group if p["ack_flag"] and not p["syn"] and p["direction"] == "out"
                  and synack and p["time_ms"] > synack["time_ms"]), None)
    leg1 = synack["time_ms"] - syn["time_ms"] if syn and synack else None
    leg2 = third["time_ms"] - synack["time_ms"] if third and synack else None
    position = position_evidence(group, (summary["client"], summary["client_port"]),
                                 (leg1, leg2))
    side = position["side"]
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
    burst = burst_rate(group, data_direction)
    facts = {"mss": mss, "max_payload": max((p["length"] for p in group), default=0),
             "typical_frame_bytes": sizes[len(sizes) // 2] if sizes else None,
             "large_capture_records": sum(p["length"] > 1460 for p in group),
             "first_flight_packets": len(flight),
             "first_flight_bytes": sum(p["length"] for p in flight),
             "first_flight_span_ms": round(flight[-1]["time_ms"] - flight[0]["time_ms"], 3)
             if flight else None,
             "burst": burst,
             "retransmissions": sum(p["retrans"] for p in group),
             "sack_packets": sum(p["sack"] for p in group),
             "psh_packets": sum(p["psh"] for p in group)}
    tcp_detail = tcp_accounting(accounting_input)
    phases = stream_phases(accounting_input)
    symptoms = transport_symptoms(accounting_input)
    fingerprints = fingerprint_endpoint(accounting_input,
                                        (summary["client"], summary["client_port"]))
    return {"summary": summary, "rtt_ms": round(rtt, 2) if rtt is not None else None,
            "rtt_source": source, "capture_side": side, "position": position,
            "accounting": tcp_detail, "phases": phases, "symptoms": symptoms,
            "fingerprint": fingerprints,
            "handshake_legs_ms": [round(leg1, 3), round(leg2, 3)] if leg1 is not None and leg2 is not None else None,
            "packets": group, "facts": facts, "pattern": pattern,
            "https": https, "slicing": slicing_report(group),
            "note": "Incoming timestamps are arrival times at the capture point. One-way time is estimated as RTT/2; choose the capture side manually if the handshake is ambiguous."}


