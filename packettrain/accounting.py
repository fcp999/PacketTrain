"""Per-stream summaries, capture-side inference and stream detail."""
from collections import defaultdict

from flask import abort

from .decode import slicing_report
from .behavior import classify_stream
from .https import analyze_https


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
            "https": https, "slicing": slicing_report(group),
            "note": "Incoming timestamps are arrival times at the capture point. One-way time is estimated as RTT/2; choose the capture side manually if the handshake is ambiguous."}


