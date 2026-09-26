"""Classify observable traffic shape, never the application or file type."""
from statistics import median, pstdev


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


