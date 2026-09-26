"""Behaviour phases within a TCP stream.

A phase is a contiguous interval with a label, its time bounds, the evidence
that justified it, any competing interpretation, and the frame references.
Thresholds are versioned analysis settings, not TCP constants: they are named
here so a result can be reproduced against a stated rule set.
"""

# Versioned thresholds. Changing a value changes results, so the version is
# reported with every phase set.
THRESHOLDS = {
    "version": "2026-09-26.1",
    "idle_gap_s": 2.0,          # quiet time that separates phases
    "bulk_min_bytes": 65_536,   # payload in one phase that counts as bulk
    "bulk_min_share": 0.5,      # share of that phase's payload in one direction
    "small_max_bytes": 4_096,   # a phase at or below this is a small exchange
    "teardown_tail_s": 5.0,     # window after the last payload for FIN/RST
}


def _activity(packets):
    """Group packets into contiguous activity runs separated by idle gaps."""
    ordered = sorted(packets, key=lambda p: p["time_ms"])
    if not ordered:
        return []
    runs = []
    current = {"packets": [ordered[0]], "start": ordered[0]["time_ms"],
               "end": ordered[0]["time_ms"]}
    for p in ordered[1:]:
        if (p["time_ms"] - current["end"]) / 1000.0 > THRESHOLDS["idle_gap_s"]:
            runs.append(current)
            current = {"packets": [p], "start": p["time_ms"], "end": p["time_ms"]}
        else:
            current["packets"].append(p)
            current["end"] = p["time_ms"]
    runs.append(current)
    return runs


def _classify_run(run):
    """Label one activity run from its own payload shape."""
    packets = run["packets"]
    payload = [p for p in packets if p["length"] > 0]
    out_bytes = sum(p["length"] for p in packets if p["direction"] == "out")
    in_bytes = sum(p["length"] for p in packets if p["direction"] == "in")
    total = out_bytes + in_bytes
    span_s = (run["end"] - run["start"]) / 1000.0

    if not payload:
        # Control traffic only. Distinguish a setup opener from a teardown.
        if any(p["syn"] and not p["ack_flag"] for p in packets):
            return {"label": "Setup", "evidence": ["SYN with no payload"],
                    "alternatives": []}
        if any(p["fin"] or p["rst"] for p in packets):
            return {"label": "Teardown", "evidence": ["FIN or RST with no payload"],
                    "alternatives": []}
        return {"label": "Control exchange", "evidence": ["No payload observed"],
                "alternatives": []}

    dominant = max(out_bytes, in_bytes)
    share = dominant / total if total else 0.0
    direction = "out" if out_bytes >= in_bytes else "in"

    if total >= THRESHOLDS["bulk_min_bytes"] and share >= THRESHOLDS["bulk_min_share"]:
        alternatives = []
        if any(p.get("tls_record") for p in packets):
            alternatives.append("Encrypted traffic; a bulk shape does not prove a file transfer")
            if any(p.get("retrans") for p in packets):
                alternatives.append("Retransmissions present; some bytes may be repeats")
        return {"label": "Bulk transfer", "direction": direction,
                "evidence": [f"{total:,} payload bytes over {span_s:.1f}s",
                             f"{share:.0%} in one direction",
                             f"{len(payload)} payload records"],
                "alternatives": alternatives}

    if total <= THRESHOLDS["small_max_bytes"]:
        turns = sum(1 for a, b in zip(packets, packets[1:])
                    if a["direction"] != b["direction"])
        return {"label": "Small exchange",
                "evidence": [f"{total:,} payload bytes", f"{turns} direction changes"],
                "alternatives": []}

    return {"label": "Payload exchange",
            "evidence": [f"{total:,} payload bytes", f"{span_s:.1f}s"],
            "alternatives": []}


def stream_phases(packets):
    """Segment a stream into phases with bounds, evidence and frame references."""
    ordered = sorted(packets, key=lambda p: p["time_ms"])
    if not ordered:
        return {"phases": [], "thresholds": THRESHOLDS, "limitation": None}

    phases = []
    runs = _activity(ordered)

    # A pause is the quiet interval between runs, reported explicitly rather
    # than hidden: the spec distinguishes a payload pause from a teardown.
    for index, run in enumerate(runs):
        verdict = _classify_run(run)
        phase = {
            "index": len(phases),
            "label": verdict["label"],
            "start_ms": round(run["start"], 3),
            "end_ms": round(run["end"], 3),
            "duration_ms": round(run["end"] - run["start"], 3),
            "packets": len(run["packets"]),
            "frames": [p["frame"] for p in run["packets"]],
            "evidence": verdict["evidence"],
            "alternatives": verdict["alternatives"],
        }
        if "direction" in verdict:
            phase["direction"] = verdict["direction"]
        phases.append(phase)

        if index + 1 < len(runs):
            gap_s = (runs[index + 1]["start"] - run["end"]) / 1000.0
            phases.append({
                "index": len(phases),
                "label": "Payload pause" if gap_s < 30 else "Idle",
                "start_ms": round(run["end"], 3),
                "end_ms": round(runs[index + 1]["start"], 3),
                "duration_ms": round((runs[index + 1]["start"] - run["end"]), 3),
                "packets": 0,
                "frames": [],
                "evidence": [f"{gap_s:.1f}s with no captured activity"],
                "alternatives": ["An application pause and a network gap look the "
                                 "same at one capture point"],
            })

    return {"phases": phases, "thresholds": THRESHOLDS,
            "limitation": ("Phase boundaries follow a disclosed idle threshold and "
                           "are not unique. Encrypted streams can hide an application "
                           "pause inside an apparent control exchange.")}


def transport_symptoms(packets):
    """Transport-level observations, kept separate from behaviour labels.

    Each symptom says what was observed and what it does not prove.
    """
    ordered = sorted(packets, key=lambda p: p["time_ms"])
    symptoms = []

    retrans = [p for p in ordered if p.get("retrans")]
    if retrans:
        symptoms.append({
            "symptom": "Recovery observed",
            "observed": f"{len(retrans)} retransmission record(s)",
            "frames": [p["frame"] for p in retrans[:20]],
            "does_not_prove": ("A retransmission shows the receiver did not "
                               "acknowledge in time; it does not by itself "
                               "attribute loss to the network."),
        })

    # Only a window that was actually advertised as zero is a stall. An absent
    # field (sliced capture, non-TCP row) is unknown, not zero.
    zero_window = [p for p in ordered
                   if p.get("window_present") and p.get("window") == 0]
    if zero_window:
        symptoms.append({
            "symptom": "Receiver flow-control stall",
            "observed": f"{len(zero_window)} zero-window advertisement(s)",
            "frames": [p["frame"] for p in zero_window[:20]],
            "does_not_prove": "Flow control is receiver-driven; this is not congestion.",
        })

    sack = [p for p in ordered if p.get("sack")]
    if sack:
        symptoms.append({
            "symptom": "SACK signalling present",
            "observed": f"{len(sack)} ACK(s) carrying SACK blocks",
            "frames": [p["frame"] for p in sack[:20]],
            "does_not_prove": "SACK reports received ranges, not the cause of the gap.",
        })

    if any(p["rst"] for p in ordered):
        rst = [p for p in ordered if p["rst"]]
        symptoms.append({
            "symptom": "Connection failure",
            "observed": f"{len(rst)} RST record(s)",
            "frames": [p["frame"] for p in rst[:20]],
            "does_not_prove": ("A RST ends the connection; it may be an application "
                               "choice, a firewall, or a timeout."),
        })

    # ACK-paced delivery: payload flights interleaved with ACKs, no large bursts.
    payload = [p for p in ordered if p["length"] > 0]
    if len(payload) >= 4:
        gaps = [(b["time_ms"] - a["time_ms"]) for a, b in zip(payload, payload[1:])]
        if gaps and max(gaps) < 50 and len(payload) >= 8:
            symptoms.append({
                "symptom": "ACK-paced delivery",
                "observed": f"{len(payload)} payload records, no gap above 50 ms",
                "frames": [],
                "does_not_prove": ("ACK pacing alone does not prove a congestion-window "
                                   "limit; the sender may simply have little to send."),
            })

    return {"symptoms": symptoms,
            "limitation": ("Transport symptoms are observations at one capture point. "
                           "Neither ACK pacing nor a response gap establishes the "
                           "sender's cwnd or a remote host's processing delay.")}
