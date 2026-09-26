"""Idle compression: decide which gaps are safe to compress during replay.

The rule that matters most is the negative one. A gap is only compressible when
the evidence says the stream was genuinely quiet. Unresolved outstanding bytes,
a zero-window wait, handshake retries and retransmission waits all look like
quiet in the packet timestamps while actually being transport activity, so they
must be preserved. When visibility is insufficient to tell, preserve the gap.

Compression never drops a packet or rewrites a timestamp: it only controls
playback pacing, and every compressed interval keeps its duration, boundaries
and an expansion option.
"""

MODES = {
    "version": "2026-09-26.1",
    "faithful": "Preserve captured timing at the selected speed.",
    "smart": "Compress qualified idle intervals; preserve transport waits.",
    "fast": "Compress long gaps, labelling transport waits explicitly.",
}

# A gap must be long enough in wall-clock terms at the selected speed to be
# worth compressing. The spec suggests two seconds of playback.
PLAYBACK_TRIGGER_S = 2.0

# Reasons a gap must be preserved rather than compressed.
TRANSPORT_WAIT_REASONS = {
    "unresolved_outstanding": "payload was still unacknowledged across the gap",
    "zero_window": "a zero-window advertisement preceded the gap",
    "handshake_retry": "a handshake retry preceded the gap",
    "retransmission": "a retransmission preceded the gap",
    "unclassifiable": "visibility was insufficient to classify the gap",
}


def _outstanding_within(packets, start_ms, end_ms):
    """Whether payload was unacknowledged at any point from start to end.

    Asking only about the instant before the gap misses the case where the
    outstanding reading falls inside the gap itself, which is exactly when a
    wait is hiding.
    """
    from .accounting_tcp import outstanding_bytes
    series = outstanding_bytes(packets)["series"]
    return any(pt["time_ms"] is not None
               and start_ms <= pt["time_ms"] <= end_ms
               and pt["outstanding"] > 0
               for pt in series)


def _gap_reason(packets, before, after):
    """Classify the quiet interval between two packets.

    Returns (compressible, reason_key). Compression is allowed only for
    `idle`; every transport-wait key is preserved.
    """
    # A retransmission or zero window in or immediately before the gap means the
    # stream was doing transport work, not sitting idle.
    window = [p for p in packets
              if before["time_ms"] <= p["time_ms"] <= after["time_ms"]]
    preceding = window or [before]

    if any(p.get("window_present") and p.get("window") == 0 for p in preceding):
        return False, "zero_window"
    if any(p.get("retrans") for p in preceding):
        return False, "retransmission"
    if any(p.get("syn") and not p.get("ack_flag") for p in preceding) and \
            not any(p.get("syn") and p.get("ack_flag") for p in preceding):
        return False, "handshake_retry"
    if _outstanding_within(packets, before["time_ms"], after["time_ms"]):
        return False, "unresolved_outstanding"

    # Nothing in the packet stream explains the gap. That is not the same as
    # proving it was idle, so say so and let the caller decide by mode.
    return True, "idle"


def analyze_gaps(packets, mode="smart", speed=1.0, trigger_s=PLAYBACK_TRIGGER_S):
    """Find gaps in a stream and decide how to replay each one.

    `speed` is the playback multiplier, so the wall-clock cost of a gap is its
    captured duration divided by the speed.
    """
    ordered = sorted(packets, key=lambda p: p["time_ms"])
    if len(ordered) < 2:
        return {"mode": mode, "mode_version": MODES["version"], "gaps": [],
                "compressed_seconds": 0.0,
                "limitation": None}

    gaps = []
    compressed = 0.0
    for before, after in zip(ordered, ordered[1:]):
        captured_s = (after["time_ms"] - before["time_ms"]) / 1000.0
        if captured_s <= 0:
            continue
        playback_s = captured_s / max(speed, 0.001)

        if mode == "faithful":
            gaps.append({"start_ms": before["time_ms"], "end_ms": after["time_ms"],
                         "captured_s": round(captured_s, 3),
                         "compressible": False, "reason": "faithful mode",
                         "label": None,
                         "frames": [before["frame"], after["frame"]]})
            continue

        # Both smart and fast preserve transport waits. Fast may compress a
        # wait, but only with an explicit label, so it is still reported here
        # rather than silently dropped.
        compressible, reason = _gap_reason(ordered, before, after)
        too_short = playback_s < trigger_s

        if compressible and not too_short:
            compressed += captured_s
            label = f"Idle interval compressed \u00b7 {captured_s:.1f} s"
        elif not compressible and mode == "fast" and not too_short:
            # Fast review may compress a transport wait, with the wait named.
            compressed += captured_s
            label = (f"Transport wait compressed \u00b7 {captured_s:.1f} s "
                     f"({TRANSPORT_WAIT_REASONS.get(reason, reason)})")
        else:
            label = None

        entry = {"start_ms": round(before["time_ms"], 3),
                 "end_ms": round(after["time_ms"], 3),
                 "captured_s": round(captured_s, 3),
                 "playback_s": round(playback_s, 3),
                 "compressible": bool(compressible),
                 "reason": reason,
                 "label": label,
                 "expandable": True,
                 "frames": [before["frame"], after["frame"]]}
        if not compressible:
            entry["preserved_because"] = TRANSPORT_WAIT_REASONS.get(reason, reason)
        gaps.append(entry)

    return {"mode": mode, "mode_version": MODES["version"],
            "speed": speed, "trigger_s": trigger_s,
            "gaps": gaps,
            "compressed_count": sum(1 for g in gaps if g.get("label")),
            "compressed_seconds": round(compressed, 3),
            "limitation": ("A compressed interval keeps its duration, boundaries and "
                           "expansion option, and no packet or timestamp is changed. "
                           "Qualified idle may still contain application delay, and a "
                           "gap is preserved whenever visibility is insufficient to "
                           "classify it.")}


def timeline(packets, mode="smart", speed=1.0):
    """Playback timeline with compressed gaps marked.

    Returns segments the player walks in order. Every packet appears exactly
    once, so compression cannot lose a packet.
    """
    analysis = analyze_gaps(packets, mode=mode, speed=speed)
    timeline = []
    by_start = {}
    for gap in analysis["gaps"]:
        by_start[gap["frames"][0]] = gap
    for p in sorted(packets, key=lambda q: q["time_ms"]):
        gap = by_start.get(p["frame"])
        timeline.append({"frame": p["frame"], "time_ms": p["time_ms"], "kind": "packet"})
        if gap and gap.get("label"):
            timeline.append({"kind": "compressed",
                             "label": gap["label"],
                             "captured_s": gap["captured_s"],
                             "expandable": True,
                             "start_ms": gap["start_ms"],
                             "end_ms": gap["end_ms"]})
    return {"analysis": analysis, "segments": timeline}
