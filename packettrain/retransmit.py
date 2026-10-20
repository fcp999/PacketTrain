"""Retransmission analysis: repeated sequence ranges, reordering, artifacts.

TShark already labels a frame as a retransmission when it re-sends sequence
space that was previously sent in the same direction. That label answers "was
this a repeat" but not the three questions that matter for diagnosis:

1. How much *unique* data was carried versus repeated? A flow can show forty
   retransmission records and be perfectly healthy if they cover two packets.
2. Was the repeat a genuine retransmission, or did the network deliver packets
   out of order and the sender's fast-retransmit logic duplicate them? The
   difference is loss versus reordering, and they have opposite fixes.
3. Did the capture see both sides? A retransmission observed in only one
   direction is frequently the capture point missing the first transmission,
   not the network losing it.

Sequence space is handled relative to each direction's initial sequence number,
so 32-bit wraparound does not corrupt the comparisons.
"""

from .accounting_tcp import SEQ_SPACE, initial_sequence, relative, unique_payload

# A retransmission whose original arrived within this window, while later
# sequence space was already acknowledged, is most likely a reordering artifact
# rather than loss: the receiver had already signalled the gap.
REORDER_WINDOW_MS = 200.0

# Fewer repeated segments than this and the "analysis" is describing noise.
MIN_MEANINGFUL_RETRANS = 1


def _payload_by_direction(packets):
    """Group payload-bearing packets by direction, keeping arrival order."""
    return {
        "client": [p for p in packets if p["direction"] == "out" and p["length"] > 0],
        "server": [p for p in packets if p["direction"] == "in" and p["length"] > 0],
    }


def _segments(packets, from_client):
    """Assign each payload packet its relative sequence range and repeat status."""
    base = initial_sequence(packets, from_client)
    # Use the capture clock directly. stream_detail adds ``time_ms``, but the
    # analysis must not depend on a caller having done so.
    origins = [p["ts"] for p in packets if p.get("ts") is not None]
    origin = min(origins) if origins else None
    segments = []
    for p in packets:
        start = relative(p["seq"], base)
        ts = p.get("ts")
        segments.append({
            "frame": p["frame"],
            "time_ms": (round((ts - origin) * 1000.0, 3)
                        if ts is not None and origin is not None else None),
            "start": start,
            "end": start + p["length"],
            "length": p["length"],
            "repeat": bool(p.get("retrans")),
            "sack": bool(p.get("sack")),
            "seq": p["seq"] % SEQ_SPACE,
        })
    return segments


def _overlap(first, second):
    """Bytes covered by both sequence ranges."""
    return max(0, min(first["end"], second["end"]) - max(first["start"], second["start"]))


def _first_transmissions(segments):
    """Split segments into first transmissions and repeats.

    A segment counts as a repeat when an earlier segment in the same direction
    already covered any of its sequence space. This deliberately uses sequence
    overlap rather than the TShark label: a partial retransmission carries some
    new data, and the label cannot say how much.
    """
    covered = []
    firsts = []
    repeats = []
    for segment in segments:
        duplicate_bytes = sum(_overlap(segment, prior) for prior in covered)
        # Overlapping priors can double-count, so clamp to the segment size.
        duplicate_bytes = min(duplicate_bytes, segment["length"])
        if duplicate_bytes:
            repeats.append({**segment,
                            "repeat_bytes": duplicate_bytes,
                            "new_bytes": segment["length"] - duplicate_bytes})
        else:
            firsts.append(segment)
        covered.append(segment)
    return firsts, repeats


def _classify(repeat, firsts, ordered):
    """Decide whether a repeat is reordering, capture artifact, or real loss."""
    overlapping = [s for s in firsts if _overlap(s, repeat)]
    if not overlapping:
        return "unknown", "no earlier transmission of this sequence space was captured"

    original = max(overlapping, key=lambda s: _overlap(s, repeat))
    gap_ms = (repeat["time_ms"] - original["time_ms"]) if (
        repeat["time_ms"] is not None and original["time_ms"] is not None) else None

    # A repeat that overtook the original -- arrived before the copy it
    # duplicates -- is arrival reordering, not sender recovery.
    if gap_ms is not None and gap_ms < 0:
        return "reordering", (
            f"duplicate arrived {abs(gap_ms):.1f} ms before the original record, "
            "so arrival order differs from send order")

    # A repeat arriving inside the reorder window, with no duplicate ACK that
    # would trigger fast retransmit, is more likely the duplicate caused by
    # reordering than a recovery action.
    if gap_ms is not None and gap_ms <= REORDER_WINDOW_MS:
        duplicate_acks = sum(
            1 for p in ordered
            if p.get("dup_ack")
            and original["time_ms"] is not None
            and p.get("ts") is not None
            and original["time_ms"] <= round((p["ts"] - min(
                q["ts"] for q in ordered if q.get("ts") is not None)) * 1000.0, 3)
            <= repeat["time_ms"])
        if not duplicate_acks:
            return "reordering", (
                f"repeat {gap_ms:.1f} ms after the original with no duplicate ACKs "
                "in between, which is consistent with reordering")

    return "retransmission", (
        f"repeat {gap_ms:.1f} ms after the original" if gap_ms is not None
        else "repeat after the original")


def retransmission_analysis(group):
    """Classify repeats, quantify unique data, and flag capture artifacts.

    ``group`` is one stream's packet list, already carrying ``direction``.
    """
    payload = _payload_by_direction(group)
    by_direction = {
        "client": _segments(payload["client"], True),
        "server": _segments(payload["server"], False),
    }

    totals = {}
    verdicts = {"retransmission": 0, "reordering": 0, "unknown": 0}
    captured_frames = []
    for direction, segments in by_direction.items():
        firsts, repeats = _first_transmissions(segments)
        sent_bytes = sum(s["length"] for s in firsts)
        repeated_bytes = sum(r["repeat_bytes"] for r in repeats)
        for repeat in repeats:
            verdict, reason = _classify(repeat, firsts, group)
            verdicts[verdict] += 1
            repeat["verdict"] = verdict
            repeat["reason"] = reason
            if len(captured_frames) < 20:
                captured_frames.append({
                    "frame": repeat["frame"],
                    "direction": direction,
                    "verdict": verdict,
                    "reason": reason,
                    "repeat_bytes": repeat["repeat_bytes"],
                    "new_bytes": repeat["new_bytes"],
                })
        totals[direction] = {
            "records": len(segments),
            "first_transmissions": len(firsts),
            "repeats": len(repeats),
            # Unique payload this direction actually contributed.
            "unique_bytes": sent_bytes,
            "repeated_bytes": repeated_bytes,
            "repeat_fraction": (round(repeated_bytes / (sent_bytes + repeated_bytes), 4)
                                if sent_bytes + repeated_bytes else 0.0),
            "repeated_percent": (round(100.0 * repeated_bytes / (sent_bytes + repeated_bytes), 2)
                                 if sent_bytes + repeated_bytes else 0.0),
        }

    # One-sided repeats: a direction repeat with no repeat in the other
    # direction is the classic signature of a capture point that only saw one
    # half of the path, rather than the network losing data.
    client_repeats = totals["client"]["repeats"]
    server_repeats = totals["server"]["repeats"]
    artifact = None
    if (client_repeats or server_repeats) and not (client_repeats and server_repeats):
        side = "client" if client_repeats else "server"
        artifact = {
            "suspected": True,
            "side": side,
            "detail": (f"repeats appear only in the {side} direction; a capture at "
                       "one endpoint commonly records the first transmission as "
                       "missing rather than lost"),
        }

    repeated_total = totals["client"]["repeated_bytes"] + totals["server"]["repeated_bytes"]
    unique_total = totals["client"]["unique_bytes"] + totals["server"]["unique_bytes"]
    return {
        "basis": "sequence-range overlap on captured TCP payload",
        "by_direction": totals,
        "verdicts": verdicts,
        "repeated_bytes": repeated_total,
        "unique_bytes": unique_total,
        "repeated_percent": (round(100.0 * repeated_total / (unique_total + repeated_total), 2)
                             if unique_total + repeated_total else 0.0),
        "repeats": captured_frames,
        "capture_artifact": artifact,
        "meaningful": (client_repeats + server_repeats) >= MIN_MEANINGFUL_RETRANS,
        "does_not_prove": (
            "A repeat shows sequence space was sent twice. Whether the cause was "
            "loss, reordering or the capture point is stated per repeat and is a "
            "judgement from timing, not a proof."),
    }
