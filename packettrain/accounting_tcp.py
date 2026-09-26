"""TCP accounting: sequence ranges, window scaling, outstanding data, bursts.

Every result reports its accounting basis and limitations. "Unknown" is
distinct from zero throughout: a measurement that cannot be taken returns None
rather than a misleading 0.
"""

# A burst is consecutive same-direction payload records no more than this far
# apart. Disclosed with the result because the number is a choice, not a fact.
BURST_GAP_S = 0.2

SEQ_SPACE = 1 << 32


def initial_sequence(packets, from_client):
    """The initial sequence number a direction opened with, or None.

    Sequence numbers on the wire are absolute 32-bit values, so every
    comparison has to be made relative to the ISN rather than to zero.
    """
    wanted = "out" if from_client else "in"
    for p in packets:
        if p.get("syn") and p["direction"] == wanted:
            return p["seq"] % SEQ_SPACE
    # No SYN captured: fall back to the first payload record of that direction so
    # a mid-stream capture still produces a consistent relative view.
    first = next((p for p in packets
                  if p["direction"] == wanted and p["length"] > 0), None)
    return first["seq"] % SEQ_SPACE if first else None


def relative(value, base):
    """Express an absolute sequence number relative to an initial one.

    Wraps correctly when the value sits below the base in absolute terms.
    """
    if base is None:
        return value % SEQ_SPACE
    return (value - base) % SEQ_SPACE


def _seq_ranges(packets, from_client):
    """Collect (start, end) payload sequence ranges for one direction, relative
    to that direction's initial sequence number.

    Handles wraparound by splitting a range that crosses 2^32.
    """
    base = initial_sequence(packets, from_client)
    ranges = []
    for p in packets:
        if (p["direction"] == ("out" if from_client else "in")) and p["length"] > 0:
            start = relative(p["seq"], base)
            end = start + p["length"]
            if end > SEQ_SPACE:
                ranges.append((start, SEQ_SPACE))
                ranges.append((0, end - SEQ_SPACE))
            else:
                ranges.append((start, end))
    return ranges


def unique_payload(ranges):
    """Total bytes covered by a set of ranges, counting overlap once.

    Partial retransmission overlap is common, so a plain sum overstates the
    data actually sent.
    """
    if not ranges:
        return 0
    merged = []
    for start, end in sorted(ranges):
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return sum(end - start for start, end in merged)


def window_scale(packets, from_client):
    """Negotiated window scale shift for one direction, or None if not seen.

    The shift is advertised in a SYN option. A SYN's own window value is
    unscaled; scaling applies to later segments. None means the scale is
    unknown, which is not the same as shift 0.
    """
    wanted = "out" if from_client else "in"
    for p in packets:
        if p.get("syn") and p["direction"] == wanted and p.get("wscale", -1) >= 0:
            return p["wscale"]
    return None


def scaled_window(packets):
    """Receive-window history with the negotiated scale applied.

    Returns None for the scale when it was never advertised, and flags each
    point so a caller can tell a truly unscaled window from an unknown one.
    """
    out_scale = window_scale(packets, True)
    in_scale = window_scale(packets, False)
    history = []
    for p in packets:
        if not p.get("window"):
            continue
        scale = out_scale if p["direction"] == "out" else in_scale
        # A SYN's window is not scaled even when it carries the option.
        applied = scale if (scale is not None and not p.get("syn")) else None
        history.append({
            "time_ms": p.get("time_ms"),
            "direction": p["direction"],
            "raw": p["window"],
            "scale_shift": scale,
            "scaled": p["window"] << applied if applied is not None else None,
            "counting_basis": ("scaled by the advertised shift" if applied is not None
                               else "unscaled: no scale advertised, or this is a SYN"),
        })
    return {"history": history, "client_scale_shift": out_scale,
            "server_scale_shift": in_scale,
            "limitation": ("Window scale is taken from the SYN options. If the SYN is "
                           "absent or sliced, the scale is unknown and windows are "
                           "reported unscaled rather than guessed.")}


def _timestamp(packet):
    """Seconds for ordering, accepting either wire form.

    Stream accounting runs on packets that keep "ts"; the /api/flow response
    drops it in favour of "time_ms". Both are valid inputs here.
    """
    if packet.get("ts") is not None:
        return packet["ts"]
    ms = packet.get("time_ms")
    return (ms / 1000.0) if ms is not None else 0.0


def outstanding_bytes(packets):
    """Observed unacknowledged payload over time, per direction.

    This is observed outstanding data at the capture point, not the sender's
    congestion window and not an RFC 6675 pipe estimate: the exact cwnd is not
    carried in the TCP header.
    """
    series = []
    for from_client, label in ((True, "out"), (False, "in")):
        sent_packets = [p for p in packets
                        if p["direction"] == ("out" if from_client else "in")
                        and p["length"] > 0]
        if not sent_packets:
            continue
        base = initial_sequence(packets, from_client)
        acks = [p for p in packets
                if p["direction"] == ("in" if from_client else "out")
                and p.get("ack") is not None and p.get("ack") != 0]
        # Walk both series in timestamp order, growing the sent set as ACKs
        # arrive. Counting payload sent AFTER an ACK would report data as
        # outstanding before it was ever transmitted.
        sent_packets.sort(key=_timestamp)
        acks.sort(key=_timestamp)
        sent_so_far = []
        cursor = 0
        for ack_packet in acks:
            while (cursor < len(sent_packets)
                   and _timestamp(sent_packets[cursor]) <= _timestamp(ack_packet)):
                p = sent_packets[cursor]
                start = relative(p["seq"], base)
                sent_so_far.append((start, start + p["length"]))
                cursor += 1
            acked = relative(ack_packet["ack"], base)
            open_ranges = [(max(start, acked), end) for start, end in sent_so_far
                           if end > acked]
            series.append({"time_ms": ack_packet.get("time_ms"), "direction": label,
                           "outstanding": unique_payload(open_ranges),
                           "cumulative_ack": acked,
                           "sent_records_counted": cursor})
    series.sort(key=lambda pt: (pt["time_ms"] if pt["time_ms"] is not None else 0))
    return {"series": series,
            "limitation": ("Reported as observed outstanding data, not cwnd. Sequence "
                           "wraparound beyond one 2^32 window, loss, and SACK-based "
                           "recovery are not modelled.")}


def largest_burst(packets, gap_s=BURST_GAP_S):
    """Largest consecutive same-direction payload run, with threshold sensitivity."""
    def bursts_at(gap):
        found = []
        current = None
        for p in sorted(packets, key=lambda q: q["ts"]):
            if p["length"] <= 0:
                continue
            if current and current["direction"] == p["direction"] and p["ts"] - current["end"] <= gap:
                current.update(end=p["ts"], bytes=current["bytes"] + p["length"],
                               records=current["records"] + 1)
            else:
                if current:
                    found.append(current)
                current = {"direction": p["direction"], "start": p["ts"], "end": p["ts"],
                           "bytes": p["length"], "records": 1}
        if current:
            found.append(current)
        return found

    found = bursts_at(gap_s)
    if not found:
        return {"largest": None, "threshold_s": gap_s, "sensitivity": [], "limitation": None}
    largest = max(found, key=lambda b: b["bytes"])
    return {
        "largest": {"bytes": largest["bytes"], "records": largest["records"],
                    "span_ms": round((largest["end"] - largest["start"]) * 1000, 3),
                    "direction": largest["direction"]},
        "threshold_s": gap_s,
        # The number depends on the threshold, so show nearby thresholds too.
        "sensitivity": [{"threshold_s": g,
                         "largest_bytes": max((b["bytes"] for b in bursts_at(g)), default=0)}
                        for g in (gap_s / 2, gap_s, gap_s * 2, gap_s * 5)],
        "limitation": ("Burst grouping uses a disclosed gap threshold; a different "
                       "threshold gives a different largest burst. Burst size is not a "
                       "congestion-window measurement."),
    }


def tcp_accounting(packets):
    """All accounting for one stream."""
    client_ranges = _seq_ranges(packets, True)
    server_ranges = _seq_ranges(packets, False)
    return {
        "unique_payload_bytes": {"client": unique_payload(client_ranges),
                                 "server": unique_payload(server_ranges)},
        "window": scaled_window(packets),
        "outstanding": outstanding_bytes(packets),
        "bursts": largest_burst(packets),
    }
