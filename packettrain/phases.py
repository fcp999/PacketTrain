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


def _zero_window_probe(run, packets, peer_acks=None):
    """Recognise a run that carries a receiver window probe, or None.

    A TCP window probe is a zero-length segment that re-sends one byte below the
    point the peer has acknowledged for that sender's stream. It exists to
    provoke a window update from a receiver whose advertised window is closed,
    which is why it looks like a retransmission of already-acknowledged data
    that happens to carry no payload.

    Two sequence numbers must not be confused here. A segment's own ``seq`` and
    the ``ack`` field it carries belong to *different* streams: the ack refers to
    the peer's direction, not the sender's. A probe is therefore detected by
    comparing the sender's seq against the ack the *peer* most recently sent for
    that direction (``peer_acks``), never against the ack in the same packet.

    Detection requires both halves of the pattern:
      * a zero-length segment whose seq is one below the peer's ack for its own
        direction, and
      * a closed window advertised by that peer, in this run or immediately
        before it.
    Requiring the closed window keeps an ordinary stale zero-length ACK from
    being called a probe.
    """
    peer_acks = peer_acks or {}

    def acknowledged_for(packet):
        """Most recent ack the peer sent for this sender's direction.

        The peer sends from the reverse endpoint pair, so the lookup key is
        mirrored: the packet's destination becomes the ack's source.
        """
        key = (packet.get("dst"), packet.get("dport"),
               packet.get("src"), packet.get("sport"))
        return _ack_at(peer_acks, key, packet.get("time_ms"))

    probing = []
    for packet in packets:
        if not packet.get("ack_flag") or packet.get("length", 0) != 0:
            continue
        acked = acknowledged_for(packet)
        if acked is None:
            continue
        if _behind(packet.get("seq"), acked):
            probing.append(packet)
    if not probing:
        return None

    # The probe only makes sense against a closed window: look in this run, then
    # in the packets immediately preceding it.
    closed = [p for p in packets
              if p.get("window_present") and p.get("window") == 0]
    window_source = "this phase"
    if not closed:
        lookback = run.get("lookback", [])
        closed = [p for p in lookback
                  if p.get("window_present") and p.get("window") == 0]
        window_source = "the preceding segment"
    if not closed:
        return None

    evidence = [
        f"{len(probing)} zero-length segment(s) re-sending the byte before the "
        "peer's acknowledge point",
        f"peer advertised a closed window in {window_source}",
    ]
    advertiser = closed[0].get("src")
    if advertiser:
        evidence.append(f"closed window advertised by {advertiser}")
    return {
        "label": "Zero Window Probe",
        "evidence": evidence,
        "alternatives": [
            "A closed window means the receiver had no buffer space; the probe "
            "is the sender checking whether that changed",
        ],
        "probe_frames": [p["frame"] for p in probing],
        "window_frames": [p["frame"] for p in closed[:20]],
    }


def _behind(seq, ack):
    """True when ``seq`` sits at or just below ``ack`` in 32-bit sequence space.

    A window probe re-sends the single byte immediately preceding the point the
    peer has acknowledged, so the offset is 0 or 1. Larger offsets are ordinary
    in-flight data, not a probe.
    """
    if seq is None or ack is None:
        return False
    offset = (ack - seq) % (1 << 32)
    return offset in (0, 1)


def _classify_run(run, peer_acks=None):
    """Label one activity run from its own payload shape."""
    packets = run["packets"]
    payload = [p for p in packets if p["length"] > 0]
    out_bytes = sum(p["length"] for p in packets if p["direction"] == "out")
    in_bytes = sum(p["length"] for p in packets if p["direction"] == "in")
    total = out_bytes + in_bytes
    span_s = (run["end"] - run["start"]) / 1000.0

    if not payload:
        # Control traffic only. Distinguish a setup opener from a teardown, and
        # recognise window probes, which are otherwise indistinguishable from
        # any other payload-free segment.
        if any(p["syn"] and not p["ack_flag"] for p in packets):
            return {"label": "Setup", "evidence": ["SYN with no payload"],
                    "alternatives": []}
        if any(p["fin"] or p["rst"] for p in packets):
            return {"label": "Teardown", "evidence": ["FIN or RST with no payload"],
                    "alternatives": []}
        probe = _zero_window_probe(run, packets, peer_acks)
        if probe is not None:
            return probe
        return {"label": "Control exchange", "evidence": ["No payload observed"],
                "alternatives": []}

    dominant = max(out_bytes, in_bytes)
    share = dominant / total if total else 0.0
    direction = "out" if out_bytes >= in_bytes else "in"
    bits_per_second = (total * 8 / span_s) if span_s > 0 else None
    retransmission_bytes = sum(p["length"] for p in payload if p.get("retrans"))
    retransmission_percent = (retransmission_bytes / total * 100) if total else 0.0
    rate_evidence = f"{total:,} payload bytes over {span_s:.1f}s"
    if bits_per_second is not None:
        rate_evidence += f" ({bits_per_second:,.0f} bit/s)"
    else:
        rate_evidence += " (rate unavailable: zero-duration observation)"
    retransmission_note = (
        f"Retransmissions present: {retransmission_bytes:,} of {total:,} captured "
        f"payload bytes ({retransmission_percent:.1f}%) may be repeats"
        if retransmission_bytes else None
    )
    metrics = {
        "payload_bytes": total,
        "bits_per_second": round(bits_per_second, 3) if bits_per_second is not None else None,
        "retransmission_bytes": retransmission_bytes,
        "retransmission_percent": round(retransmission_percent, 3),
    }

    if total >= THRESHOLDS["bulk_min_bytes"] and share >= THRESHOLDS["bulk_min_share"]:
        alternatives = []
        if any(p.get("tls_record") for p in packets):
            alternatives.append("Encrypted traffic; a bulk shape does not prove a file transfer")
        if retransmission_note:
            alternatives.append(retransmission_note)
        return {"label": "Bulk transfer", "direction": direction,
                "evidence": [rate_evidence, f"{share:.0%} in one direction",
                             f"{len(payload)} payload records"],
                "alternatives": alternatives, **metrics}

    if total <= THRESHOLDS["small_max_bytes"]:
        turns = sum(1 for a, b in zip(packets, packets[1:])
                    if a["direction"] != b["direction"])
        return {"label": "Small exchange",
                "evidence": [rate_evidence, f"{turns} direction changes"],
                "alternatives": [retransmission_note] if retransmission_note else [],
                **metrics}

    return {"label": "Payload exchange",
            "evidence": [rate_evidence],
            "alternatives": [retransmission_note] if retransmission_note else [],
            **metrics}


# A zero-window advertisement this long before a pause still explains it: the
# probes that keep the window closed arrive at the probe interval, and the last
# one can precede the observed silence by up to that interval.
STALL_LOOKBACK_MS = 1_000.0


def _window_stall(ordered, pause_start, pause_end):
    """Zero-window advertisements explaining a pause, or None.

    Only explicitly advertised zeros count. An absent window field means the
    capture could not see it, which is not evidence of a stall.
    """
    if pause_end <= pause_start:
        return None
    hits = [p for p in ordered
            if p.get("window_present") and p.get("window") == 0
            and pause_start - STALL_LOOKBACK_MS <= p.get("time_ms", -1) <= pause_end]
    if not hits:
        return None
    advertiser = hits[0].get("src", "unknown")
    return {
        "advertisements": len(hits),
        "advertiser": advertiser,
        "frames": [p["frame"] for p in hits[:20]],
        "first_ms": round(hits[0].get("time_ms", 0.0), 3),
        "last_ms": round(hits[-1].get("time_ms", 0.0), 3),
    }


def _peer_ack_index(ordered):
    """Ack each endpoint sent for each peer direction, in time order.

    Keyed by the sender of the ack: (src, sport, dst, dport) -> [(time_ms, ack)].
    Callers take the latest entry at or before the packet being tested. Using
    the capture-wide final ack would compare a probe against a sequence value
    the peer had not yet issued.
    """
    index = {}
    for packet in ordered:
        if not packet.get("ack_flag"):
            continue
        key = (packet.get("src"), packet.get("sport"),
               packet.get("dst"), packet.get("dport"))
        index.setdefault(key, []).append((packet.get("time_ms"), packet.get("ack")))
    return index


def _ack_at(index, key, time_ms):
    """Latest ack sent for ``key`` at or before ``time_ms``."""
    entries = index.get(key)
    if not entries:
        return None
    latest = None
    for when, ack in entries:
        if when is None or time_ms is None or when <= time_ms:
            latest = ack
    return latest


def _fmt_ms(value):
    """Human-readable duration for evidence text."""
    if value is None:
        return "an unbounded time"
    if value >= 1000.0:
        return f"{value / 1000.0:.1f}s"
    return f"{value:.0f}ms"


def _matching_episode(episodes, pause_start, pause_end, advertiser):
    """The episode a pause falls inside, or None.

    An episode runs from the first zero-window advertisement until the window
    reopens. A pause overlapping that span is part of the same stall even when
    the pause is a shorter sub-interval of it.
    """
    if not episodes:
        return None
    for episode in episodes:
        start = episode.get("start_ms")
        if start is None:
            continue
        duration = episode.get("duration_ms")
        end = (start + duration) if duration is not None else None
        if pause_end < start:
            continue
        if end is not None and pause_start > end:
            continue
        return episode
    return None


def stream_phases(packets, window_episodes=None):
    """Segment a stream into phases with bounds, evidence and frame references."""
    ordered = sorted(packets, key=lambda p: p["time_ms"])
    if not ordered:
        return {"phases": [], "thresholds": THRESHOLDS, "limitation": None}

    phases = []
    runs = _activity(ordered)
    # Most recent ack sent by each endpoint for the peer's direction. A window
    # probe is recognised by comparing its seq against this, not against the ack
    # in the same packet, which belongs to the opposite stream.
    peer_acks = _peer_ack_index(ordered)
    for index, run in enumerate(runs):
        if index > 0:
            run["lookback"] = runs[index - 1]["packets"][-4:]

    # A pause is the quiet interval between runs, reported explicitly rather
    # than hidden: the spec distinguishes a payload pause from a teardown.
    for index, run in enumerate(runs):
        verdict = _classify_run(run, peer_acks)
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
        for key in ("payload_bytes", "bits_per_second", "retransmission_bytes",
                    "retransmission_percent"):
            if key in verdict:
                phase[key] = verdict[key]
        phases.append(phase)

        if index + 1 < len(runs):
            gap_s = (runs[index + 1]["start"] - run["end"]) / 1000.0
            pause_start = run["end"]
            pause_end = runs[index + 1]["start"]
            evidence = [f"{gap_s:.1f}s with no captured activity"]
            alternatives = ["An application pause and a network gap look the "
                            "same at one capture point"]
            pause = {
                "index": len(phases),
                "label": "Payload pause" if gap_s < 30 else "Idle",
                "start_ms": round(pause_start, 3),
                "end_ms": round(pause_end, 3),
                "duration_ms": round((pause_end - pause_start), 3),
                "packets": 0,
                "frames": [],
                "evidence": evidence,
                "alternatives": alternatives,
            }
            # A pause bounded by a closed receiver window is not ambiguous: the
            # silence is flow control, which is directly observable. Report it
            # rather than leaving the application-versus-network hedge standing.
            stall = _window_stall(ordered, pause_start, pause_end)
            if stall:
                # Point at the episode this pause belongs to. A single stall can
                # span several pauses, so without the reference the phase table
                # would report four stalls where the episode list reports one.
                episode = _matching_episode(window_episodes, pause_start, pause_end,
                                           stall["advertiser"])
                if episode is not None:
                    stall["episode_index"] = episode["index"]
                    stall["episode_duration_ms"] = episode["duration_ms"]
                    stall["episode_probes"] = episode["probes"]
                    stall["episode_probe_gaps_ms"] = episode.get("probe_gaps_ms", [])
                    stall["part_of_larger_stall"] = (
                        episode["duration_ms"] is not None
                        and episode["duration_ms"] > pause["duration_ms"])
                pause["label"] = "Receiver-window stall"
                evidence.append(
                    f"{stall['advertisements']} zero-window advertisement(s) in or "
                    f"immediately before this pause, from {stall['advertiser']}")
                if episode is not None:
                    evidence.append(
                        f"Part of receiver-window stall #{episode['index']}: "
                        f"{episode['probes']} probe(s) over "
                        f"{_fmt_ms(episode['duration_ms'])}")
                alternatives = [
                    "Flow control is receiver-driven: the receiver had no buffer "
                    "space. This is not congestion and not a network gap",
                ]
                pause["alternatives"] = alternatives
                pause["window_stall"] = stall
            phases.append(pause)

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
