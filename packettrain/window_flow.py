"""Receiver-window analysis: zero-window episodes, duration, recovery.

A zero-window advertisement is one packet. What matters for diagnosis is the
*episode* it belongs to: how long the receiver kept the window closed, whether
it recovered on its own or only after the sender probed, and how much of the
flow's life was spent stalled.

Two things this deliberately refuses to do:

* Treat an absent window field as zero. A sliced capture or a non-TCP row has
  an empty field, and reading that as a stall invents receiver problems.
* Treat a SYN's window as a flow-control signal. The SYN advertises receive
  buffer size before any data flows, and its value is unscaled; a zero there is
  a broken endpoint, not a stall.
"""

from .accounting_tcp import window_scale

SEQ_SPACE = 1 << 32

# An episode shorter than this is one round trip of ordinary window refresh,
# not a stall worth reporting.
MIN_STALL_MS = 10.0

# A window that never reopens is still reported when the capture ends during the
# stall, but flagged as unresolved rather than assumed persistent.
UNRESOLVED_NOTE = "capture ended while the window was still closed"

# Zero-window advertisements arriving back-to-back within this gap are treated as
# one episode: window probes and duplicate advertisements do not each start a
# new stall.
EPISODE_COALESCE_MS = 1000.0


def _time_ms(packet, origin):
    ts = packet.get("ts")
    if ts is not None and origin is not None:
        return round((ts - origin) * 1000.0, 3)
    return packet.get("time_ms")


def _direction_of(packet):
    """Endpoint whose *receive* window this packet advertises.

    A packet's window field describes the receive buffer of the endpoint that
    sent it. So a client-to-server packet advertises the client's window, and a
    stall seen there constrains the server's sending.

    Directions arrive either as out/in (stream_detail) or client/server. Both are
    normalised here: "out" is the client's side, "in" is the server's.
    """
    direction = packet.get("direction")
    if direction in ("out", "client"):
        return "client"
    if direction in ("in", "server"):
        return "server"
    return None


def _is_stall(packet):
    """True only when the window was explicitly advertised as zero."""
    return bool(packet.get("window_present")) and packet.get("window") == 0


def _episodes(advertisements, origin):
    """Group zero-window advertisements into contiguous episodes."""
    episodes = []
    current = None
    for packet in advertisements:
        time_ms = _time_ms(packet, origin)
        if time_ms is None:
            continue
        if current is None or time_ms - current["last_probe_ms"] > EPISODE_COALESCE_MS:
            if current is not None:
                episodes.append(current)
            current = {
                "start_ms": time_ms,
                "last_probe_ms": time_ms,
                "probes": 0,
                "frames": [],
            }
        current["last_probe_ms"] = time_ms
        current["probes"] += 1
        if len(current["frames"]) < 20:
            current["frames"].append(packet.get("frame"))
    if current is not None:
        episodes.append(current)
    return episodes


def receiver_window_analysis(group):
    """Zero-window episodes with duration, recovery and persistence.

    ``group`` is one stream's packet list carrying ``direction``, ``window`` and
    ``window_present``.
    """
    origins = [p["ts"] for p in group if p.get("ts") is not None]
    origin = min(origins) if origins else None

    stalls = [p for p in group if _is_stall(p)]
    # A SYN's window is advertised before data flows and is never scaled; a zero
    # there says the endpoint opened with no buffer, which is a configuration
    # problem rather than flow control.
    syn_zero = [p for p in stalls if p.get("syn")]
    stalls = [p for p in stalls if not p.get("syn")]

    if not stalls:
        return {
            "basis": "explicitly advertised zero window on non-SYN segments",
            "episodes": [],
            "episode_count": 0,
            "total_stalled_ms": 0.0,
            "stalled_fraction": 0.0,
            "syn_zero_window": len(syn_zero),
            "persistent": False,
            "does_not_prove": (
                "Flow control is receiver-driven. A closed window says the receiver "
                "had no room, not that the network was congested."),
        }

    by_direction = {}
    for packet in stalls:
        by_direction.setdefault(_direction_of(packet), []).append(packet)

    end_times = [p["ts"] for p in group if p.get("ts") is not None]
    capture_end_ms = (round((max(end_times) - origin) * 1000.0, 3)
                      if end_times and origin is not None else None)

    episodes = []
    for direction, packets in by_direction.items():
        for episode in _episodes(packets, origin):
            # Recovery is the first advertisement from the same endpoint with a
            # non-zero window after the last zero.
            recovered_at = None
            for candidate in group:
                if _direction_of(candidate) != direction:
                    continue
                candidate_ms = _time_ms(candidate, origin)
                if candidate_ms is None or candidate_ms <= episode["last_probe_ms"]:
                    continue
                if not candidate.get("window_present"):
                    continue
                if candidate.get("window", 0) > 0:
                    recovered_at = candidate_ms
                    break

            if recovered_at is None:
                duration_ms = (capture_end_ms - episode["start_ms"]
                               if capture_end_ms is not None else None)
                recovered = False
                note = UNRESOLVED_NOTE
            else:
                duration_ms = recovered_at - episode["start_ms"]
                recovered = True
                note = None

            episodes.append({
                "direction": direction,
                "constrained_direction": ("server" if direction == "client" else "client"),
                "start_ms": episode["start_ms"],
                "duration_ms": (round(duration_ms, 3)
                                if duration_ms is not None else None),
                "probes": episode["probes"],
                "recovered": recovered,
                "note": note,
                "frames": episode["frames"],
            })

    episodes = [e for e in episodes
                if e["duration_ms"] is None or e["duration_ms"] >= MIN_STALL_MS]
    episodes.sort(key=lambda e: e["start_ms"])

    stalled_ms = sum(e["duration_ms"] for e in episodes if e["duration_ms"] is not None)
    flow_ms = capture_end_ms if capture_end_ms else None
    unresolved = [e for e in episodes if not e["recovered"]]

    return {
        "basis": "explicitly advertised zero window on non-SYN segments",
        "episodes": episodes,
        "episode_count": len(episodes),
        "total_stalled_ms": round(stalled_ms, 3),
        "stalled_fraction": (round(stalled_ms / flow_ms, 4)
                             if flow_ms and flow_ms > 0 else None),
        "syn_zero_window": len(syn_zero),
        # Persistence means the receiver never reopened during a flow that
        # otherwise continued, so a stall that outlives the capture is reported
        # as unresolved instead of being called persistent.
        "persistent": bool(unresolved) and capture_end_ms is None,
        "unresolved": len(unresolved),
        "window_scale": {"client": window_scale(group, True),
                         "server": window_scale(group, False)},
        "does_not_prove": (
            "Flow control is receiver-driven. A closed window says the receiver had "
            "no room, not that the network was congested. Duration is bounded by the "
            "capture; an episode still open at the last frame is not proven persistent."),
    }
