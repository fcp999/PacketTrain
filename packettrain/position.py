"""Capture-position evidence: where the capture point sits relative to endpoints.

Reports observations separately from the inference. The three-way handshake
gives two intervals; TTL gives a proximity hint. Neither alone proves location,
and conflicting evidence yields unknown rather than a guess.
"""

# Common initial TTL / hop-limit values. An observed value below one of these
# suggests routed hops, not proximity.
INITIAL_TTL_CANDIDATES = (64, 128, 255)


def _ttl_observation(value):
    """Describe one TTL/hop-limit observation without claiming location."""
    if not value:
        return None
    for initial in INITIAL_TTL_CANDIDATES:
        if value == initial:
            return {"ttl": value, "hint": "at-initial", "initial_ttl": initial,
                    "note": f"TTL {value} equals a common initial value"}
        if 0 < value < initial and initial - value <= 4:
            return {"ttl": value, "hint": "few-hops", "initial_ttl": initial,
                    "hops": initial - value,
                    "note": f"TTL {value} suggests {initial - value} hop(s) from an initial {initial}"}
    return {"ttl": value, "hint": "indeterminate", "initial_ttl": None,
            "note": f"TTL {value} does not match a common initial value"}


def position_evidence(packets, client, legs):
    """Build the evidence set for a capture-position inference.

    `legs` is (leg1, leg2) in milliseconds: SYN->SYN-ACK and SYN-ACK->ACK.
    Returns observations, the inferred side, a confidence and the conflicts
    that limited it. Callers should show the observations even when the
    inference is unknown.
    """
    leg1, leg2 = legs
    observations = []
    conflicts = []

    # A sliced capture may contain no usable handshake at all.
    have_handshake = leg1 is not None and leg2 is not None
    if have_handshake:
        observations.append({
            "kind": "handshake-intervals",
            "leg_syn_to_synack_ms": round(leg1, 3),
            "leg_synack_to_ack_ms": round(leg2, 3),
            "note": ("The larger interval is the leg that crossed the network; "
                     "the smaller one was observed near its endpoint."),
        })
    else:
        observations.append({
            "kind": "handshake-intervals", "leg_syn_to_synack_ms": None,
            "leg_synack_to_ack_ms": None,
            "note": "Handshake legs unavailable; the capture may be sliced or mid-stream.",
        })

    # Client-side TTL from the first packet the client sent; server-side from the
    # first the server sent. Comparing the two is more informative than either.
    client_ttl = next((p["ttl"] for p in packets
                       if (p["src"], p["sport"]) == client and p["ttl"]), None)
    server_ttl = next((p["ttl"] for p in packets
                       if (p["src"], p["sport"]) != client and p["ttl"]), None)
    for name, value in (("client", client_ttl), ("server", server_ttl)):
        obs = _ttl_observation(value)
        if obs:
            obs["kind"] = "ttl"
            obs["side"] = name
            observations.append(obs)

    # Interval inference, only from a usable handshake.
    interval_side = "unknown"
    if have_handshake and min(leg1, leg2) >= 0:
        if leg1 >= 3 * max(leg2, 0.001):
            interval_side = "client"
        elif leg2 >= 3 * max(leg1, 0.001):
            interval_side = "server"

    # TTL is the primary position factor. Compare estimated hop distance when
    # both endpoint TTLs are present; handshake asymmetry is supporting evidence
    # because it also includes endpoint response delay.
    ttl_side = "unknown"
    client_obs = _ttl_observation(client_ttl)
    server_obs = _ttl_observation(server_ttl)

    def ttl_hops(obs):
        if not obs:
            return None
        if obs["hint"] == "at-initial":
            return 0
        if obs["hint"] == "few-hops":
            return obs.get("hops")
        return None

    if client_obs and server_obs:
        client_hops, server_hops = ttl_hops(client_obs), ttl_hops(server_obs)
        if client_hops is not None and server_hops is not None and client_hops != server_hops:
            ttl_side = "client" if client_hops < server_hops else "server"
        elif client_hops is not None and server_hops is None:
            ttl_side = "client"
        elif server_hops is not None and client_hops is None:
            ttl_side = "server"
        elif client_hops is not None and client_hops == server_hops:
            observations.append({
                "kind": "ttl-pair",
                "note": (f"Both endpoints have the same inferred TTL distance "
                         f"(client {client_ttl}, server {server_ttl}); TTL does not "
                         "distinguish the nearer endpoint."),
            })

    if ttl_side != "unknown":
        side = ttl_side
        if interval_side == ttl_side:
            confidence = "high"
        elif interval_side != "unknown":
            confidence = "moderate"
            conflicts.append(
                f"TTL (primary) suggests near {ttl_side}; handshake timing "
                f"(supporting) suggests near {interval_side}")
        else:
            confidence = "moderate"
        primary_factor = "ttl"
    elif interval_side != "unknown":
        side, confidence = interval_side, "moderate"
        primary_factor = "handshake-timing"
    else:
        side, confidence = "unknown", "low"
        primary_factor = "none"

    if side == "unknown" and not conflicts:
        conflicts.append("No handshake timing or TTL evidence established a position")

    return {"side": side, "confidence": confidence, "primary_factor": primary_factor,
            "evidence": observations, "conflicts": conflicts,
            "limitation": ("Position is inferred, not measured. TTL is the primary factor, "
                           "but remains a proximity hint: initial values are assumed and "
                           "a proxy, NAT or non-standard stack defeats it. Handshake "
                           "timing is supporting evidence and includes host response delay.")}


def infer_capture_side(packets, client, legs):
    """Backwards-compatible side string."""
    return position_evidence(packets, client, legs)["side"]
