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

    # TTL inference: the endpoint whose TTL sits at a common initial value is
    # the nearer one. This is a hint, never proof.
    ttl_side = "unknown"
    client_obs = _ttl_observation(client_ttl)
    server_obs = _ttl_observation(server_ttl)
    if client_obs and server_obs:
        client_at_initial = client_obs["hint"] == "at-initial"
        server_at_initial = server_obs["hint"] == "at-initial"
        if client_at_initial and not server_at_initial:
            ttl_side = "client"
        elif server_at_initial and not client_at_initial:
            ttl_side = "server"
        elif client_at_initial and server_at_initial:
            # Both match a common initial value. The nearer endpoint is still
            # unidentified, but this is a real observation worth surfacing: a
            # matched pair usually means the capture sits near both stacks or
            # the initial values are not what we assumed.
            observations.append({
                "kind": "ttl-pair",
                "note": (f"Both endpoints show a common initial TTL "
                         f"(client {client_ttl}, server {server_ttl}); TTL does not "
                         "distinguish the nearer endpoint."),
            })

    if interval_side != "unknown" and ttl_side != "unknown" and interval_side != ttl_side:
        conflicts.append(
            f"Handshake timing suggests near {interval_side} but TTL suggests near {ttl_side}")
        side, confidence = "unknown", "low"
    elif interval_side != "unknown":
        side = interval_side
        confidence = "moderate" if ttl_side == "unknown" else "high"
    elif ttl_side != "unknown":
        side, confidence = ttl_side, "low"
    else:
        side, confidence = "unknown", "low"

    if side == "unknown" and not conflicts:
        conflicts.append("No handshake timing or TTL evidence established a position")

    return {"side": side, "confidence": confidence, "evidence": observations,
            "conflicts": conflicts,
            "limitation": ("Position is inferred, not measured. TTL is a proximity hint "
                           "only: initial values are assumed and a proxy, NAT or a "
                           "non-standard stack defeats it. Timings include host "
                           "response delay at the far endpoint.")}


def infer_capture_side(packets, client, legs):
    """Backwards-compatible side string."""
    return position_evidence(packets, client, legs)["side"]
