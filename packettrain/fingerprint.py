"""Passive endpoint fingerprinting from SYN / SYN-ACK evidence.

Estimates a stack family per endpoint from the options a host offers and the
shape of its initial window. This is passive: no probing, nothing is sent.

A signature match is evidence, not identity. A proxy, a middlebox, MSS clamping
or a non-standard stack can all defeat it, so observed fields are always
reported alongside any label, and no match is stated as certainty.
"""

# Signature database, keyed by the offered-option pattern. Versioned so a result
# can be reproduced against a stated rule set.
SIGNATURES = {
    "version": "2026-09-26.1",
    "entries": [
        {"family": "Linux 4.x/5.x/6.x", "option_order": "mss,sack,ts,nop,ws",
         "window": 64240, "mss": 1460, "wscale": 7,
         "note": "Common Linux default with timestamps and window scaling."},
        {"family": "Linux (timestamps disabled)", "option_order": "mss,sack,nop,ws",
         "window": 64240, "mss": 1460, "wscale": 7,
         "note": "Linux default with tcp_timestamps off."},
        {"family": "Windows 10/11", "option_order": "mss,nop,ws,nop,nop,sack",
         "window": 65535, "mss": 1460, "wscale": 8,
         "note": "Windows commonly omits timestamps on SYN."},
        {"family": "macOS / iOS", "option_order": "mss,nop,ws,nop,nop,ts,sack",
         "window": 65535, "mss": 1460, "wscale": 6,
         "note": "Apple stacks place timestamps after window scale."},
        {"family": "BSD", "option_order": "mss,nop,ws,sack,ts",
         "window": 65535, "mss": 1460, "wscale": 6,
         "note": "FreeBSD places SACK before timestamps."},
        {"family": "Network appliance / middlebox", "option_order": "mss,sack,ts",
         "window": 8192, "mss": 8960, "wscale": None,
         "note": "Unusually large MSS with no window scale suggests a middlebox."},
    ],
}

# Option kind numbers, for reading raw option bytes.
OPTION_NAMES = {0: "eol", 1: "nop", 2: "mss", 3: "ws", 4: "sack", 5: "sackperm",
                8: "ts"}


def parse_options(raw):
    """Decode raw option bytes into an ordered list of names.

    Order matters for a signature, so this preserves it and treats padding as
    nop. Unknown kinds are reported by number rather than dropped, so an
    unmatched signature still shows what was offered.
    """
    if not raw:
        return []
    data = bytes.fromhex(raw)
    names = []
    index = 0
    while index < len(data):
        kind = data[index]
        if kind == 0:
            # End-of-list padding terminates the options; it is not an option.
            break
        if kind == 1:
            names.append("nop")
            index += 1
            continue
        if index + 1 >= len(data):
            break
        length = data[index + 1]
        if length < 2 or index + length > len(data):
            names.append(f"malformed_{kind}")
            break
        names.append(OPTION_NAMES.get(kind, f"kind{kind}"))
        index += length
    return names


def _offered_option_summary(option_names):
    """A signature-comparable option list: keep order and repeats."""
    return [name for name in option_names if name != "eol"]


def _match_signature(option_names, window, mss, wscale):
    """Find candidate families. Returns matches with their agreement level."""
    offered = _offered_option_summary(option_names)
    matches = []
    for entry in SIGNATURES["entries"]:
        expected = [part.strip() for part in entry["option_order"].split(",")]
        agrees = 0
        disagrees = []
        for field, actual, wanted in (
            ("options", offered, expected),
            ("window", window, entry["window"]),
            ("mss", mss, entry["mss"]),
            ("wscale", None if wscale is None or wscale < 0 else wscale,
             entry["wscale"]),
        ):
            if wanted is None:
                continue
            if actual == wanted:
                agrees += 1
            else:
                disagrees.append(field)
        if agrees:
            matches.append({"family": entry["family"], "agreement": agrees,
                            "differing_fields": disagrees, "note": entry["note"]})
    matches.sort(key=lambda m: (-m["agreement"], len(m["differing_fields"])))
    return matches


def fingerprint_endpoint(packets, client):
    """Describe the client and server stack evidence for one stream."""
    syn = next((p for p in packets
                if p["syn"] and not p["ack_flag"]
                and (p["src"], p["sport"]) == client), None)
    synack = next((p for p in packets
                   if p["syn"] and p["ack_flag"]
                   and (p["src"], p["sport"]) != client), None)

    result = {"signature_version": SIGNATURES["version"], "client": None,
              "server": None,
              "limitation": ("Passive estimate from SYN evidence only. A proxy, NAT, "
                             "MSS clamping or a non-standard stack can alter or hide "
                             "the real host. A match is not an identification, and "
                             "uptime is not inferred from timestamp values.")}

    for label, packet, role in (("client", syn, "initiator"), ("server", synack, "responder")):
        if not packet:
            result[label] = {"observed": False, "role": role,
                             "note": f"No {label} SYN captured; that endpoint's stack "
                                     f"cannot be estimated from this stream."}
            continue
        options = parse_options(packet.get("options_raw", ""))
        wscale = packet.get("wscale", -1)
        wscale = None if wscale < 0 else wscale
        entry = {
            "observed": True,
            "role": role,
            "frame": packet["frame"],
            "option_order": _offered_option_summary(options),
            "options_raw": packet.get("options_raw", ""),
            "mss": packet.get("mss"),
            "window": packet.get("window"),
            "wscale": wscale,
            "sack_permitted": packet.get("sack_perm"),
            "timestamps": packet.get("has_timestamp"),
            "ttl": packet.get("ttl"),
            "candidates": [],
            "note": None,
            # A SYN-ACK reflects options the client offered, so a responder
            # signature is weaker evidence than an initiator's.
            "evidence_strength": ("moderate" if label == "client"
                                  else "weak: a SYN-ACK is shaped by the client's offer"),
        }
        matches = _match_signature(options, packet.get("window"), packet.get("mss"), wscale)
        if matches and matches[0]["agreement"] >= 2:
            entry["candidates"] = matches[:3]
            entry["family"] = matches[0]["family"]
            entry["confidence"] = ("moderate" if matches[0]["agreement"] >= 3
                                   else "low")
        else:
            entry["family"] = None
            entry["confidence"] = "low"
            entry["note"] = ("Observed fields are reported, but no signature matched "
                             "closely enough to suggest a family.")
        result[label] = entry

    return result


def cross_connection_consistency(per_stream):
    """Summarise which families recur across related streams.

    A family seen once is weak; the same family across many connections from one
    address is stronger. A change across connections is a signal to investigate,
    not proof that the backend changed.
    """
    totals = {}
    for entry in per_stream:
        for side in ("client", "server"):
            data = entry.get(side) or {}
            family = data.get("family")
            if family:
                key = (side, family)
                totals[key] = totals.get(key, 0) + 1
    return {
        "counts": [{"side": side, "family": family, "connections": count}
                   for (side, family), count in sorted(totals.items())],
        "note": ("Repeated families across connections strengthen an estimate. A "
                 "family that changes from one connection to the next is evidence "
                 "to investigate, not proof the endpoint changed."),
    }
