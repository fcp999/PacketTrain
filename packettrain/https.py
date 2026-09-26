"""Visible TLS phases and encrypted-traffic behaviour."""
import re

from .behavior import classify_stream


def analyze_https(packets, client):
    """Describe visible TLS phases and classify encrypted traffic behavior.

    TLS 1.3 encrypted handshake records look like application data on the wire.
    We therefore never call a ciphertext record an HTTP request or response.
    """
    ordered = sorted(packets, key=lambda p: p["ts"])
    client_packets = [p for p in ordered if (p["src"], p["sport"]) == client]
    server_packets = [p for p in ordered if (p["src"], p["sport"]) != client]
    handshake_types = lambda p: set(re.split(r"[,;]", p.get("tls_handshake", "")))
    hello = next((p for p in client_packets if "1" in handshake_types(p)), None)
    server_hello = next((p for p in server_packets if "2" in handshake_types(p)
                         and (hello is None or p["ts"] >= hello["ts"])), None)
    if not hello and not server_hello:
        # No handshake was dissected. Say so when TLS records are present, so a
        # sliced or undissected handshake cannot read as "this stream has no TLS".
        if any(p.get("tls_record") or p.get("tls_version") for p in ordered):
            return {"detected": False, "handshake_decoded": False,
                    "sni": None, "alpn_offered": None, "behavior": None,
                    "limitation": ("TLS records are present but no handshake was decoded, "
                                   "so SNI, ALPN and encrypted behaviour are unavailable. "
                                   "A sliced capture (-s 0 needed) or an undissected "
                                   "handshake can cause this.")}
        return None

    def elapsed(later, earlier):
        return round((later["ts"] - earlier["ts"]) * 1000, 3) if later and earlier else None

    # Explicit 23 is the TLS outer application_data record. For TLS 1.3 it
    # also carries encrypted handshake messages; this is a phase boundary only.
    encrypted = [p for p in ordered if "23" in re.split(r"[,;]", p.get("tls_record", ""))]
    # Membership by frame number: a list search here is quadratic in packet count.
    server_frames = {p["frame"] for p in server_packets}
    client_frames = {p["frame"] for p in client_packets}
    first_server_cipher = next((p for p in encrypted if p["frame"] in server_frames and
                                (server_hello is None or p["ts"] >= server_hello["ts"])), None)
    first_client_cipher = next((p for p in encrypted if p["frame"] in client_frames and
                                (server_hello is None or p["ts"] >= server_hello["ts"])), None)
    sni = next((p["tls_sni"] for p in client_packets if p.get("tls_sni")), None)
    alpn = next((p["tls_alpn"] for p in client_packets if p.get("tls_alpn")), None)

    # Guard: a TLS-bearing stream whose records the decoder did not identify
    # must not be classified. Handshake, ChangeCipherSpec and undecoded
    # ciphertext all look like one-directional payload, which would otherwise
    # produce a confident "bulk upload/download" label from key material.
    decoded_records = sum(1 for p in ordered if p.get("tls_record"))
    undecoded_note = None
    if decoded_records == 0:
        undecoded_note = ("TLS records present but the decoder identified no record types, "
                          "so no encrypted traffic shape can be classified.")
        behavior = {"label": "Undetermined encrypted traffic", "confidence": "unknown",
                    "evidence": [f"{len(ordered)} records with no decoded TLS record type",
                                 "Decoded record types unavailable; handshake bytes are not payload"],
                    "metrics": {"decoded_records": 0},
                    "scope": "Traffic behavior not established for this stream."}
    elif not encrypted:
        undecoded_note = ("No application-data (type 23) records were identified, so the "
                          "stream carries no classifiable encrypted payload.")
        behavior = {"label": "Handshake / control only", "confidence": "moderate",
                    "evidence": [f"{decoded_records} decoded TLS records, none application-data",
                                 "No encrypted payload records to classify"],
                    "metrics": {"decoded_records": decoded_records, "application_data_records": 0},
                    "scope": "Traffic behavior not established; no encrypted payload observed."}
    else:
        # Drop visible handshake packets and the first encrypted flights on both
        # sides. This is deliberately approximate; coalesced records remain opaque.
        excluded = {p["frame"] for p in ordered if p.get("tls_handshake")}
        excluded.update(p["frame"] for p in (first_client_cipher, first_server_cipher) if p)
        traffic = [p for p in ordered if p["frame"] not in excluded]
        behavior = classify_stream(traffic, client)

    result = {
        "detected": True, "sni": sni, "alpn_offered": alpn,
        "client_hello_frame": hello["frame"] if hello else None,
        "server_hello_frame": server_hello["frame"] if server_hello else None,
        "client_hello_to_server_hello_ms": elapsed(server_hello, hello),
        # Usually ~0-1 ms: the ServerHello and first ciphertext record share a
        # flight, so this is an ordering marker, not a key-exchange duration.
        "server_hello_to_first_record_ms": elapsed(first_server_cipher, server_hello),
        "server_hello_to_first_server_cipher_ms": elapsed(first_server_cipher, server_hello),
        "first_client_cipher_frame": first_client_cipher["frame"] if first_client_cipher else None,
        "first_server_cipher_frame": first_server_cipher["frame"] if first_server_cipher else None,
        "decoded_records": decoded_records,
        "undecoded_records": decoded_records == 0,
        "behavior": behavior,
        "limitation": "Ciphertext cannot identify an HTTP method, status, URL, file, or exact request boundary. TLS 1.3 encrypts most handshake messages; outer type 23 can still be handshake data. Timings at one capture point include path delay.",
    }
    if undecoded_note:
        result["limitation"] = undecoded_note + " " + result["limitation"]
    return result


