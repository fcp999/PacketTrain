import pytest

import app
from packettrain import config as ptconfig

packettrain = app


def row(frame, ts, stream, seq, length, flags=None):
    flags = flags or {}
    d = {k: "" for k in packettrain.FIELDS}
    d.update({"frame.number": str(frame), "frame.time_epoch": str(ts),
              "ip.src": "192.0.2.1", "ip.dst": "198.51.100.2",
              "tcp.srcport": "50000", "tcp.dstport": "443",
              "tcp.stream": str(stream), "tcp.seq_raw": str(seq),
              "tcp.len": str(length), "frame.len": "1514"})
    d.update(flags)
    return "\t".join(d[k] for k in packettrain.FIELDS)


def test_parse_flags_and_timing():
    lines = [row(1, 100.0, 7, 100, 0, {"tcp.flags.syn": "1"}),
             row(2, 100.2, 7, 101, 1460, {"tcp.flags.push": "1",
                 "tcp.analysis.fast_retransmission": "1", "tcp.options.sack_le": "100"})]
    packets = packettrain.parse_rows(lines)
    assert len(packets) == 2
    assert packets[1]["psh"] and packets[1]["retrans"] and packets[1]["sack"]
    detail = packettrain.stream_detail(packets, 7)
    assert detail["packets"][1]["time_ms"] == pytest.approx(200)


def test_https_handshake_timing_and_encrypted_shape():
    lines = [
        row(1, 10.0, 1, 1, 0, {"tcp.flags.syn": "1"}),
        row(2, 10.10, 1, 2, 300, {"tls.handshake.type": "1", "tls.record.content_type": "22",
                                   "tls.handshake.extensions_server_name": "example.test",
                                   "tls.handshake.extensions_alpn_str": "h2"}),
        row(3, 10.35, 1, 3, 120, {"tls.handshake.type": "2", "tls.record.content_type": "22"}),
        row(4, 10.36, 1, 4, 900, {"tls.record.content_type": "23"}),
        row(5, 10.50, 1, 5, 80, {"tls.record.content_type": "23"}),
        row(6, 10.75, 1, 6, 600, {"tls.record.content_type": "23"}),
    ]
    packets = packettrain.parse_rows(lines)
    for p in (packets[2], packets[3], packets[5]):
        p.update(src="198.51.100.2", dst="192.0.2.1", sport=443, dport=50000)
    tls = packettrain.analyze_https(packets, ("192.0.2.1", 50000))
    assert tls["client_hello_to_server_hello_ms"] == pytest.approx(250)
    assert tls["server_hello_to_first_server_cipher_ms"] == pytest.approx(10)
    assert tls["sni"] == "example.test" and tls["alpn_offered"] == "h2"
    assert tls["behavior"]["metrics"]["server_bytes"] == 600
    assert tls["behavior"]["metrics"]["client_bytes"] == 0
    assert packettrain.stream_detail(packets, 1)["https"]["detected"]


def test_https_needs_visible_hello():
    packets = packettrain.parse_rows([row(1, 0, 1, 1, 120)])
    assert packettrain.analyze_https(packets, ("192.0.2.1", 50000)) is None


def test_files_stay_inside_mount(tmp_path, monkeypatch):
    monkeypatch.setattr(ptconfig, "PCAP_DIR", tmp_path)
    (tmp_path / "good.pcap").write_bytes(b"capture")
    (tmp_path / "link.pcap").symlink_to(tmp_path / "good.pcap")
    client = packettrain.app.test_client()
    assert [x["name"] for x in client.get("/api/files").json["files"]] == ["good.pcap"]
    assert client.get("/api/streams?file=../good.pcap").status_code == 400
    assert client.get("/api/streams?file=link.pcap").status_code == 404


def test_stream_endpoints_use_tshark_fields(tmp_path, monkeypatch):
    monkeypatch.setattr(ptconfig, "PCAP_DIR", tmp_path)
    (tmp_path / "sample.pcap").write_bytes(b"sample")
    lines = [row(1, 100.0, 3, 1, 0, {"tcp.flags.syn": "1"}),
             row(2, 100.2, 3, 2, 1460, {"tcp.flags.push": "1"})]

    class Completed:
        returncode = 0
        stdout = "\n".join(lines) + "\n"
        stderr = ""

    def fake_run(command, **kwargs):
        assert command[:4] == ["tshark", "-n", "-r", str(tmp_path / "sample.pcap")]
        assert kwargs["check"] is False
        return Completed()

    monkeypatch.setattr(packettrain.subprocess, "run", fake_run)
    client = packettrain.app.test_client()
    streams = client.get("/api/streams?file=sample.pcap").json["streams"]
    assert len(streams) == 1 and streams[0]["id"] == 3
    flow = client.get("/api/flow?file=sample.pcap&stream=3").json
    assert flow["packets"][1]["time_ms"] == pytest.approx(200)
    assert flow["packets"][1]["psh"] is True


@pytest.mark.parametrize("synack_time,ack_time,expected_side,expected_rtt", [
    (100.100, 100.101, "client", 100),
    (100.001, 100.101, "server", 100),
    (100.050, 100.101, "unknown", None),
])
def test_handshake_capture_side(synack_time, ack_time, expected_side, expected_rtt):
    syn = packettrain.parse_rows([row(1, 100.0, 1, 1, 0, {"tcp.flags.syn": "1"})])[0]
    synack = syn.copy()
    synack.update({"frame": 2, "ts": synack_time, "src": "198.51.100.2",
                   "dst": "192.0.2.1", "sport": 443, "dport": 50000,
                   "syn": True, "ack_flag": True})
    third = syn.copy()
    third.update({"frame": 3, "ts": ack_time, "syn": False, "ack_flag": True})
    detail = packettrain.stream_detail([syn, synack, third], 1)
    assert detail["capture_side"] == expected_side
    if expected_rtt is not None:
        assert detail["rtt_ms"] == pytest.approx(expected_rtt, abs=0.01)


def test_jumbo_first_flight_uses_captured_lengths():
    packets = packettrain.parse_rows([
        row(1, 0.0, 4, 1, 0, {"tcp.flags.syn": "1", "tcp.options.mss_val": "8960"}),
        row(2, 0.001, 4, 2, 8948),
        row(3, 0.002, 4, 8950, 8948),
        row(4, 0.003, 4, 17898, 8948),
    ])
    ack = packets[-1].copy()
    ack.update({"frame": 5, "ts": 0.220, "src": "198.51.100.2", "sport": 443,
                "dst": "192.0.2.1", "dport": 50000, "length": 0, "ack_flag": True})
    detail = packettrain.stream_detail(packets + [ack], 4)
    assert detail["facts"]["mss"] == [8960]
    assert detail["facts"]["large_capture_records"] == 3
    assert detail["facts"]["first_flight_packets"] == 3
    assert detail["facts"]["first_flight_bytes"] == 26844


def test_raw_tcp_flag_mask_covers_handshake_and_teardown():
    packets = packettrain.parse_rows([
        row(1, 0.0, 1, 1, 0, {"tcp.flags": "0x0002"}),
        row(2, 0.1, 1, 2, 0, {"tcp.flags": "0x0012"}),
        row(3, 0.2, 1, 3, 0, {"tcp.flags": "0x0011"}),
        row(4, 0.3, 1, 4, 0, {"tcp.flags": "0x0014"}),
    ])
    assert [(p["syn"], p["ack_flag"], p["fin"], p["rst"]) for p in packets] == [
        (True, False, False, False), (True, True, False, False),
        (False, True, True, False), (False, True, False, True),
    ]


def test_boolean_text_fallback():
    p = packettrain.parse_rows([row(1, 0.0, 1, 1, 0,
        {"tcp.flags.syn": "True", "tcp.flags.ack": "False"})])[0]
    assert p["syn"] and not p["ack_flag"]


def traffic(ts, side, size, syn=False, ack=False):
    return {"ts": ts, "src": "192.0.2.1" if side == "client" else "198.51.100.2",
            "sport": 50000 if side == "client" else 443, "length": size,
            "syn": syn, "ack_flag": ack}


def classify(packets):
    return packettrain.classify_stream(packets, ("192.0.2.1", 50000))


def test_bulk_patterns_are_directional_and_explain_themselves():
    download = [traffic(0, "client", 96)] + [traffic(0.3 + i * .01, "server", 9000)
                                             for i in range(50)]
    result = classify(download)
    assert result["label"] == "Bulk download pattern"
    assert result["confidence"] == "high"
    assert result["metrics"]["server_bytes"] == 450000
    upload = [traffic(0, "server", 96)] + [traffic(0.3 + i * .01, "client", 9000)
                                            for i in range(50)]
    assert classify(upload)["label"] == "Bulk upload pattern"


def test_periodic_polling_and_interactive_exchange():
    polling = [p for i in range(5) for p in
               (traffic(i * 2.0, "client", 80), traffic(i * 2.0 + .1, "server", 100))]
    assert classify(polling)["label"] == "Periodic polling pattern"
    chat = [p for i in range(4) for p in
            (traffic(i * 3.0, "client", 60), traffic(i * 3.0 + 1.2, "server", 110))]
    assert classify(chat)["label"] == "Interactive exchange pattern"


def test_short_exchange_and_control_only():
    assert classify([traffic(0, "client", 75), traffic(.2, "server", 800)])["label"] == "Request/response pattern"
    assert classify([traffic(0, "client", 0, syn=True)])["label"] == "Connection attempt"


def test_tls_stream_without_decoded_records_is_not_classified():
    """A detected hello with no decoded record types must not be classified.

    analyze_https returns None when no hello is found, so the guard is only
    reachable once a handshake type has been extracted. That is the real risk
    case: the card renders, record types are missing, and the remaining
    one-directional bytes would otherwise be read as an encrypted traffic
    pattern.
    """
    lines = [
        row(1, 0.00, 1, 1, 0, {"tcp.flags.syn": "1"}),
        row(2, 0.02, 1, 2, 0, {"tcp.flags.syn": "1", "tcp.flags.ack": "1"}),
        row(3, 0.03, 1, 3, 0, {"tcp.flags.ack": "1"}),
        # Hello detected -> the early "no hello" return does not fire.
        row(4, 0.04, 1, 4, 300, {"tls.handshake.type": "1"}),
    ]
    # A large client->server flight with no decoded TLS record type at all.
    for i in range(40):
        lines.append(row(5 + i, 0.05 + i * 0.001, 1, 5 + i, 1400, {}))
    packets = packettrain.parse_rows(lines)
    tls = packettrain.analyze_https(packets, ("192.0.2.1", 50000))
    assert tls is not None
    assert tls["decoded_records"] == 0
    assert tls["undecoded_records"] is True
    assert tls["behavior"]["label"] == "Undetermined encrypted traffic"
    assert tls["behavior"]["confidence"] == "unknown"
    assert "no record types" in tls["limitation"].lower()


def test_tls_with_only_handshake_records_reports_no_payload():
    """Type 22/20 only means there is no encrypted payload to classify."""
    lines = [
        row(1, 0.00, 1, 1, 200, {"tls.handshake.type": "1", "tls.record.content_type": "22"}),
        row(2, 0.25, 1, 2, 90, {"tls.handshake.type": "2", "tls.record.content_type": "22"}),
    ]
    packets = packettrain.parse_rows(lines)
    for p in (packets[1],):
        p.update(src="198.51.100.2", dst="192.0.2.1", sport=443, dport=50000)
    tls = packettrain.analyze_https(packets, ("192.0.2.1", 50000))
    assert tls["behavior"]["label"] == "Handshake / control only"
    assert tls["behavior"]["metrics"]["application_data_records"] == 0


def test_tls_with_application_data_still_classifies_normally():
    """The guard must not suppress genuine encrypted-payload classification."""
    lines = [
        row(1, 0.00, 1, 1, 200, {"tls.handshake.type": "1", "tls.record.content_type": "22"}),
        row(2, 0.25, 1, 2, 90, {"tls.handshake.type": "2", "tls.record.content_type": "22"}),
    ]
    for i in range(50):
        lines.append(row(3 + i, 0.30 + i * 0.01, 1, 3 + i, 9000,
                         {"tls.record.content_type": "23"} if i else
                         {"tls.record.content_type": "23"}))
    packets = packettrain.parse_rows(lines)
    # frames 3,4,... are server-origin: override them
    for p in packets[2:]:
        p.update(src="198.51.100.2", dst="192.0.2.1", sport=443, dport=50000)
    tls = packettrain.analyze_https(packets, ("192.0.2.1", 50000))
    assert tls["behavior"]["label"] == "Bulk download pattern"
    assert tls["behavior"]["confidence"] == "high"
    assert tls["undecoded_records"] is False


def test_slicing_report_detects_truncated_capture():
    """A frame stored shorter than claimed is slicing (snaplen truncation).

    Mirrors the live ollama.com_001.pcap case, where frame 5 claimed tcp.len 120
    and stored only the 66-byte header, so the ClientHello's extensions (and its
    SNI) were never captured.
    """
    lines = [
        row(1, 0.0, 1, 1, 0, {}),
        row(2, 0.1, 1, 2, 1400, {}),
    ]
    packets = packettrain.parse_rows(lines)
    # Simulate slicing: claimed 186 on the wire, only 66 stored.
    packets[1]["frame_length"] = 186
    packets[1]["cap_length"] = 66
    packets[1]["sliced"] = True
    report = packettrain.slicing_report(packets)
    assert report["sliced"] is True
    assert report["sliced_frames"] == 1
    assert report["lost_bytes"] == 120
    assert report["total"] == 2
    assert "-s 0" in report["advice"]


def test_slicing_report_clean_capture_has_no_advice():
    packets = packettrain.parse_rows([row(1, 0.0, 1, 1, 100, {}), row(2, 0.1, 1, 2, 200, {})])
    for p in packets:
        p["cap_length"] = p["frame_length"]
        p["sliced"] = False
    report = packettrain.slicing_report(packets)
    assert report["sliced"] is False
    assert report["sliced_frames"] == 0
    assert report["lost_bytes"] == 0
    assert report["advice"] is None


def test_slicing_report_heavy_loss_flags_heavy_wording():
    packets = []
    for i in range(10):
        p = packettrain.parse_rows([row(i + 1, i * 0.1, 1, i + 1, 1400, {})])[0]
        p["frame_length"] = 186
        p["cap_length"] = 66
        p["sliced"] = True
        packets.append(p)
    report = packettrain.slicing_report(packets)
    assert report["sliced_fraction"] == 1.0
    assert "heavily sliced" in report["advice"]


def test_slicing_report_empty_is_safe():
    report = packettrain.slicing_report([])
    assert report["sliced"] is False
    assert report["total"] == 0
    assert report["advice"] is None


def test_flow_reports_slicing_for_stream():
    """A sliced stream must say so, instead of only hiding derived fields."""
    lines = [
        row(1, 0.0, 1, 1, 0, {"tcp.flags.syn": "1"}),
        row(2, 0.02, 1, 2, 0, {"tcp.flags.syn": "1", "tcp.flags.ack": "1"}),
        row(3, 0.03, 1, 3, 0, {"tcp.flags.ack": "1"}),
        row(4, 0.04, 1, 4, 1400, {}),
    ]
    packets = packettrain.parse_rows(lines)
    packets[3]["frame_length"] = 1466
    packets[3]["cap_length"] = 66
    packets[3]["sliced"] = True
    detail = packettrain.stream_detail(packets, 1)
    assert detail["slicing"]["sliced"] is True
    assert detail["slicing"]["lost_bytes"] == 1400


def test_https_self_reports_undecoded_handshake():
    """TLS records with no decoded handshake must say so, not read as 'no TLS'.

    A sliced capture contains the record type but loses the handshake body, so
    analyze_https previously returned None and the caller could not tell
    "no TLS here" from "TLS present but unreadable".
    """
    lines = [
        row(1, 0.0, 1, 1, 0, {"tcp.flags.syn": "1"}),
        row(2, 0.2, 1, 2, 1400, {"tls.record.content_type": "22"}),
    ]
    packets = packettrain.parse_rows(lines)
    tls = packettrain.analyze_https(packets, ("192.0.2.1", 50000))
    assert tls is not None
    assert tls["detected"] is False
    assert tls["handshake_decoded"] is False
    assert tls["behavior"] is None
    assert "no handshake was decoded" in tls["limitation"]


def test_https_absent_tls_still_returns_none():
    """A stream with no TLS indication at all keeps the old behaviour."""
    packets = packettrain.parse_rows([row(1, 0.0, 1, 1, 100, {"tcp.flags.ack": "1"})])
    assert packettrain.analyze_https(packets, ("192.0.2.1", 50000)) is None


def test_cipher_interval_has_both_names_and_agrees():
    lines = [
        row(1, 0.00, 1, 1, 300, {"tls.handshake.type": "1", "tls.record.content_type": "22"}),
        row(2, 0.25, 1, 2, 90, {"tls.handshake.type": "2", "tls.record.content_type": "22"}),
        row(3, 0.27, 1, 3, 900, {"tls.record.content_type": "23"}),
    ]
    packets = packettrain.parse_rows(lines)
    for p in packets[1:]:
        p.update(src="198.51.100.2", dst="192.0.2.1", sport=443, dport=50000)
    tls = packettrain.analyze_https(packets, ("192.0.2.1", 50000))
    assert tls["server_hello_to_first_record_ms"] == tls["server_hello_to_first_server_cipher_ms"]
    assert tls["server_hello_to_first_record_ms"] == pytest.approx(20, abs=1)


def test_handshake_decoded_is_reported_on_both_paths():
    """handshake_decoded must be explicit, not only present when false."""
    lines = [
        row(1, 0.00, 1, 1, 300, {"tls.handshake.type": "1", "tls.record.content_type": "22"}),
        row(2, 0.25, 1, 2, 90, {"tls.handshake.type": "2", "tls.record.content_type": "22"}),
    ]
    packets = packettrain.parse_rows(lines)
    for p in packets[1:]:
        p.update(src="198.51.100.2", dst="192.0.2.1", sport=443, dport=50000)
    tls = packettrain.analyze_https(packets, ("192.0.2.1", 50000))
    assert tls["detected"] is True
    assert tls["handshake_decoded"] is True


def test_position_evidence_reports_observations_and_side():
    """Position carries observations, not just a side string."""
    lines = [
        row(1, 0.000, 1, 1, 0, {"tcp.flags.syn": "1"}),
        row(2, 0.100, 1, 2, 0, {"tcp.flags.syn": "1", "tcp.flags.ack": "1"}),
        row(3, 0.101, 1, 3, 0, {"tcp.flags.ack": "1"}),
    ]
    packets = packettrain.parse_rows(lines)
    ev = packettrain.position_evidence(packets, ("192.0.2.1", 50000), (100.0, 1.0))
    assert ev["side"] == "client"
    assert ev["confidence"] in {"moderate", "high"}
    kinds = {o["kind"] for o in ev["evidence"]}
    assert "handshake-intervals" in kinds
    assert ev["evidence"][0]["leg_syn_to_synack_ms"] == 100.0


def test_position_evidence_ambiguous_ttl_keeps_interval_answer():
    """Two endpoints at a common initial TTL must not silently pick one.

    TTL cannot say which endpoint is nearer, so the observation is surfaced and
    the handshake interval decides - rather than TTL quietly winning.
    """
    lines = [
        row(1, 0.000, 1, 1, 0, {"tcp.flags.syn": "1", "ip.ttl": "64"}),
        row(2, 0.100, 1, 2, 0, {"tcp.flags.syn": "1", "tcp.flags.ack": "1", "ip.ttl": "128"}),
        row(3, 0.101, 1, 3, 0, {"tcp.flags.ack": "1"}),
    ]
    packets = packettrain.parse_rows(lines)
    # The SYN-ACK comes from the server, so it needs the server's address and
    # port; row() defaults to the client tuple.
    packets[1].update(src="198.51.100.2", dst="192.0.2.1", sport=443, dport=50000)
    ev = packettrain.position_evidence(packets, ("192.0.2.1", 50000), (100.0, 1.0))
    assert ev["side"] == "client"
    assert any(o["kind"] == "ttl-pair" for o in ev["evidence"])


def test_position_evidence_without_handshake_is_unknown_not_absent():
    """A sliced/mid-stream capture still returns observations and says why."""
    packets = packettrain.parse_rows([row(1, 0.0, 1, 1, 1400, {"ip.ttl": "64"})])
    ev = packettrain.position_evidence(packets, ("192.0.2.1", 50000), (None, None))
    assert ev["side"] == "unknown"
    assert ev["evidence"][0]["kind"] == "handshake-intervals"
    assert ev["evidence"][0]["leg_syn_to_synack_ms"] is None
    assert any("Handshake legs unavailable" in o.get("note", "") for o in ev["evidence"])


def test_flow_carries_position_object():
    lines = [
        row(1, 0.000, 1, 1, 0, {"tcp.flags.syn": "1", "ip.ttl": "64"}),
        row(2, 0.100, 1, 2, 0, {"tcp.flags.syn": "1", "tcp.flags.ack": "1", "ip.ttl": "64"}),
        row(3, 0.101, 1, 3, 0, {"tcp.flags.ack": "1"}),
    ]
    packets = packettrain.parse_rows(lines)
    packets[1].update(src="198.51.100.2", dst="192.0.2.1", sport=443, dport=50000)
    detail = packettrain.stream_detail(packets, 1)
    assert detail["capture_side"] == "client"
    assert detail["position"]["side"] == "client"
    assert isinstance(detail["position"]["evidence"], list)


def _stream(packets, ts=0.0):
    """Give packets a time_ms and direction, as stream_detail does.

    Call again after overriding a packet's src to refresh its direction.
    """
    for p in packets:
        p["time_ms"] = round((p["ts"] - packets[0]["ts"]) * 1000, 3)
        p["direction"] = "out" if p["src"] == "192.0.2.1" else "in"
    return packets


def test_unique_payload_dedupes_overlap():
    """Partial retransmission overlap must be counted once, not summed."""
    acc = packettrain.accounting_tcp
    # Two ranges overlapping by 100 bytes; naive sum would be 800.
    assert acc.unique_payload([(0, 500), (400, 700)]) == 700
    # Fully disjoint.
    assert acc.unique_payload([(0, 100), (200, 300)]) == 200
    # Exact duplicate.
    assert acc.unique_payload([(0, 100), (0, 100)]) == 100
    assert acc.unique_payload([]) == 0


def test_unique_payload_handles_wraparound():
    """A range crossing 2^32 is split, not treated as backwards."""
    acc = packettrain.accounting_tcp
    top = acc.SEQ_SPACE
    # 100 bytes at the very top plus 100 bytes at the bottom.
    assert acc.unique_payload([(top - 100, top), (0, 100)]) == 200


def test_window_scale_is_none_when_not_advertised():
    """Unknown scale must be None, never an assumed 0."""
    acc = packettrain.accounting_tcp
    lines = [
        row(1, 0.000, 1, 100, 0, {"tcp.flags.syn": "1"}),
        row(2, 0.100, 1, 200, 1400, {"tcp.flags.ack": "1"}),
    ]
    packets = _stream(packettrain.parse_rows(lines))
    packets[1].update(src="198.51.100.2", dst="192.0.2.1", sport=443, dport=50000)
    result = acc.scaled_window(packets)
    assert result["client_scale_shift"] is None
    assert result["server_scale_shift"] is None
    # Reported unscaled, and labelled as such rather than multiplied by 1.
    assert all(pt["scaled"] is None for pt in result["history"])
    assert all("unscaled" in pt["counting_basis"] for pt in result["history"])


def test_window_scale_is_per_direction_and_skips_syn():
    """Each direction scales by its own advertised shift; a SYN window is unscaled.

    Window scale is negotiated independently per direction, so one side
    advertising shift 7 says nothing about the other side's windows.
    """
    acc = packettrain.accounting_tcp
    lines = [
        row(1, 0.000, 1, 100, 0, {"tcp.flags.syn": "1", "tcp.options.wscale.shift": "7"}),
        row(2, 0.010, 1, 200, 0, {"tcp.flags.syn": "1", "tcp.flags.ack": "1",
                                   "tcp.options.wscale.shift": "8"}),
        row(3, 0.100, 1, 101, 1400, {"tcp.flags.ack": "1"}),
        row(4, 0.110, 1, 201, 1400, {"tcp.flags.ack": "1"}),
    ]
    packets = _stream(packettrain.parse_rows(lines))
    # Frames 2 and 4 travel server -> client.
    for idx in (1, 3):
        packets[idx].update(src="198.51.100.2", dst="192.0.2.1", sport=443, dport=50000)
    _stream(packets)
    packets[0]["window"] = 64240   # client SYN
    packets[1]["window"] = 64240   # server SYN-ACK
    packets[2]["window"] = 502     # client data
    packets[3]["window"] = 256     # server data

    result = acc.scaled_window(packets)
    assert result["client_scale_shift"] == 7
    assert result["server_scale_shift"] == 8

    by_dir = {}
    for pt in result["history"]:
        by_dir.setdefault(pt["direction"], []).append(pt)

    # Both SYN windows stay unscaled even though they carry the option.
    assert by_dir["out"][0]["scaled"] is None
    assert by_dir["in"][0]["scaled"] is None
    # Data windows scale by their own direction's shift.
    assert by_dir["out"][1]["scaled"] == 502 << 7    # 64256, matches TShark
    assert by_dir["in"][1]["scaled"] == 256 << 8     # 65536


def test_outstanding_bytes_starts_full_and_drains_on_ack():
    acc = packettrain.accounting_tcp
    lines = [
        row(1, 0.000, 1, 1000, 0, {"tcp.flags.syn": "1"}),
        row(2, 0.010, 1, 1001, 500, {"tcp.flags.ack": "1"}),
        row(3, 0.020, 1, 1501, 500, {"tcp.flags.ack": "1"}),
        row(4, 0.030, 1, 2001, 0, {"tcp.flags.ack": "1"}),
    ]
    packets = _stream(packettrain.parse_rows(lines))
    packets[3].update(src="198.51.100.2", dst="192.0.2.1", sport=443, dport=50000)
    _stream(packets)
    # The server acks to 1001, so both sent segments (1001-2001) stay outstanding.
    packets[3]["ack"] = 1001
    result = acc.outstanding_bytes(packets)
    points = [p for p in result["series"] if p["direction"] == "out"]
    assert points, "expected an outstanding series for the client direction"
    assert points[-1]["outstanding"] == 1000
    # Ack everything and confirm the outstanding figure drains to zero.
    packets[3]["ack"] = 2001
    drained = acc.outstanding_bytes(packets)
    assert all(p["outstanding"] == 0 for p in drained["series"]
               if p["direction"] == "out")


def test_largest_burst_reports_threshold_and_sensitivity():
    acc = packettrain.accounting_tcp
    lines = []
    for i in range(6):
        lines.append(row(i + 1, i * 0.01, 1, 1000 + i * 500, 500, {"tcp.flags.ack": "1"}))
    packets = _stream(packettrain.parse_rows(lines))
    result = acc.largest_burst(packets)
    assert result["largest"]["bytes"] == 3000
    assert result["largest"]["records"] == 6
    assert result["threshold_s"] == acc.BURST_GAP_S
    assert len(result["sensitivity"]) == 4


def test_accounting_reports_limitations():
    """Each result names its basis, so callers cannot read it as cwnd."""
    acc = packettrain.accounting_tcp
    lines = [
        row(1, 0.0, 1, 1, 0, {"tcp.flags.syn": "1"}),
        row(2, 0.01, 1, 2, 1400, {"tcp.flags.ack": "1"}),
    ]
    packets = _stream(packettrain.parse_rows(lines))
    result = acc.tcp_accounting(packets)
    assert "not cwnd" in result["outstanding"]["limitation"]
    assert "not a congestion-window measurement" in result["bursts"]["limitation"]
    assert result["unique_payload_bytes"]["client"] == 1400


def test_flow_carries_accounting_with_limitations():
    """The flow payload exposes accounting, each part naming its basis."""
    lines = [
        row(1, 0.000, 1, 1000, 0, {"tcp.flags.syn": "1", "tcp.options.wscale.shift": "7"}),
        row(2, 0.010, 1, 2000, 0, {"tcp.flags.syn": "1", "tcp.flags.ack": "1",
                                   "tcp.options.wscale.shift": "7"}),
        row(3, 0.100, 1, 1001, 1400, {"tcp.flags.ack": "1"}),
        row(4, 0.110, 1, 2001, 0, {"tcp.flags.ack": "1"}),
    ]
    packets = packettrain.parse_rows(lines)
    for idx in (1, 3):
        packets[idx].update(src="198.51.100.2", dst="192.0.2.1", sport=443, dport=50000)
    detail = packettrain.stream_detail(packets, 1)
    acc = detail["accounting"]
    assert acc["unique_payload_bytes"]["client"] == 1400
    assert acc["window"]["client_scale_shift"] == 7
    assert acc["window"]["server_scale_shift"] == 7
    assert "not cwnd" in acc["outstanding"]["limitation"]
    assert acc["bursts"]["largest"]["bytes"] == 1400


def test_flow_response_drops_ts_but_keeps_time_ms():
    """The wire format must not grow a per-packet epoch timestamp.

    Accounting needs ts internally, but the response drops it because a million
    packets would carry a large redundant field.
    """
    lines = [
        row(1, 100.0, 1, 1, 0, {"tcp.flags.syn": "1"}),
        row(2, 100.2, 1, 2, 1400, {"tcp.flags.ack": "1"}),
    ]
    packets = packettrain.parse_rows(lines)
    detail = packettrain.stream_detail(packets, 1)
    for p in detail["packets"]:
        assert "ts" not in p
        assert "time_ms" in p
    # Accounting still saw the real timestamps.
    assert detail["accounting"]["unique_payload_bytes"]["client"] == 1400


def test_accounting_does_not_mutate_input_packets():
    """Accounting works on a copy, so the response packets stay as documented."""
    lines = [
        row(1, 100.0, 1, 1, 0, {"tcp.flags.syn": "1"}),
        row(2, 100.2, 1, 2, 1400, {"tcp.flags.ack": "1"}),
    ]
    packets = packettrain.parse_rows(lines)
    before = [dict(p) for p in packets]
    packettrain.stream_detail(packets, 1)
    for original, after in zip(before, packets):
        assert original == after


def test_static_assets_are_served_and_scoped():
    """The vendored bundle is reachable, and only from static/."""
    client = packettrain.app.test_client()
    ok = client.get("/static/plotly.min.js")
    assert ok.status_code == 200
    assert b"plotly.js v2" in ok.data[:80]
    # Path traversal must not escape the static directory.
    assert client.get("/static/../app.py").status_code in (400, 404)
    assert client.get("/static/..%2fapp.py").status_code in (400, 404)
