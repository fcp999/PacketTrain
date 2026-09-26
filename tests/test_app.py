import pytest

import app as packettrain


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
    monkeypatch.setattr(packettrain, "PCAP_DIR", tmp_path)
    (tmp_path / "good.pcap").write_bytes(b"capture")
    (tmp_path / "link.pcap").symlink_to(tmp_path / "good.pcap")
    client = packettrain.app.test_client()
    assert [x["name"] for x in client.get("/api/files").json["files"]] == ["good.pcap"]
    assert client.get("/api/streams?file=../good.pcap").status_code == 400
    assert client.get("/api/streams?file=link.pcap").status_code == 404


def test_stream_endpoints_use_tshark_fields(tmp_path, monkeypatch):
    monkeypatch.setattr(packettrain, "PCAP_DIR", tmp_path)
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
