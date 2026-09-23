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
    assert detail["facts"]["jumbo_segments"] is True
    assert detail["facts"]["first_flight_packets"] == 3
    assert detail["facts"]["first_flight_bytes"] == 26844
