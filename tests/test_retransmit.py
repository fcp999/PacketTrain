import pytest

import app
from packettrain import retransmit

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


def stream(frames):
    """Build a stream from (ts, seq, length, extra_flags) tuples in one direction."""
    lines = [row(index + 1, ts, 1, seq, length, flags)
             for index, (ts, seq, length, flags) in enumerate(frames)]
    packets = packettrain.parse_rows(lines)
    for packet in packets:
        packet["direction"] = "out"
    return packets


def test_unique_versus_repeated_bytes():
    # 1000 bytes sent once, then the same 1000 bytes again.
    packets = stream([(1.0, 1000, 1000, {}), (1.5, 1000, 1000, {})])
    result = retransmit.retransmission_analysis(packets)
    client = result["by_direction"]["client"]
    assert client["first_transmissions"] == 1
    assert client["repeats"] == 1
    assert client["unique_bytes"] == 1000
    assert client["repeated_bytes"] == 1000
    assert client["repeated_percent"] == pytest.approx(50.0)


def test_partial_retransmission_counts_overlap_only():
    # 1000 bytes, then a 600-byte repeat of the tail: only 600 bytes are repeats.
    packets = stream([(1.0, 1000, 1000, {}), (1.5, 1400, 600, {})])
    result = retransmit.retransmission_analysis(packets)
    client = result["by_direction"]["client"]
    assert client["repeated_bytes"] == 600
    assert client["unique_bytes"] == 1000


def test_repeat_after_duplicate_acks_is_a_retransmission():
    packets = stream([
        (1.0, 1000, 1000, {}),
        (1.2, 2000, 0, {"tcp.flags.ack": "1", "tcp.analysis.duplicate_ack": "1"}),
        (1.4, 1000, 1000, {"tcp.analysis.fast_retransmission": "1"}),
    ])
    result = retransmit.retransmission_analysis(packets)
    assert result["verdicts"]["retransmission"] == 1
    assert result["repeats"][0]["reason"].startswith("repeat ")


def test_early_repeat_without_duplicate_acks_is_reordering():
    packets = stream([(1.0, 1000, 1000, {}), (1.05, 1000, 1000, {})])
    result = retransmit.retransmission_analysis(packets)
    assert result["verdicts"]["reordering"] == 1
    assert "reordering" in result["repeats"][0]["reason"]


def test_one_sided_repeats_flag_capture_artifact():
    packets = stream([(1.0, 1000, 1000, {}), (2.0, 1000, 1000, {})])
    result = retransmit.retransmission_analysis(packets)
    assert result["capture_artifact"]["suspected"] is True
    assert result["capture_artifact"]["side"] == "client"


def test_no_repeats_is_clean():
    packets = stream([(1.0, 1000, 1000, {}), (1.1, 2000, 1000, {})])
    result = retransmit.retransmission_analysis(packets)
    assert result["repeated_bytes"] == 0
    assert result["repeated_percent"] == 0.0
    assert result["capture_artifact"] is None
    assert result["meaningful"] is False


def test_sequence_wraparound_does_not_create_false_repeats():
    # ISN near 2^32: a segment crossing the boundary must not look like a repeat.
    isn = (1 << 32) - 500
    packets = stream([(1.0, isn, 1000, {}), (1.1, (isn + 1000) % (1 << 32), 1000, {})])
    result = retransmit.retransmission_analysis(packets)
    assert result["by_direction"]["client"]["repeats"] == 0
