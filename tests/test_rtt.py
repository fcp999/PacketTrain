import pytest

import app
from packettrain import rtt

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


def rtt_row(frame, ts, ack_rtt_ms, flags=None):
    """A packet row carrying an ACK RTT sample in milliseconds.

    TShark reports ``tcp.analysis.ack_rtt`` in seconds; decode.py rescales to
    milliseconds, so the raw field here is ms / 1000.
    """
    merged = {"tcp.analysis.ack_rtt": str(ack_rtt_ms / 1000.0)}
    merged.update(flags or {})
    return row(frame, ts, 1, frame * 1000, 0, merged)


def samples(rtts, start=100.0, step=0.05, extra=None):
    """Build packets carrying the given RTT samples, one per frame."""
    lines = []
    ts = start
    for index, value in enumerate(rtts):
        flags = dict(extra or {})
        lines.append(rtt_row(index + 1, round(ts, 6), value, flags))
        ts += step
    return packettrain.parse_rows(lines)


def test_percentiles_and_spread():
    packets = samples([10, 20, 30, 40, 50])
    result = rtt.rtt_distribution(packets)
    assert result["samples"] == 5
    assert result["min_ms"] == pytest.approx(10, abs=0.001)
    assert result["median_ms"] == pytest.approx(30, abs=0.001)
    # Linear interpolation: position 0.95 * 4 = 3.8 between 40 and 50.
    assert result["p95_ms"] == pytest.approx(48, abs=0.001)
    assert result["max_ms"] == pytest.approx(50, abs=0.001)
    assert result["mean_ms"] == pytest.approx(30, abs=0.001)
    assert result["stdev_ms"] == pytest.approx(14.142, abs=0.01)
    assert result["variability"] == pytest.approx(0.471, abs=0.01)
    assert not result["insufficient"]


def test_single_sample_has_no_spread():
    result = rtt.rtt_distribution(samples([25]))
    assert result["samples"] == 1
    assert result["median_ms"] == pytest.approx(25, abs=0.001)
    assert result["p95_ms"] == pytest.approx(25, abs=0.001)
    assert result["variability"] == 0
    # One sample is not a distribution, and is flagged as such.
    assert result["insufficient"]
    assert "too few" in result["reason"]


def test_retransmitted_ack_samples_are_rejected():
    packets = samples([20, 20, 20],
                      extra={"tcp.analysis.fast_retransmission": "1"})
    result = rtt.rtt_distribution(packets)
    assert result["samples"] == 0
    assert result["rejected"]["retransmitted_ack"] == 3
    assert result["insufficient"]


def test_idle_gap_rejects_application_stall():
    # Second sample arrives 10s after the first: the ACK measures a stall in
    # either the application or the capture, not a network round trip.
    lines = [rtt_row(1, 100.0, 20), rtt_row(2, 110.0, 30),
             rtt_row(3, 110.05, 25)]
    result = rtt.rtt_distribution(packettrain.parse_rows(lines))
    assert result["rejected"]["idle_gap"] == 1
    assert result["samples"] == 2


def test_implausible_and_sliced_samples_are_rejected():
    lines = [rtt_row(1, 100.0, 20),
             rtt_row(2, 100.05, 120_000),        # beyond MAX_SAMPLE_MS
             rtt_row(3, 100.10, 30, {"frame.cap_len": "64", "frame.len": "1514"}),
             rtt_row(4, 100.15, 0)]              # no usable sample
    result = rtt.rtt_distribution(packettrain.parse_rows(lines))
    assert result["rejected"]["implausible"] == 1
    assert result["rejected"]["sliced"] == 1
    assert result["rejected"]["missing"] == 1
    assert result["samples"] == 1


def test_no_samples_reports_honest_absence():
    result = rtt.rtt_distribution(samples([0, 0, 0]))
    assert result["samples"] == 0
    assert result["insufficient"]
    assert result["reason"] == "no valid ACK RTT samples in this capture"
    assert "median_ms" not in result
