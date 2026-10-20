import pytest

import app
from packettrain import window_flow

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


def build(frames):
    """frames: (ts, window, direction, extra_flags)."""
    lines = []
    for index, (ts, window, direction, flags) in enumerate(frames):
        merged = {"frame.time_epoch": str(ts)}
        if window is not None:
            merged["tcp.window_size"] = str(window)
        merged.update(flags or {})
        lines.append(row(index + 1, ts, 1, 1000 + index * 100, 0, merged))
    packets = packettrain.parse_rows(lines)
    for packet, (_, _, direction, _) in zip(packets, frames):
        packet["direction"] = direction
    return packets


def test_no_stall_reports_clean():
    packets = build([(1.0, 502, "out", None), (1.1, 501, "out", None)])
    result = window_flow.receiver_window_analysis(packets)
    assert result["episode_count"] == 0
    assert result["total_stalled_ms"] == 0.0
    assert result["persistent"] is False


def test_single_zero_window_episode_with_recovery():
    packets = build([
        (1.0, 502, "out", None),
        (1.5, 0, "out", None),      # receiver closes
        (1.6, 0, "out", None),      # probe
        (3.0, 502, "out", None),    # reopened
    ])
    result = window_flow.receiver_window_analysis(packets)
    assert result["episode_count"] == 1
    episode = result["episodes"][0]
    assert episode["start_ms"] == pytest.approx(500.0, abs=0.5)
    assert episode["duration_ms"] == pytest.approx(1500.0, abs=0.5)
    assert episode["recovered"] is True
    assert episode["probes"] == 2
    # A client advertisement constrains the server's ability to send.
    assert episode["constrained_direction"] == "server"


def test_back_to_back_zeros_coalesce_into_one_episode():
    packets = build([
        (1.0, 0, "out", None),
        (1.2, 0, "out", None),
        (1.4, 0, "out", None),
        (2.0, 500, "out", None),
    ])
    result = window_flow.receiver_window_analysis(packets)
    assert result["episode_count"] == 1
    assert result["episodes"][0]["probes"] == 3


def test_separate_stalls_are_separate_episodes():
    packets = build([
        (1.0, 0, "out", None), (1.5, 500, "out", None),
        (5.0, 0, "out", None), (6.0, 500, "out", None),
    ])
    result = window_flow.receiver_window_analysis(packets)
    assert result["episode_count"] == 2
    assert [e["start_ms"] for e in result["episodes"]] == [0.0, 4000.0]


def test_absent_window_field_is_not_a_stall():
    # Sliced capture: no window field at all. Must not read as zero.
    packets = build([(1.0, None, "out", None), (1.1, None, "out", None)])
    result = window_flow.receiver_window_analysis(packets)
    assert result["episode_count"] == 0


def test_syn_zero_window_is_configuration_not_stall():
    packets = build([(1.0, 0, "out", {"tcp.flags.syn": "1"}),
                     (1.1, 500, "out", None)])
    result = window_flow.receiver_window_analysis(packets)
    assert result["episode_count"] == 0
    assert result["syn_zero_window"] == 1


def test_unrecovered_episode_is_flagged_unresolved():
    packets = build([(1.0, 0, "out", None), (2.0, 0, "out", None)])
    result = window_flow.receiver_window_analysis(packets)
    assert result["episode_count"] == 1
    assert result["episodes"][0]["recovered"] is False
    assert result["unresolved"] == 1
    # Not called persistent, because the capture simply ended.
    assert result["episodes"][0]["note"] == window_flow.UNRESOLVED_NOTE


def test_stalled_fraction_of_flow():
    packets = build([
        (1.0, 500, "out", None),
        (2.0, 0, "out", None),
        (4.0, 500, "out", None),
    ])
    result = window_flow.receiver_window_analysis(packets)
    # 2.0 ms of a 3.0 s flow stalled.
    assert result["stalled_fraction"] == pytest.approx(2000 / 3000, abs=0.01)


def test_sub_round_trip_zero_is_not_reported():
    packets = build([(1.0, 0, "out", None), (1.005, 500, "out", None)])
    result = window_flow.receiver_window_analysis(packets)
    assert result["episode_count"] == 0


def test_separated_probes_are_one_episode_with_backoff():
    """A stuck receiver probes on a widening backoff: one stall, not many.

    Regression for the sourceforge shape, where seven advertisements spaced
    0.3s to 9.2s apart are a single 36s stall. An earlier implementation opened
    a new episode per probe and reported seven.
    """
    packets = build([
        (1.0, 0, "out", None),
        (1.3, 0, "out", None),
        (1.9, 0, "out", None),
        (3.1, 0, "out", None),
        (5.4, 0, "out", None),
        (10.0, 0, "out", None),
        (19.2, 0, "out", None),
        (37.0, 500, "out", None),   # window reopens
    ])
    result = window_flow.receiver_window_analysis(packets)
    assert result["episode_count"] == 1
    episode = result["episodes"][0]
    assert episode["probes"] == 7
    assert episode["recovered"] is True
    assert episode["duration_ms"] == pytest.approx(36000.0, abs=1.0)
    # Gaps widen: the receiver keeps finding no buffer space.
    assert len(episode["probe_gaps_ms"]) == 6
    assert episode["probe_gaps_ms"][-1] > episode["probe_gaps_ms"][0]
    assert episode["probe_backoff"] is True


def test_pauses_point_at_the_episode_they_belong_to():
    """Several pauses inside one stall must not read as several stalls."""
    from packettrain import phases
    packets = build([
        (1.0, 0, "out", None),
        (3.0, 0, "out", None),
        (8.0, 0, "out", None),
        (20.0, 500, "out", None),
    ])
    for index, packet in enumerate(packets):
        packet["time_ms"] = (packet["ts"] - packets[0]["ts"]) * 1000.0
        packet["frame"] = index + 1
    window = window_flow.receiver_window_analysis(packets)
    assert window["episode_count"] == 1
    table = phases.stream_phases(packets, window["episodes"])
    stalls = [p for p in table["phases"] if p.get("window_stall")]
    assert stalls, "expected at least one stall-labelled pause"
    for pause in stalls:
        assert pause["window_stall"]["episode_index"] == 0
        assert pause["window_stall"]["episode_probes"] == 3
