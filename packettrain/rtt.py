"""Round-trip time distribution from valid ACK timing samples.

Ack RTT samples come from TShark's ``tcp.analysis.ack_rtt``: the gap between a
data segment and the ACK that acknowledges it, measured in the capture's own
clock. That single number is only useful when the sample is honest, so this
module decides which samples count before computing anything.

Samples are rejected when:

* the RTT is absent or non-positive (no ACK-to-data pairing at all);
* the ACK is itself a retransmission, so the timer restarted mid-flight;
* the flow was idle long before the ACK -- an application stall, not a network
  round trip;
* the frame was sliced, so the measured gap includes data the capture lost;
* the value falls outside a physically plausible range.

Everything else is reported as percentiles. The spread matters more than the
median for diagnosis: a flow can sit at a healthy 20 ms median while its P95 is
seconds, and only the tail explains why the user thinks it is slow.
"""


# An ACK arriving after this much silence behind the data it acknowledges is
# measuring an application pause as much as a network trip.
IDLE_GAP_MS = 5_000.0

# Beyond this, the "RTT" is almost certainly a stalled peer or a reassembled
# capture artifact rather than a round trip worth reporting.
MAX_SAMPLE_MS = 60_000.0

# Below this the sample is loopback, virtual switching, or timestamp resolution.
MIN_SAMPLE_MS = 0.01

# Fewer than this and "percentiles" are just the handful of values that happened
# to appear; the distribution is reported but flagged insufficient.
MIN_SAMPLES = 3


def _samples(group):
    """Split packets into accepted RTT samples and per-reason rejection counts."""
    accepted = []
    rejected = {
        "missing": 0,
        "retransmitted_ack": 0,
        "idle_gap": 0,
        "sliced": 0,
        "implausible": 0,
    }
    previous_ts = None
    for packet in group:
        ts = packet.get("ts")
        gap_ms = None
        if ts is not None and previous_ts is not None:
            gap_ms = (ts - previous_ts) * 1000.0
        if ts is not None:
            previous_ts = ts

        rtt_ms = packet.get("ack_rtt_ms") or 0.0
        if rtt_ms <= 0:
            rejected["missing"] += 1
            continue
        if packet.get("retrans"):
            rejected["retransmitted_ack"] += 1
            continue
        if packet.get("sliced"):
            rejected["sliced"] += 1
            continue
        if gap_ms is not None and gap_ms > IDLE_GAP_MS:
            rejected["idle_gap"] += 1
            continue
        if not MIN_SAMPLE_MS <= rtt_ms <= MAX_SAMPLE_MS:
            rejected["implausible"] += 1
            continue
        accepted.append(rtt_ms)
    return accepted, rejected


def _percentile(sorted_values, fraction):
    """Linear-interpolated percentile over an already sorted list."""
    if not sorted_values:
        return None
    if len(sorted_values) == 1:
        return sorted_values[0]
    position = (len(sorted_values) - 1) * fraction
    lower = int(position)
    upper = min(lower + 1, len(sorted_values) - 1)
    weight = position - lower
    return sorted_values[lower] * (1.0 - weight) + sorted_values[upper] * weight


def rtt_distribution(group):
    """Percentiles and spread of valid ACK RTT samples for one stream.

    Returns a dict with ``samples: 0`` when nothing survives validation: an
    absent distribution is honest, while one built from a few broken samples
    would invite conclusions the capture cannot support.
    """
    accepted, rejected = _samples(group)
    if not accepted:
        return {
            "samples": 0,
            "rejected": rejected,
            "insufficient": True,
            "reason": "no valid ACK RTT samples in this capture",
        }

    values = sorted(accepted)
    median = _percentile(values, 0.5)
    p95 = _percentile(values, 0.95)
    mean = sum(values) / len(values)
    # Population standard deviation: these are all the samples the capture
    # offered, not a draw from a larger population we are inferring.
    variance = sum((value - mean) ** 2 for value in values) / len(values)
    stdev = variance ** 0.5
    return {
        "samples": len(values),
        "min_ms": round(values[0], 3),
        "median_ms": round(median, 3),
        "p95_ms": round(p95, 3),
        "max_ms": round(values[-1], 3),
        "mean_ms": round(mean, 3),
        "stdev_ms": round(stdev, 3),
        # Jitter as a fraction of the median: comparable across paths with very
        # different baseline latency, where absolute stdev is not.
        "variability": round(stdev / median, 3) if median else None,
        "tail_ratio": round(p95 / median, 2) if median else None,
        "rejected": rejected,
        "insufficient": len(values) < MIN_SAMPLES,
        "reason": (None if len(values) >= MIN_SAMPLES
                   else "too few valid samples for percentiles"),
    }
