"""Conservative TLS exchange inference from directional TCP payload flights.

No claim is made about HTTP request boundaries, methods or application identity.
"""
from bisect import bisect_left
from statistics import median
import math
import re

MAX_EXCHANGES = 2000
MAX_BURSTS = 10000
_SEQ = 1 << 32


def _types(p, key):
    return set(re.split(r"[,;\s]+", str(p.get(key) or "")))


def _quantile(values, q):
    if not values:
        return None
    x = sorted(values)
    pos = (len(x) - 1) * q
    lo = int(pos)
    return round(x[lo] + (x[min(lo + 1, len(x)-1)] - x[lo]) * (pos - lo), 3)


def _unique_records(packets):
    """Count unique sequence intervals once, including partial retransmits.

    Maintain merged intervals per direction. The common sequential case is
    constant time; disordered inserts use a binary search.
    """
    bases = {}
    ranges = {"out": [], "in": []}
    for p in packets:
        direction = p.get("direction")
        if direction not in ranges or not p.get("length"):
            continue
        length = p["length"]
        seq = (p["seq"] + int(bool(p.get("syn")))) % _SEQ
        base = bases.setdefault(direction, seq)
        start = (seq - base + _SEQ // 2) % _SEQ - _SEQ // 2
        end = start + length
        intervals = ranges[direction]
        i = bisect_left(intervals, (start,))
        if i and intervals[i-1][1] >= start:
            i -= 1
        j, overlap = i, 0
        left, right = start, end
        while j < len(intervals) and intervals[j][0] <= right:
            a, b = intervals[j]
            overlap += max(0, min(end, b) - max(start, a))
            left, right = min(left, a), max(right, b)
            j += 1
        intervals[i:j] = [(left, right)]
        unique = max(0, length - overlap)
        if unique:
            yield p, unique


def analyze_transactions(packets, https, rtt_ms=None, side="unknown"):
    if not https:
        return None
    ordered = sorted(packets, key=lambda p: (p["time_ms"], p["frame"]))
    if not ordered:
        return None
    idle_ms = round(max(50, min(1000, 3 * rtt_ms if rtt_ms and rtt_ms > 0 else 200)), 3)
    alpn = str(https.get("alpn_offered") or "")
    multiplex = "h2" in re.split(r"[,;\s]+", alpn)
    hello = any(_types(p, "tls_handshake") & {"1", "2"} for p in ordered)
    visible_tls = any("23" in _types(p, "tls_record") for p in ordered)
    limitation = ("Directional ciphertext exchanges are estimates, not HTTP transactions. "
                  "TLS 1.3 encrypted handshake, alerts, session tickets and HTTP/2 multiplexing "
                  "can resemble application exchanges; TCP byte totals include TLS overhead. "
                  "A capture ending before the next turn cannot prove response completion.")
    out = {"available": visible_tls, "idle_gap_ms": idle_ms,
           "alpn_h2_offered": multiplex, "handshake_observed": hello,
           "exchanges": [], "bursts": [], "stats": {}, "periodicity": None,
           "limitation": limitation, "notes": [], "truncated": False}
    if not visible_tls:
        out["notes"].append("No decoded TLS application-data record (outer type 23).")
        return out
    if multiplex:
        out["notes"].append("HTTP/2 offered, not necessarily negotiated. Overlapping logical requests cannot be separated.")
    if any(p.get("sliced") for p in ordered):
        out["notes"].append("Capture slicing detected; byte counts use TCP-declared lengths and may exceed captured bytes.")
    if not hello:
        out["notes"].append("Capture lacks a visible hello; direction and handshake filtering are uncertain.")
    # When a hello exists, conservatively exclude the first ciphertext flight
    # in each direction and any visible handshake/control packets. A possible
    # genuine first request may therefore be excluded. No guessed exact TLS 1.3 boundary.
    unique = list(_unique_records(ordered))
    bursts = []
    current = None
    started = False
    for p, length in unique:
        typ = _types(p, "tls_record")
        if p.get("tls_handshake") or p.get("syn") or p.get("rst"):
            current = None
            continue
        if "23" in typ:
            started = True
        if not started or (typ - {""} and "23" not in typ):
            current = None
            continue
        t, direction = p["time_ms"], p["direction"]
        if current is None or current["direction"] != direction or t-current["end_ms"] > idle_ms:
            if len(bursts) >= MAX_BURSTS:
                out["truncated"] = True
                break
            current = {"direction": direction, "start_ms": t, "end_ms": t,
                       "first_frame": p["frame"], "last_frame": p["frame"],
                       "bytes": 0, "records": 0, "tls23_records": 0}
            bursts.append(current)
        current["end_ms"], current["last_frame"] = t, p["frame"]
        current["bytes"] += length
        current["records"] += 1
        current["tls23_records"] += int("23" in typ)
    excluded = set()
    if hello:
        for direction in ("out", "in"):
            first = next((i for i,b in enumerate(bursts) if b["direction"] == direction and b["tls23_records"]), None)
            if first is not None:
                excluded.add(first)
        if excluded:
            out["notes"].append("First TLS ciphertext flight in each direction excluded as potential handshake; early application data may be omitted.")
    # Coalesce same-direction flights into a turn so ACK pacing, slow start
    # and application pauses do not create fake requests.
    turns = []
    for i,b in enumerate(bursts):
        if i in excluded:
            continue
        if turns and turns[-1]["direction"] == b["direction"]:
            t = turns[-1]
            t["end_ms"], t["last_frame"] = b["end_ms"], b["last_frame"]
            for key in ("bytes", "records", "tls23_records"):
                t[key] += b[key]
            t["bursts"] += 1
        else:
            turns.append(dict(b, bursts=1))
    out["bursts"] = bursts
    rows = out["exchanges"]
    i = 0
    while i < len(turns):
        req = turns[i]
        if req["direction"] != "out":
            i += 1
            continue
        response = turns[i+1] if i+1 < len(turns) and turns[i+1]["direction"] == "in" else None
        if response is None:
            out["notes"].append("Final client flight has no observed server response.")
            break
        delay = max(0, response["start_ms"]-req["end_ms"])
        next_client = turns[i+2] if i+2 < len(turns) else None
        confidence = "low" if multiplex or not hello or not req["tls23_records"] or not response["tls23_records"] else "moderate"
        if req["bursts"] > 1 or response["bursts"] > 1:
            confidence = "low"
        # A server-side capture directly observes the interval, while a
        # client-side capture has an unknown time-varying path component.
        estimate = delay if side == "server" else max(0, delay-rtt_ms) if side == "client" and rtt_ms and rtt_ms > 0 else None
        row = {"id": len(rows)+1, "start_ms": req["start_ms"], "end_ms": response["end_ms"],
               "request_end_ms": req["end_ms"], "response_start_ms": response["start_ms"],
               "request_bytes": req["bytes"], "response_bytes": response["bytes"],
               "first_frame": req["first_frame"], "last_frame": response["last_frame"],
               "request_last_frame": req["last_frame"], "response_first_frame": response["first_frame"],
               "response_delay_ms": round(delay, 3), "service_estimate_ms": round(estimate, 3) if estimate is not None else None,
               "response_span_ms": round(response["end_ms"]-response["start_ms"], 3),
               "duration_ms": round(response["end_ms"]-req["start_ms"], 3),
               "idle_after_ms": round(max(0,next_client["start_ms"]-response["end_ms"]),3) if next_client else None,
               "confidence": confidence, "right_censored": next_client is None,
               "request_bursts": req["bursts"], "response_bursts": response["bursts"], "anomaly": False}
        rows.append(row)
        if len(rows) >= MAX_EXCHANGES:
            out["truncated"] = True
            break
        i += 2
    delays = [r["response_delay_ms"] for r in rows]
    if delays:
        med = median(delays)
        mad = median(abs(x-med) for x in delays)
        threshold = max(med * 2, med + 3 * 1.4826 * mad, med + 10)
        if len(rows) >= 5:
            for row in rows:
                row["anomaly"] = row["response_delay_ms"] > threshold
        out["stats"] = {"count": len(rows), "median_ms": _quantile(delays,.5),
                        "p95_ms": _quantile(delays,.95), "p99_ms": _quantile(delays,.99),
                        "max_ms": round(max(delays),3),
                        "anomalies": sum(r["anomaly"] for r in rows),
                        "anomaly_threshold_ms": round(threshold,3) if len(rows)>=5 else None}
    if len(rows) >= 5:
        intervals = [b["start_ms"]-a["start_ms"] for a,b in zip(rows,rows[1:])]
        period = median(intervals)
        jitter = median(abs(v-period) for v in intervals)
        matching = sum(abs(v-period) <= max(10, .15*period) for v in intervals)
        if period >= 100 and matching/len(intervals) >= .8:
            out["periodicity"] = {"period_ms": round(period,3), "median_abs_jitter_ms": round(jitter,3),
                                  "matching_intervals": matching, "intervals": len(intervals),
                                  "label": "Regular exchange cadence (possible polling/heartbeat)"}
    if out["truncated"]:
        out["notes"].append("Analysis row limit reached; statistics describe only the displayed prefix.")
    return out
