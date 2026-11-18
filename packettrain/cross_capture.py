"""Capture-wide lifetimes and selected-stream comparison."""
from collections import Counter, defaultdict
from statistics import median


def activity_timeline(rows, client=None, limit=100):
    filtered=[r for r in rows if not client or r["client"]==client]
    # Favor high-volume flows, but preserve a shared clock across the capture.
    origin=min((r["first_ts"] for r in rows),default=0)
    chosen=sorted(filtered,key=lambda r:(-r["bytes"],r["first_ts"],r["id"]))[:limit]
    result=[]
    for r in sorted(chosen,key=lambda r:r["first_ts"]):
        result.append({**r,"start_ms":round((r["first_ts"]-origin)*1000,3),
                       "end_ms":round((r["last_ts"]-origin)*1000,3)})
    return {"flows":result,"total":len(filtered),"shown":len(result),
            "origin_epoch":origin,
            "basis":"Flow lifetimes (first to last captured TCP record), not continuous activity or causal transaction boundaries."}


def packet_signature(p):
    # TCP sequence/ack/flags/length only: not a payload hash. Compare
    # direction relative to each independently selected stream.
    return (p["direction"],p["seq"],p["ack"],p["length"],p.get("flags_raw"))


def compare_streams(a,b,clock_offset_ms=None):
    aa,bb=defaultdict(list),defaultdict(list)
    for p in a: aa[packet_signature(p)].append(p)
    for p in b: bb[packet_signature(p)].append(p)
    # Ambiguous identical ACKs and retries are not paired.
    unique=[]
    for key, left in aa.items():
        right=bb.get(key,[])
        if len(left)==len(right)==1:
            unique.append((left[0],right[0]))
    unique.sort(key=lambda x:x[0]["ts"])
    samples=[(q["ts"]-p["ts"])*1000 for p,q in unique]
    results=[]
    for direction in ("out","in"):
        pairs=[(p,q) for p,q in unique if p["direction"]==direction]
        unmatched_a=sum(len(v) for k,v in aa.items() if k[0]==direction and k not in bb)
        unmatched_b=sum(len(v) for k,v in bb.items() if k[0]==direction and k not in aa)
        values=[(q["ts"]-p["ts"])*1000 for p,q in pairs]
        # Signed B-A delta; reverse-direction travel is normally negative.
        corrected=[v-clock_offset_ms for v in values] if clock_offset_ms is not None else []
        results.append({"direction":direction,"unique_matches":len(pairs),
                        "only_a_records":unmatched_a,"only_b_records":unmatched_b,
                        "median_timestamp_delta_ms":round(median(values),3) if values else None,
                        "median_corrected_delta_ms":round(median(corrected),3) if corrected else None})
    return {"directions":results,"unique_matches":len(unique),
            "ambiguous_signatures":sum(1 for k,v in aa.items() if k in bb and (len(v)!=1 or len(bb[k])!=1)),
            "examples":[{"frame_a":p["frame"],"frame_b":q["frame"],"direction":p["direction"],
                         "delta_ms":round((q["ts"]-p["ts"])*1000,3)} for p,q in unique[:100]],
            "basis":"Unique direction/sequence/ACK/length/flags signatures, not payload hashes. Unmatched records are not proven loss; capture coverage, offload, NAT sequence rewriting or unrelated sessions can prevent matches. Timestamp deltas are not one-way latency unless clocks and capture locations are independently verified."}
