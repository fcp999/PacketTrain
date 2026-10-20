"""Bounded host-pair topology aggregation from indexed TCP flow summaries.

PacketCircle-inspired concept, independently implemented for PacketTrain.
This phase represents TCP payload volume (not full L2/L3 packet bytes).
"""
from collections import defaultdict
import ipaddress

def build_topology(streams, limit=100):
    limit = max(1, min(int(limit), 500))
    edges = defaultdict(lambda: {"bytes": 0, "packets": 0, "streams": 0, "stream": None, "ports": set()})
    hosts = defaultdict(lambda: {"bytes": 0, "packets": 0, "peers": set()})
    for s in streams:
        a, b = s["client"], s["server"]
        key = tuple(sorted((a, b)))
        edge = edges[key]
        count, size = int(s["packets"]), int(s["bytes"])
        edge["bytes"] += size
        edge["packets"] += count
        edge["streams"] += 1
        if edge["stream"] is None:
            edge["stream"] = s["id"]
        if len(edge["ports"]) < 32:
            edge["ports"].add(s["server_port"])
        for x, y in ((a, b), (b, a)):
            hosts[x]["bytes"] += size
            hosts[x]["packets"] += count
            hosts[x]["peers"].add(y)
    selected = sorted(edges.items(), key=lambda item: (-item[1]["bytes"], -item[1]["packets"]))[:limit]
    visible = {address for pair, _ in selected for address in pair}
    nodes = []
    for address in visible:
        try:
            ip = ipaddress.ip_address(address)
            role = "internal" if ip.is_private else "external"
            if ip.is_multicast:
                role = "multicast"
            elif ip.is_loopback:
                role = "loopback"
        except ValueError:
            role = "unknown"
        h = hosts[address]
        nodes.append({"id": address, "role": role, "bytes": h["bytes"],
                      "packets": h["packets"], "peers": len(h["peers"])})
    nodes.sort(key=lambda node: (-node["bytes"], node["id"]))
    links = [{"source": a, "target": b, "bytes": d["bytes"], "packets": d["packets"],
              "streams": d["streams"], "stream": d["stream"], "ports": sorted(d["ports"])}
             for (a, b), d in selected]
    return {"nodes": nodes, "edges": links, "total_pairs": len(edges),
            "shown_pairs": len(links), "metric": "TCP payload bytes"}
