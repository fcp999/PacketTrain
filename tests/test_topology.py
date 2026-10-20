"""Tests for topology aggregation. No PCAP or TShark required."""
from packettrain.topology import build_topology

def test_aggregate_flows_and_limit():
    streams = [
        {"id": 4, "client": "10.0.0.1", "server": "8.8.8.8", "server_port": 443, "packets": 3, "bytes": 100},
        {"id": 9, "client": "10.0.0.1", "server": "8.8.8.8", "server_port": 443, "packets": 8, "bytes": 900},
        {"id": 10, "client": "10.0.0.3", "server": "10.0.0.2", "server_port": 22, "packets": 2, "bytes": 5},
    ]
    result = build_topology(streams, limit=1)
    assert result["total_pairs"] == 2
    assert result["shown_pairs"] == 1
    assert len(result["nodes"]) == 2
    assert result["edges"][0]["bytes"] == 1000
    assert result["edges"][0]["packets"] == 11
    assert result["edges"][0]["streams"] == 2
    assert result["edges"][0]["stream"] == 4
    assert result["edges"][0]["ports"] == [443]

def test_empty():
    assert build_topology([])["edges"] == []

def test_limit_is_bounded():
    assert build_topology([], 999999)["shown_pairs"] == 0

def test_native_pairs_to_graph_nodes():
    from packettrain.topology import topology_from_pairs
    result = topology_from_pairs([
        {"source": "10.0.0.1", "target": "8.8.8.8",
         "bytes": 120, "packets": 7, "streams": 1, "stream": 0, "ports": [443]}
    ])
    assert result["engine"] == "rust-sqlite"
    assert result["shown_pairs"] == 1
    assert len(result["nodes"]) == 2
    assert {n["role"] for n in result["nodes"]} == {"internal", "external"}

def test_native_stats_are_preserved():
    from packettrain.topology import topology_from_pairs
    edge = {"source": "192.0.2.10", "target": "198.51.100.2",
            "bytes": 400, "captured_bytes": 900, "packets": 5,
            "streams": 2, "stream": 1, "ports": [443],
            "resets": 1, "syn_flows": 2, "closed_flows": 1,
            "duration_ms": 250}
    result = topology_from_pairs([edge])
    assert result["edges"][0]["resets"] == 1
    assert result["edges"][0]["closed_flows"] == 1
    assert result["edges"][0]["captured_bytes"] == 900
