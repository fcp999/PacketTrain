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
