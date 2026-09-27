# PacketTrain flow index (Stage A)

Indexes classic Ethernet PCAP without running Wireshark over the whole capture.
It writes one fixed-size packet reference per TCP packet and one SQLite row per
connection generation. The source capture remains read-only.

```bash
packettrain-index scan capture.pcap --output capture.ptindex
packettrain-index extract --index capture.ptindex --flow 0 --output flow-0.pcap
```

This stage intentionally rejects PCAPNG and non-Ethernet link types. Those are
next-stage features after packet-membership and extraction validation.
