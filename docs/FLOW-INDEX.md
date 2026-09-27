# Flow index Stage A

`packettrain-index` replaces repeated whole-capture Wireshark passes with a
read-only packet-location index for classic Ethernet PCAP.

## Artifacts

Each index directory contains:

- `capture.sqlite`: source identity and one row per TCP connection generation.
- `refs.bin`: 32-byte packet references linked backward per flow.
- `READY`: written last; extraction rejects an incomplete index.

A reference stores source record offset and length, original frame number,
previous reference, and owner flow ID. Extraction walks one flow's chain and
copies the original PCAP records without rescanning the source.

The source size and nanosecond mtime are validated before extraction. The source
capture is never modified.

## Commands

```bash
packettrain-index scan capture.pcap --output capture.ptindex
packettrain-index extract --index capture.ptindex --flow 0 --output flow-0.pcap
```

## Stage A protocol scope

- classic PCAP, microsecond or nanosecond timestamps
- Ethernet with stacked 802.1Q/802.1ad VLAN tags
- IPv4 and IPv6 TCP
- common IPv6 extension headers
- first/later IPv4 and IPv6 fragment association
- connection generations after a closed tuple is reused
- midstream flows finalized at EOF

PCAPNG, non-Ethernet link types, tunnels, fragment-ID expiry, cache eviction,
and progressive API integration are intentionally deferred.

## Measured fixture

On the lab's 795 MiB `haproxy24_1.pcap` fixture:

- 5,999,968 frames and 5,999,064 indexed TCP packets
- 12,393 connection generations
- 2.03 seconds internal indexing time on a warm cache
- 184 MiB `refs.bin`; 1.2 MiB SQLite manifest
- flows 0, 1, and 2 extracted in 1.8-3.4 ms
- those flows exactly matched TShark stream membership and field output
- a 5,076,501-packet flow extracted to a 473 MiB PCAP in 1.03 seconds

The previous full TShark pass took 578 seconds on the same capture.
