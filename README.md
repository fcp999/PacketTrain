# PacketTrain

Browser animation of TCP streams from PCAP and PCAPNG files. Packet timestamps,
sizes, flags, duplicate ACKs, SACK blocks, and retransmission indicators come
from TShark. The app compares the two handshake legs to infer whether a capture
was taken near the client or server. If that is ambiguous, choose the capture
point manually. RTT uses the long handshake leg when classification is clear,
or TShark's ACK RTT samples as a fallback. You can override RTT in the UI.

Local-origin packets leave the capture endpoint at their captured timestamp.
Far-origin packets leave the remote endpoint at timestamp minus estimated
one-way time, then reach the capture endpoint at the captured timestamp.
The one-way estimate is RTT/2. It assumes roughly symmetric paths and does not
claim to measure actual one-way delay.

## Run with Docker

```bash
git clone https://github.com/fcp999/PacketTrain.git
cd PacketTrain
PCAP_PATH=/absolute/path/to/your/pcaps docker compose up -d --build
```

Open `http://YOUR-SERVER:8088`. Place `.pcap`, `.pcapng`, or `.cap` files directly
in the mounted directory. Click **Refresh files** after adding them. The mount
is read-only, and the app needs no packet-capture privileges. The container
runs as an unprivileged user, so the PCAP files must be readable by it.

Change the host port in `compose.yaml` if 8088 is occupied. A reverse proxy
can forward ordinary HTTP requests to the published port; WebSockets are not
required.

## Reading the visualization

- Local dot launch times use captured timestamps. Incoming dots arrive at the
  capture endpoint at their captured timestamps; their remote launch is
  estimated by subtracting RTT/2.
- Green is data; purple indicates PSH. Red `R` marks a TShark retransmission
  indicator. Blue `D` is a duplicate ACK; `S` means the ACK contains a SACK
  block. A packet with SACK takes precedence over its duplicate ACK label.
- **X** is shown only for a sequence gap with duplicate ACK or SACK evidence.
  It means an inferred missing range, not a measured physical loss location.
- The link rate is a user-supplied model parameter. The app calculates
  serialization time and bandwidth-delay product; it does not infer link speed
  from the PCAP.
- RTT uses the long handshake leg when the capture point can be inferred; the
  median TShark ACK RTT sample is a fallback. Neither measures individual
  one-way delays. Override the result if you have a better measured RTT.
- The first 5,000 packet rows are listed while up to 100,000 packets animate.
  The default PCAP size limit is 256 MiB. For large captures, split or filter
  before loading, or raise `MAX_PCAP_BYTES` with enough container memory.

The interface is intended for an isolated lab or a trusted reverse proxy.
It does not include user authentication. File selection is constrained to the
mounted directory and TShark runs without shell interpolation.

## Development

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt pytest
pytest -q
PCAP_DIR=./pcaps python app.py
```
