# PacketTrain

Browser animation of TCP streams from PCAP and PCAPNG files. Packet launch times,
sizes, flags, duplicate ACKs, SACK blocks, and retransmission indicators come
from TShark. Motion across the track uses half of a measured RTT as an
illustrative one-way time when only one capture point is available.

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

- Dot launch times use packet timestamps in the selected capture.
- Green is data; purple indicates PSH. Red `R` marks a TShark retransmission
  indicator. Blue `D` is a duplicate ACK; `S` means the ACK contains a SACK
  block. A packet with SACK takes precedence over its duplicate ACK label.
- **X** is shown only for a sequence gap with duplicate ACK or SACK evidence.
  It means an inferred missing range, not a measured physical loss location.
- The link rate is a user-supplied model parameter. The app calculates
  serialization time and bandwidth-delay product; it does not infer link speed
  from the PCAP.
- RTT uses the median TShark ACK RTT sample when available, otherwise the
  SYN-to-SYN-ACK interval. Neither measures individual one-way delays.
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
