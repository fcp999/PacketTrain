# PacketTrain

Browser animation of TCP streams from PCAP and PCAPNG files. Packet timestamps,
sizes, flags, duplicate ACKs, SACK blocks, and retransmission indicators come
from TShark. The app compares the two handshake legs to infer whether a capture
was taken near the client or server. If that is ambiguous, choose the capture
point manually. RTT uses the long handshake leg when classification is clear,
or TShark's ACK RTT samples as a fallback. You can override RTT in the UI.

The stream menu also classifies **traffic patterns** from payload direction,
volume, timing, and turn-taking: bulk download/upload, periodic polling,
interactive exchange, sparse notifications, request/response, and control-only
connections. Each label includes its evidence and confidence. A bulk download
pattern does not prove a file transfer; encrypted video or another large
response can look similar. The classifier does not inspect payload contents.

Local-origin packets leave the capture endpoint at their captured timestamp.
Far-origin packets leave the remote endpoint at timestamp minus estimated
one-way time, then reach the capture endpoint at the captured timestamp.
The one-way estimate is RTT/2. It assumes roughly symmetric paths and does not
claim to measure actual one-way delay.

## HTTPS / TLS view

When TShark sees a TLS ClientHello or ServerHello in a TCP stream, the flow
page shows visible handshake milestones, offered SNI and ALPN, and the traffic
pattern of later ciphertext. ClientHello to ServerHello is an observed
interval: at a client-side capture it includes the network round trip and
server handling; near the server it mostly reflects server handling. The
ServerHello to first server ciphertext interval is an encrypted-handshake
phase estimate, not a pure key-exchange timer.

The encrypted behavior label describes traffic shape, such as bulk download,
upload, periodic polling, or interactive exchange. It cannot reveal the HTTP
method, URL, status, file type, or an exact request boundary. TLS 1.3 encrypts
most handshake messages; its first ciphertext records can contain handshake
traffic. SNI can be absent or protected by ECH, and the ClientHello ALPN list
is an offer, not proof of the protocol selected. Captures that begin after the
hello show no TLS card.

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
- Data records are length-scaled rectangles. Their width represents modeled
  serialization time relative to estimated one-way transit, with limits to
  keep the view readable. `G` marks a captured payload over 1460 bytes that
  may represent GRO/LRO aggregation or jumbo traffic. It is one capture
  record, not a proven count of wire packets.
- Green is data; purple indicates PSH. SYN, SYN+ACK, FIN, and RST are labeled
  on their moving control dots. Red `R` marks a TShark retransmission
  indicator. Blue `D` is a duplicate ACK; `S` means the ACK contains a SACK
  block. A packet with SACK takes precedence over its duplicate ACK label.
- **X** is shown only for a sequence gap with duplicate ACK or SACK evidence.
  It means an inferred missing range, not a measured physical loss location.
- The link rate is a user-supplied model parameter, defaulting to 1 Gb/s. The
  app calculates serialization time for a typical captured data frame and
  bandwidth-delay product; it does not infer link speed from the PCAP. Set it to
  the actual link under test when the model matters. If the modeled first
  flight would take much longer to serialize than the observed frame timestamp
  span, the interface flags that mismatch. Capture timestamps can precede
  physical transmission.
- Advertised MSS, first data flight, and large capture-record counts come from
  the selected stream. Large records can be caused by jumbo MTU, GRO/LRO, or
  capture before segmentation. The app does not assert their on-wire count.
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
