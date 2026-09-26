# PacketTrain: TCP conversations, explained

Status: agreed product direction and implementation specification, 2026-09-26.

## Purpose and current status

Turn PCAPs into an evidence-based explanation of a TCP conversation: what the endpoints did, where time was spent, and which client, server, or network explanations the capture supports. Serve both troubleshooting and classroom demonstrations.

Preserve PacketTrain's existing file-selection workflow and packet animation. Add interactive graphs inspired by [tcptrace-ng](https://github.com/phreakocious/tcptrace-ng), behavior analysis, statistics, endpoint fingerprints, and synchronized navigation.

The existing application already uses TShark for packet extraction, handshake-based capture-side estimates, basic behavior classification, and animated replay. See the repository README for current behavior. The [interactive prototype](packettrain-prototype.html) is a standalone design preview, not an implemented analysis backend. Download it and open it in a browser; GitHub's file view displays its source.

Prototype numbers and packets are synthetic. Its replay fixture is separate from its simplified graph fixtures. Some interactions demonstrate the intended design without implementing a complete shared state model. Endpoint fingerprinting is specified here but is not present in the prototype. Do not use prototype output as a packet-analysis result or copy its stacked demonstration scripts into production.

## Workspace and navigation

Retain capture selection from the mounted PCAP directory, Refresh files, stream selection, and manual overrides. Select a capture once, then use the same selected conversation throughout the workspace.

| View | Purpose |
| --- | --- |
| Conversations | Stream list, endpoint roles, primary and secondary behavior |
| Graphs | Time-sequence, throughput, ACK timing, outstanding bytes, receive window |
| Statistics | Directional counters, bursts, ECN, delay and congestion evidence |
| Behavior | Phases, classifier evidence, alternatives, transport symptoms |
| Endpoints | Client/server passive fingerprints and capture-position evidence |
| Packet replay | Animation, vertical bounce chart, idle compression, packet table |

Use one central selection state: capture ID, stream ID, direction, selected frame, cursor time, selected time interval, playback mode/speed, capture-side inference, and manual overrides. All views subscribe to it. Changing streams clears incompatible frame and range selections. Preserve explicit user preferences separately from inferred results.

Use original capture timestamps for computations. Zooming, animation speed, and idle compression must never change stored timestamps, measured durations, or statistics. Clearly distinguish whole-stream statistics from selected-range statistics.

## Automatic capture-position detection

Default the capture-point selector to **Auto-detect**. Run inference per stream, not once for the entire file. Results: near client, near server, intermediate/uncertain, or unknown. Show supporting observations and allow manual override.

1. Identify the initiator from SYN without ACK. This establishes a transport role, not capture proximity or application role. Handle simultaneous open and missing SYNs as ambiguous.
2. Match SYN, SYN-ACK, and completing ACK by endpoints and sequence/ACK relationships. They need not be consecutive file rows. Distinguish retransmitted attempts and reused tuples.
3. Calculate both intervals: delta12 = SYN-ACK time minus SYN time; delta23 = completing ACK time minus SYN-ACK time.
4. A much larger delta12 suggests near client; a much larger delta23 suggests near server. Similar values do not establish an endpoint location. Ratios and absolute thresholds are configurable heuristics, to be validated against known-position captures.
5. Combine timing with observed TTL or IPv6 hop limit. Consider initial-value candidates 64, 128, and 255, with fingerprint-informed alternatives. An observed 64 or 128 supports proximity only if the initial-value hypothesis is credible. A value of 63 or 127 can suggest one routed hop. Never label TTL alone as proof.
6. Account for timestamp resolution, host response delay, asymmetric paths, retransmissions, merged captures, and TCP proxies. Conflicting evidence reduces confidence or yields unknown.

NAT does not change who initiated a transport connection. Private/public addressing alone does not establish NAT or capture position. Confirm translation using corresponding observations across interfaces/captures or supplied mapping metadata. Preserve original and translated tuples where established. A TCP-terminating proxy creates separate transport legs; do not merge them as if they were ordinary NAT.

Show observed handshake intervals separately from an inferred endpoint RTT. The larger interval approximates endpoint RTT only when endpoint proximity is credible. Do not apply that shortcut universally to an intermediate capture. RTT/2 in animation is an explicitly symmetric-path model, not measured one-way delay. If position or timing is unknown, retain an observed-event chart without invented precise remote times.

## Graphs and packet evidence

Provide time-sequence with cumulative ACK and advertised receive-window edge, directional throughput, data-to-ACK samples, outstanding payload bytes, and receive-window history. Make units and accounting layers explicit. Label capture-record sizes separately from wire-packet sizes.

Graphs support pan/zoom and selecting a time range. Selecting a graph event highlights its frame in the packet table. Selecting a table row seeks replay and highlights graph evidence. Retain access to raw flags, sequence/ACK values, option fields, and decoder annotations.

TShark is the initial decoding foundation. tcptrace-ng demonstrates converting tcptrace output into interactive Plotly graphs; adopting that backend is optional, not a prerequisite. Evaluate output consistency, licensing, tunnel support, and maintenance before integrating another engine.

## Statistics and interpretation

Every result carries scope/direction, units, accounting basis, method, sample count, evidence frame references, and validity limitations. Unknown is distinct from zero.

| Measurement | Required handling |
| --- | --- |
| Unique payload | Deduplicate TCP sequence ranges; handle wraparound and partial overlap |
| Maximum observed flight | Unique sent payload not cumulatively acknowledged; report this as observed outstanding data, not exact cwnd or RFC pipe estimate |
| Largest burst | Consecutive same-direction payload records under a disclosed gap threshold; report bytes, records, span, and sensitivity to threshold |
| Receiver window | Apply negotiated scale to eligible packets; SYN window itself is unscaled; unknown scaling remains unknown |
| Retransmissions/SACK/duplicate ACKs | Preserve decoder evidence and distinguish observation from physical loss attribution |
| ECN | Directional Not-ECT, ECT(0), ECT(1), CE counts; negotiation mode; mode-aware feedback interpretation |
| ACK intervals | Exclude ambiguous retransmission matches; report baseline, percentiles, sample count and exclusions |
| Excess delay | ACK interval minus defensible baseline, labeled candidate queueing evidence |

Exact sender cwnd is not carried in the ordinary TCP header. Report it as unavailable without endpoint telemetry. Burst size is not a congestion-window measurement. Application supply, receiver window, pacing, and congestion control can all constrain observed flights.

### ECN and congestion evidence

Determine negotiation mode before interpreting flags. Under Classic ECN, separate SYN negotiation bits from later ECE/CWR signaling. Repeated ECE ACKs can refer to the same congestion episode. CWR is sender signaling, not a direct measurement of the new cwnd. Implement AccECN counter semantics separately; unknown or unsupported modes must not silently use Classic ECN interpretation. Record CE at the capture point and account for tunnel-layer context.

CE fraction uses CE / (ECT(0) + ECT(1) + CE) over a declared direction and scope. No eligible samples means N/A. Zero CE does not exclude congestion elsewhere or in non-ECN traffic.

Present congestion evidence as insufficient, weak, supporting, or strong explicit signaling. Distinguish explicit marking from an inference that congestion caused the user's performance problem. Correlate sustained excess delay, recovery events, rate changes, and ECN in the same interval. No fabricated percentages: a numeric congestion probability requires a calibrated model and labeled validation set.

### Burst rate and probable minimum bandwidth

First report observed burst dispersion rate. For consistently timestamped equal-size records, measure bytes after the first record divided by last-minus-first timestamp span; document how variable record sizes and timestamp conventions are handled. Include packet count and interval rather than hiding the denominator.

Do not equate a fast local burst with bottleneck capacity or available bandwidth. Sender captures can precede NIC transmission. Receiver-side spacing can be compressed by downstream queues; offload and coarse timestamps can produce unrealistic rates. Require repeated qualified trains and explicit assumptions before presenting any probable capacity estimate. Otherwise display **Not established**. Do not subtract guessed queueing delay from a burst span to inflate the estimate.

Excess ACK delay includes possible forward/reverse queueing, receiver ACK policy, path changes, and host scheduling. A single capture cannot uniquely locate a queue. Do not label the full excess as measured network queueing.

## Conversation behavior

Build on the existing rules before adding a trained classifier. Use unique payload bytes, directional balance, turn-taking, burst sizes, idle fraction, interval regularity, connection lifetime, and setup/teardown state. ACK-only packets do not count as application turns. PSH is not a message delimiter.

| Pattern | Evidence |
| --- | --- |
| Bulk download/upload | Sustained payload dominated by one direction |
| Request/response-like | Alternating payload bursts and turnarounds |
| Interactive exchange | Small bidirectional bursts with irregular pauses |
| Periodic polling | Repeating exchanges with stable recurrence intervals |
| Heartbeat-like | Tiny repetitive application payloads, distinct from TCP keepalives |
| Notification-like | Payload resumes after idle without an immediately preceding peer payload burst |
| Chunked delivery | Repeated large bursts separated by quiet periods |
| Continuous bidirectional | Substantial overlapping payload in both directions |
| Connection churn | Repeated short connections, evaluated across related flows |
| Mixed/indeterminate | Competing patterns, missing evidence, or phase changes |

Use protocol-decoded transactions when available. Encrypted HTTP/2 multiplexing prevents reliable request boundaries from direction changes alone. A bulk-download pattern does not prove a file download or distinguish encrypted video.

Detect phases within a stream: setup, small exchange, bulk transfer, payload pause, idle, periodic activity, and teardown. Each phase has time bounds, label, evidence, alternatives, and frame references. Thresholds are versioned analysis settings, not universal TCP constants.

Keep transport symptoms separate from behavior: receiver flow-control stall, recovery observed, ACK-paced delivery, possible application pause, possible queue buildup, and connection failure. ACK-paced traffic alone does not prove cwnd limitation. A response gap alone does not establish server CPU delay.

NFStream is a useful reference for directional timing/size features and plugins. It is optional; do not introduce another parser solely to reproduce fields already available from TShark.

## Passive endpoint fingerprinting

Estimate client and server stack families separately using SYN and SYN-ACK evidence: ordered TCP options including padding, raw initial window, window scale, MSS, inferred initial TTL, IP/TCP quirks, and timestamp behavior. A server SYN-ACK is affected by options offered by the client; match against appropriate response signatures.

Start with a p0f-style signature and a versioned, maintainable signature database. Show observed fields even if no OS label matches. Report candidate families, match quality, alternatives, supporting frames, and cross-connection consistency. Exact signature match does not guarantee a unique OS or version. Do not infer uptime directly from arbitrary timestamp values.

A terminating proxy exposes its own stack. MSS clamping, normalization, configuration, and shared/NAT addresses can alter or mix observations. Fingerprint changes across the same IP are evidence to investigate, not proof of a backend change. JA4T/JA4TS are optional grouping formats; review their specific license before reuse. Active probing is outside this passive-PCAP feature.

## Replay, bounce chart, and idle compression

The vertical bounce chart has client on the left, server on the right, and time progressing downward. Packet arrows slope downward to their destinations. Preserve captured observations and visibly identify inferred remote timing. Show SYN, SYN-ACK, ACK, PSH, FIN, RST, duplicate ACK, SACK, and retransmission evidence. Large captured records remain single records unless real segmentation is known.

Place the behavior-over-time selector above the chart. One selected time and range coordinates behavior, chart, graph, packet table, and animation.

| Action | Result |
| --- | --- |
| Click arrow or packet row | Pause, seek to frame, highlight all corresponding evidence |
| Click behavior phase | Select its interval and seek to phase start across views |
| Drag chart time range | Select that interval for graph inspection and replay |
| Play selection | Stop at selected interval end |
| Click compressed gap | Expand and offer replay without skipping |
| Full conversation | Clear range restriction without altering data |

Provide three modes: Faithful preserves timing at selected speed; Smart skip compresses qualified idle intervals; Fast review compresses long gaps but labels transport waits explicitly.

Default to Smart skip. Suggested trigger: a quiet gap would exceed two seconds of wall-clock playback at the selected speed. Finish any in-flight animation, show a roughly 0.8-second transition, then resume just before the next packet. Use the exact neutral label **Idle interval compressed · 12.4 s**, replacing the number with the actual interval. No meme or audio.

Smart skip must not treat unresolved outstanding bytes, zero-window recovery, handshake retries, or retransmission waits as harmless idle. If visibility is insufficient to classify the gap, preserve it. Even qualified idle may contain application delay, so always retain duration, boundaries, and an expansion option. Fast review may compress a transport wait only with an explicit wait label. Neither mode drops packets or rewrites timestamps. Mark timeline discontinuities across both endpoint lanes.

## Implementation sequence

1. Normalize decoder output and shared selection state. Preserve current capture-directory protections, subprocess argument handling, reverse-proxy operation, limits and unprivileged runtime.
2. Add automatic capture-position evidence and overrides. Keep inference separate from observed facts.
3. Build linked graphs, bounce chart, replay controls, and idle compression from the same event model.
4. Add statistics with validity/exclusion reporting and directional accounting.
5. Extend behavior rules and phase segmentation with explainable evidence.
6. Add passive endpoint signatures and a versioned fingerprint database.
7. Add optional backend integrations and cross-capture matching only after the core workflow is coherent.

Avoid monolithic UI scripts. Separate packet extraction, TCP accounting, capture inference, behavior rules, fingerprints, and presentation. Cache analysis by capture identity, engine/rule versions, and relevant settings. Manual animation settings must not overwrite measured observations. Dense graphs may downsample rendering while retaining full-resolution evidence and calculations.

## Acceptance criteria

Use deterministic fixtures with known expected fields plus representative real captures. Tests must cover:

- Near-client and near-server handshakes; equal legs; delayed endpoint response; missing/retransmitted handshake; simultaneous open; contradictory TTL.
- NAT tuples across two observations and a TCP proxy with separate connections. No NAT claim from private addresses alone.
- Sequence wraparound, partial retransmission overlap, missing direction, scale negotiation, SYN unscaled windows, zero-window recovery and offloaded records.
- Classic ECN negotiation excluded from congestion counts; repeated ECE; AccECN mode; unknown mode and zero eligible denominator.
- ACK-only traffic excluded from application turns; mixed phases; encrypted multiplexing remains qualified; missing evidence returns unknown.
- Arrow, phase, packet and graph selections agree; playback stops at range end; changing stream resets stale selections.
- Smart skip preserves unresolved transport waits and packets already animating; expanding a gap restores faithful timing; original durations and statistics never change.
- Keyboard access, narrow-screen layout, legible arrow labels, and large-capture rendering without freezing controls.

The production feature is complete only when actual PCAP-derived data drives all linked views. Synthetic mockup success is not an analysis validation.

## References

- [PacketTrain current application](../README.md)
- [tcptrace-ng](https://github.com/phreakocious/tcptrace-ng)
- [Wireshark Flow Graph](https://www.wireshark.org/docs/wsug_html_chunked/ChStatFlowGraph.html)
- [Wireshark TCP analysis](https://www.wireshark.org/docs/wsug_html_chunked/ChAdvTCPAnalysis.html)
- [NFStream feature/API documentation](https://www.nfstream.org/docs/api)
- [p0f signatures and implementation](https://github.com/p0f/p0f)
- [JA4 family and licenses](https://github.com/FoxIO-LLC/ja4)
- [RFC 3168: Classic ECN](https://www.rfc-editor.org/rfc/rfc3168.html)
- [RFC 9768: AccECN](https://www.rfc-editor.org/rfc/rfc9768.html)
- [RFC 9293: TCP](https://www.rfc-editor.org/rfc/rfc9293.html)
- [RFC 3022: Traditional NAT](https://www.rfc-editor.org/rfc/rfc3022.html)
- [RFC 5136: Network capacity terminology](https://www.rfc-editor.org/rfc/rfc5136.html)
- [RFC 9113: HTTP/2 multiplexing](https://www.rfc-editor.org/rfc/rfc9113.html)

References inform the measurements and constraints; the UI, thresholds, architecture, and implementation sequence above are proposed PacketTrain design decisions.
