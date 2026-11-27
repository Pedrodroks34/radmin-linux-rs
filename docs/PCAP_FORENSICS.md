# PCAP Forensics — Consolidated Evidence (Draft)

**Project:** Radmin VPN Linux client (Rust, independent)
**Capture directory:** `claude-handoff/pcaps/`
**Capture files analyzed:** 6 (.pcap/.pcapng)
**Sources consolidated:** 5 documents (see ## Sources)
**Language:** English
**Status:** Draft — evidence-preserving consolidation; conflicts recorded, not resolved

---

## 1. Capture Inventory

Six capture files were analyzed. The inventory below is reproduced verbatim from `PCAP_FORENSICS_REPORT.md` §2 (packet counts, sizes, durations, and timestamps use the source's formatting, including European decimal separators).

| File | Type | Packets | Size | Duration | First capture | Last capture | Interface(s) | Capture filter |
|---|---|---|---|---|---|---|---|---|
| `radmin_17301.pcap` | pcapng | 85 | 30 kB | 55,86 s | 31/10/2026 18:06:10 | 31/10/2026 18:07:06 | virbr0 | host 192.168.122.77 |
| `radmin-connect.pcapng` | pcapng | 2.216 | 3,18 MB | 47,94 s | 06/11/2026 14:22:04 | 06/11/2026 14:22:52 | enp7s0, radminvpn0 | (none) |
| `radmin-mine-host.pcapng` | pcapng | 50.249 | 31 MB | 67,72 s | 06/11/2026 14:32:56 | 06/11/2026 14:34:03 | enp7s0, radminvpn0 | (none) |
| `radmin-mine.pcapng` | pcapng | 20.681 | 7,34 MB | 44,00 s | 06/11/2026 14:31:21 | 06/11/2026 14:32:05 | enp7s0, radminvpn0 | (none) |
| `radmin_vm2.pcap` | pcapng | 1.147 | 196 kB | 118,39 s | 31/10/2026 18:08:57 | 31/10/2026 18:10:56 | virbr0 | host 192.168.122.77 |
| `radmin_vm.pcap` | pcapng | 6.364 | 21 MB | 114,64 s | 31/10/2026 18:05:28 | 31/10/2026 18:07:23 | virbr0 | host 192.168.122.77 |

**Cross-source discrepancies in the inventory (recorded, not resolved):**
- `EVIDENCE_INDEX.md` §1 lists `radmin_17301.pcap` at 1,258,496 bytes and describes its role as "TCP traffic capture on ports 17301 and 17351 (Relay)"; `PCAP_FORENSICS_REPORT.md` §2 lists the same file at 30 kB, 85 packets, capture filter `host 192.168.122.77`. Both values are preserved verbatim; see ## Evidence Limitations.
- `EVIDENCE_INDEX.md` §3 indexes packets up to #839 in `radmin_vm2.pcap` (1,147 packets — consistent) and frames #688..#710 in `radmin_17301.pcap`, which the report lists as 85 packets — inconsistent packet ranges are preserved as reported.

No original `.pcap`/`.pcapng` file was modified. SHA-256 hashes are available in `capinfos` metadata (consulted individually, not reproduced here).

---

## 2. Control-Channel Flows and Framing

### 2.1 TCP/17301 — Primary Control

**Servers:** `148.113.190.78:17301` (primary control), `198.244.203.247:17301` (alternative control). `45.162.230.182:17301` also appears (report §4.1: captures `radmin_vm`, `radmin_vm2`).

**Framing (CONFIRMED):** `[4-byte big-endian length][payload]`. The length field represents only the payload size; it excludes the 4-byte header itself. `tcp.len = 4 + length`.

**Validation (radmin-connect.pcapng):**

| Frame | Length field | Value | tcp.len | Expected | Match |
|---|---|---|---|---|---|
| 77 | `00 00 00 c0` | 192 | 196 | 4 + 192 = 196 | YES |
| 80 | `00 00 00 20` | 32 | 36 | 4 + 32 = 36 | YES |
| 81 | `00 00 01 00` | 256 | 260 | 4 + 256 = 260 | YES |
| 88 | `00 00 00 30` | 48 | 52 | 4 + 48 = 52 | YES |
| 94 | `00 00 01 50` | 336 | 340 | 4 + 336 = 340 | YES |

**Byte evidence:**

- Frame 77: `00 00 00 c0 | 10 f9 bf 00 3c e2 ...` (192 bytes of payload)
- Frame 80: `00 00 00 20 | c7 f5 78 26 ...` (32 bytes of payload)
- Frame 81: `00 00 01 00 | 65 93 01 46 ...` (256 bytes of payload)

**Fragmentation (messages larger than MSS are fragmented across TCP segments):**

- Frame 100: length = 0x0a20 = 2592, first segment 1440 bytes (4 header + 1436 payload); frame 101: continuation with 1156 bytes of payload (no new length prefix); 1436 + 1156 = 2592.
- Frame 105: length = 0x1140 = 4416, tcp.len = 4420.

**Connection flow (radmin-connect.pcapng):**

1. TCP SYN → `148.113.190.78:17301` (source port 44340)
2. SYN-ACK, ACK (handshake complete)
3. Bidirectional data with PSH+ACK
4. New TCP connection → `198.244.203.247:17301` (alternative server)
5. New TCP connection → `148.113.190.78:17301` (new source port 44342)

**Observed connection tuples:**

- `192.168.15.15:44340` ↔ `148.113.190.78:17301`
- `192.168.15.15:57924` ↔ `198.244.203.247:17301`
- `192.168.15.15:44342` ↔ `148.113.190.78:17301`
- `192.168.122.77:56923` → `148.113.190.78:17301` (`radmin_vm.pcap` / `radmin_17301.pcap`, T+42s per report timeline)

Wireshark detected TPKT in some frames (possible dissector misinterpretation — report §5.1).

**Classification:** CONFIRMED framing on TCP/17301, validated in multiple frames; TCP fragmentation occurs for large messages; multiple parallel connections are used.

### 2.2 TCP/17351 — Alternative Control

**Framing:** Same `[4-byte big-endian length][payload]` format as TCP/17301.

**Server:** `45.162.230.182:17351` (`radmin_vm.pcap` only).

**Internal payload structure:**

| Offset | Field | Size |
|---|---|---|
| 0x00 | `10 00 00 04` — message version/type (constant in all observed messages) | 4 bytes |
| 0x04 | Sequence number — big-endian, increments (2, 3, 4, 5, 6 observed) | 4 bytes |
| 0x08+ | Variable payload | Variable |

**Validation (radmin_vm.pcap):**

| Frame | Length field | Value | tcp.len | Expected | Match |
|---|---|---|---|---|---|
| 5487 | `00 00 00 0c` | 12 | 16 | 4 + 12 = 16 | YES |
| 5493 | `00 00 00 f5` | 245 | 249 | 4 + 245 = 249 | YES |
| 5494 | `00 00 00 cb` | 203 | 207 | 4 + 203 = 207 | YES |
| 5501 | `00 00 00 cc` | 204 | 208 | 4 + 204 = 208 | YES |

Example payload (frame 5486): `10 00 00 04 00 00 00 03 60 00 00 bf ...` (length 0xcb = 203, tcp.len = 207).

**Sequence numbers (radmin_vm.pcap):**

| Frame | Direction | Sequence field | Value |
|---|---|---|---|
| 5487 | Server → Client | `00 00 00 04` | 4 |
| 5493 | Server → Client | `00 00 00 02` | 2 |
| 5494 | Server → Client | `00 00 00 03` | 3 |
| 5501 | Server → Client | `00 00 00 04` | 4 |
| 5502 | Client → Server | `00 00 00 05` | 5 |
| 5509 | Client → Server | `00 00 00 06` | 6 |

Sequence numbers are not strictly monotonic (frame 5487 seq = 4, frame 5493 seq = 2), suggesting either multiple independent streams or a different field meaning — INCONCLUSIVE. Purpose of TCP/17351 (control, synchronization, key exchange) is INCONCLUSIVE; the hypothesis that it is a key synchronization channel has no direct evidence of cryptographic material.

**Classification:** CONFIRMED framing; purpose INCONCLUSIVE.

---

## 3. TCP Relay

- `EVIDENCE_INDEX.md` §3 packet index: `radmin_17301.pcap` packets #688..#710 `192.168.122.77:49502 <-> 198.244.203.247:17351`, TCP Relay — establishment of the TcpRelay forwarding tunnel and exchange of E2E-encrypted data.
- Static references (`EVIDENCE_INDEX.md` §2, Front 5): `RvROLClient.dll!0x1004d220` establishes the relay tunnel on port 17351; `RvControlSvc.exe!0x43fb60` transport enum conversion: 0 -> "TCP", 1 -> "UDP", 2 -> "TcpRelay".
- PCAP-level relay hypothesis: flow `192.168.15.15:43139 ↔ [IP_PUBLICO_MASCARADO}:58358` (UDP, 10.156 packets, 3.1 MB) in `radmin-mine-host.pcapng`; no TLV structure identified in the first bytes; port 58358 is not the standard P2P port 9993. May be relay traffic, P2P with another peer, or unrelated background traffic. Classification: HYPOTHESIS — not confirmed as Radmin relay.
- Control server → relay on TCP/17301/17351: HYPOTHESIS; no evidence of relay on control servers (flow map §Hypothetical).

---

## 4. STUN and NAT

### 4.1 STUN Servers (Non-Standard Radmin Ports)

These ports are NOT standard STUN ports (3478).

| Port | Servers | Captures |
|---|---|---|
| 17309 | 162.19.169.168 | radmin_vm2.pcap |
| 17310 | 162.19.169.168, 198.244.203.247 | radmin_vm2.pcap |
| 17341 | 148.113.190.78 | radmin_vm.pcap |
| 17342 | 148.113.190.78, 15.204.183.160 | radmin_vm.pcap |
| 17347 | 148.113.1.139 | radmin_vm2.pcap |
| 17348 | 148.113.190.78, 148.113.1.139, 135.181.75.9 | radmin_vm2.pcap |
| 17349 | 148.113.190.78, 148.113.1.139, 135.181.75.9 | radmin_vm2.pcap |
| 17357 | 135.181.75.11, 135.181.75.20 | radmin_vm.pcap |
| 17358 | 135.181.75.11, 135.181.75.20 | radmin_vm.pcap |

Endpoints (`PCAP_FORENSICS_REPORT.md` §4.2): `135.181.75.11:17357`, `135.181.75.20:17358`, `148.113.190.78:17341`, `148.113.190.78:17342`, `15.204.183.160:17342`, `162.19.169.168:17309/17310` — Binding Request sent, Binding Response received.

### 4.2 STUN Message Structure

**Binding Request:** 20 bytes UDP payload — Type 2 bytes (`00 01` = Binding Request), Length 2 bytes (`00 00` = no attributes), Transaction ID 16 bytes. No magic cookie (`0x2112A442` absent).

Raw example (frame 5477, `radmin_vm.pcap`): `192.168.122.77:54527 → 135.181.75.11:17357`

```
00 01 00 00 24 df 38 03 cb e7 64 ea 10 67 38 b6 1d 31 4c 66
```

Transaction ID `24df3803cbe764ea106738b61d314c66`.

**Binding Response:** 56 bytes UDP payload (`udp.length` = 64 minus 8-byte UDP header; `frame.len` = 98 is the Ethernet frame size — sources disagree, see ## Prior-Round Corrections). Type `01 01`, Length `00 24` (36 bytes of attributes).

Raw example (frame 5489, `radmin_vm.pcap`):

```
01 01 00 24 24 df 38 03 cb e7 64 ea 10 67 38 b6 1d 31 4c 66
00 01 00 08 00 01 d4 ff bb 3b c7 27
00 04 00 08 00 01 00 00 00 00 00 00
05 00 08 00 01 00 00 00 00 00 00 00
```

Decoded attributes: Type 0x0001 MAPPED-ADDRESS Length 8, IPv4, Port 0xd4ff = 54527, IP 0xbb3bc727 = 187.59.199.39; Type 0x0004 SOURCE-ADDRESS Length 8, Port 0, IP 0.0.0.0; Type 0x0005 CHANGED-ADDRESS Length 8, Port 0, IP 0.0.0.0. Transaction ID matches the request.

### 4.3 Observed STUN Frames

| Frame | Source | Dest | Port | Type | Transaction ID | Capture |
|---|---|---|---|---|---|---|
| 5477 | 192.168.122.77:54527 | 135.181.75.11 | 17357 | Binding Request (0x0001) | `24df3803cbe764ea106738b61d314c66` | radmin_vm.pcap |
| 5480 | 192.168.122.77:54527 | 135.181.75.11 | 17357 | Binding Request (0x0001), retry | same | radmin_vm.pcap |
| 5489 | 135.181.75.11:17357 | 192.168.122.77:54527 | 17357 | Binding Response (0x0101) | same | radmin_vm.pcap |
| 5551 | 192.168.122.77:54530 | 148.113.190.78 | 17341 | Binding Request (0x0001) | — | radmin_vm.pcap |
| 5575 | 148.113.190.78:17341 | 192.168.122.77:54530 | 17341 | Binding Response (0x0101) | — | radmin_vm.pcap |
| 676 | 192.168.122.77:54533 | 162.19.169.168 | 17309 | Binding Request | `676387424d688c31c2860788a26eed38` | radmin_vm2.pcap |
| 678 | 192.168.122.77:54533 | 162.19.169.168 | 17309 | Binding Request | same | radmin_vm2.pcap |

Retry pattern: two Binding Requests sent with ~99–100 ms interval (automatic retry due to no response on the first attempt).

`EVIDENCE_INDEX.md` §3 additionally lists `radmin_vm2.pcap` #796 `192.168.122.77:54536 -> 198.244.203.247:17348` UDP STUN Binding Request (`0x0001`) and #839 `198.244.203.247:17348 -> 192.168.122.77:54536` STUN Binding Response returning reflexive IP `<CLIENT-PUBLIC-IP>:54536`. The report's STUN server table does not list `198.244.203.247:17348`; this cross-reference is preserved as reported and not reconciled.

### 4.4 Protocol Classification

- **CONFIRMED:** STUN-like Binding Request/Response observed on 9 non-standard ports.
- **REFUTED:** this is NOT standard RFC 5389 STUN — no magic cookie, 16-byte transaction ID instead of 12.
- **INCONCLUSIVE:** whether this is a proprietary STUN variant or a different protocol using STUN-like formatting. Standard STUN libraries may not work without modification.

### 4.5 Size Confusion

Documents alternate between 98 bytes (`frame.len` / Ethernet frame size) and 56 bytes (UDP payload) for Binding Responses. Resolution per the audit: 98 bytes = frame length; 56 bytes = UDP payload. Both measurements are preserved; documentation must state which is meant.

### 4.6 NAT

NAT type (Full Cone, Restricted Cone, Port-Restricted, Symmetric): INCONCLUSIVE — single STUN response per server is insufficient; no request/response pairs from multiple servers for the same local address.
Hole punching: transmission attempts CONFIRMED; successful NAT traversal HYPOTHESIS.

---

## 5. Teredo

**Server:** `20.201.205.4:3544` (public Microsoft Teredo server).

- Frame 708 (`radmin_vm.pcap`): `192.168.122.77:54778 → 20.201.205.4:3544`, Teredo Router Solicitation (ICMPv6 type 133); nonce `8acf0087ddea3402`.
- Frame 169 (`radmin_vm2.pcap`): same source, destination, and port; Router Solicitation.
- `EVIDENCE_INDEX.md` §3: `radmin_vm2.pcap` #10 `192.168.122.77 -> 20.201.205.4:3544` UDP Teredo — initialization packet of the IPv6-over-UDP Teredo tunnel.

The Teredo packet contains an ICMPv6 Router Solicitation from `fe80::ffff:ffff:fffe` to `ff02::2`. No Router Advertisement observed in response. No IPv6 encapsulated traffic beyond the Router Solicitation. DNS queries to Windows/MS domains (`api.msn.com`, `c.bing.com`, `config.edge.skype.com`, etc.) were also observed.

**Classification:** CONFIRMED that Teredo traffic was observed; likely Windows/Wine background traffic, NOT confirmed as Radmin-specific. No evidence that Radmin uses Teredo for its communications.

---

## 6. UDP/9993 and UDP/47836 Families

### 6.1 UDP/9993 Size Distribution (payload bytes)

| Payload size | radmin-mine | radmin-mine-host | radmin-connect | Total |
|---|---|---|---|---|
| 28 | 35 | 42 | 5 | 82 |
| 33 | 84 | 100 | 39 | 223 |
| 37 | 13 | 20 | 5 | 38 |
| 59 | 15 | 15 | 0 | 30 |
| 67 | 0 | 12 | 8 | 20 |
| 93 | 12 | 12 | 4 | 28 |
| 99 | 19 | 34 | 21 | 74 |
| 114 | 12 | 12 | 4 | 28 |
| 137 | 36 | 42 | 15 | 93 |
| 149 | 0 | 12 | 4 | 16 |
| 215 | 7 | 9 | 11 | 27 |
| 247 | 0 | 12 | 0 | 12 |
| 249 | 0 | 8 | 0 | 8 |
| 309 | 4 | 4 | 4 | 12 |
| 369 | 6 | 4 | 4 | 14 |
| 629 | 0 | 3 | 3 | 6 |
| 641 | 1 | 1 | 1 | 3 |

**Observation:** `radmin-mine` and `radmin-mine-host` have a concentrated distribution (28, 33, 137, 99). `radmin-connect` has a wider distribution including large sizes (629, 641), consistent with a control negotiation phase.

### 6.2 Message Families

**Family A — 137 bytes** (`udp.length` = 145). Example frame 116, `radmin-mine.pcapng`, interface 1, source `26.239.229.134:9993` → dest `26.172.178.79:9993`, `frame.len` = 179, `udp.length` = 145.

Complete hex dump (137 bytes):

```
0x00    25 2d ff 68 42 c3 84 70
0x08    e5 d4 c1 c5 bc 21 59 16
0x10    c8 0f 00 01 03 74 49 74
0x1c    bf 0f ed 01 0d 01 10 00
0x20    02 00 00 01 a1 b1 ea 42
0x28    91 21 59 16 c8 0f 00 2e
0x30    38 e9 0a 46 71 a7 7c fd
0x38    d8 81 06 57 ec 45 de 15
0x40    6c 7a 3e 5d 6c 86 65 7c
0x48    bb e4 53 9d 0b c3 69 5e
0x50    db 03 c5 ab 8b ef 20 1d
0x58    c6 ca 71 c4 dc a7 1d ba
0x60    4f cb cc 9f 54 b0 57 4d
0x68    0e 08 59 c1 af 78 4e 00
0x70    04 1a ac b2 4f 27 09 00
0x78    00 00 00 08 ea c9 0a 00
0x80    00 01 94 db 79 5b 4e 0b
0x88    2c
```

Deep-dive offset table (`PCAP_FORENSICS_DEEP_DIVE.md` §Front 02):

| Offset | Size | Bytes | Interpretation | Confidence |
|---|---|---|---|---|
| 0x00 | 4 | `25 2d ff 68` | Magic / message type | CONFIRMED |
| 0x04 | 4 | `42 c3 84 70` | Variable field (possible flags) | INCONCLUSIVE |
| 0x08 | 10 | `e5 d4 c1 c5 bc 21 59 16 c8 0f` | Session identifier (parts 1+2) | STRONG INDICATION |
| 0x12 | 2 | `00 01` | Message subtype | CONFIRMED |
| 0x14 | 8 | `03 74 49 74 bf 0f ed 01` | Variable field | INCONCLUSIVE |
| 0x1c | 4 | `0d 01 10 00` | Fixed field | CONFIRMED |
| 0x20 | 4 | `02 00 00 01` | Fixed field | CONFIRMED |
| 0x24 | 10 | `a1 b1 ea 42 91 21 59 16 c8 0f` | Repeated session ID + timestamp? | HYPOTHESIS |
| 0x2e | 48 | `00 2e 38 e9 ...` | Encrypted region | STRONG INDICATION |
| 0x5e | 12 | `1d ba c6 ca 71 c4 dc a7 1d ba 4f cb` | Unknown region | INCONCLUSIVE |
| 0x6a | 6 | `cc 9f 54 b0 57 4d` | Unknown | INCONCLUSIVE |
| 0x70 | 2 | `0e 08` | Unknown | INCONCLUSIVE |
| 0x72 | 2 | `59 c1` | Unknown | INCONCLUSIVE |
| 0x74 | 2 | `af 78` | Unknown | INCONCLUSIVE |
| 0x76 | 2 | `4e 00` | Unknown | INCONCLUSIVE |
| 0x78 | 2 | `00 00` | Possible TLV start | HYPOTHESIS |
| 0x7a | 4 | `00 08 ea c9` | Possible IP fragment | HYPOTHESIS |
| 0x7e | 2 | `0a 00` | Unknown | INCONCLUSIVE |
| 0x80 | 1 | `00` | Unknown | INCONCLUSIVE |
| 0x81 | 7 | `00 01 94 db 79 5b` | Unknown | INCONCLUSIVE |
| 0x88 | 1 | `4e` | Unknown | INCONCLUSIVE |
| 0x89 | 1 | `0b` | Unknown | INCONCLUSIVE |
| 0x8a | 1 | `2c` | Unknown | INCONCLUSIVE |

Third-round audit offset table (`PCAP_THIRD_ROUND_AUDIT.md` §Front 02):

| Offset | Size | Bytes | Interpretation | Confidence |
|---|---|---|---|---|
| 0x00 | 4 | `25 2d ff 68` | Magic / message type | CONFIRMED (observed constant) |
| 0x04 | 4 | `42 c3 84 70` | Variable field | INCONCLUSIVE |
| 0x08 | 10 | `e5 d4 c1 c5 bc 21 59 16 c8 0f` | Session identifier | STRONG INDICATION |
| 0x12 | 2 | `00 01` | Message subtype | CONFIRMED |
| 0x14 | 8 | `03 74 49 74 bf 0f ed 01` | Variable field | INCONCLUSIVE |
| 0x1c | 4 | `0d 01 10 00` | Fixed field | CONFIRMED |
| 0x20 | 4 | `02 00 00 01` | Fixed field | CONFIRMED |
| 0x24 | 10 | `a1 b1 ea 42 91 21 59 16 c8 0f` | Session ID repeated + timestamp? | HYPOTHESIS |
| 0x2e | 48 | `00 2e 38 e9 ...` (48 bytes) | Encrypted region | STRONG INDICATION |
| 0x5e | 12 | `1d ba c6 ca 71 c4 dc a7 1d ba 4f cb` | Unknown — was previously misidentified as TLV start | INCONCLUSIVE |
| 0x6a | 6 | `cc 9f 54 b0 57 4d` | Unknown | INCONCLUSIVE |
| 0x70 | 2 | `0e 08` | Unknown | INCONCLUSIVE |
| 0x72 | 2 | `59 c1` | Unknown | INCONCLUSIVE |
| 0x74 | 2 | `af 78` | Unknown | INCONCLUSIVE |
| 0x76 | 2 | `4e 00` | Unknown | INCONCLUSIVE |
| 0x78 | 2 | `04 1a` | Possible TLV start | HYPOTHESIS |
| 0x7a | 4 | `ac b2 4f 27` | Possible IP fragment | HYPOTHESIS |
| 0x7e | 2 | `09 00` | Unknown | INCONCLUSIVE |
| 0x80 | 2 | `00 00` | Unknown | INCONCLUSIVE |
| 0x82 | 1 | `00` | Unknown | INCONCLUSIVE |
| 0x83 | 7 | `00 08 ea c9 0a 00 00` | Unknown | INCONCLUSIVE |
| 0x8a | 1 | `01` | Unknown | INCONCLUSIVE |
| 0x8b | 4 | `94 db 79 5b` | Unknown | INCONCLUSIVE |
| 0x8f | 4 | `4e 0b 2c` (only 3 bytes, offset 0x8f–0x91) | — | — |

**Discrepancy in Family A offsets 0x78–0x83:** the complete hex dump above shows `00 00` at 0x78–0x79, `00 08 ea c9` at 0x7a–0x7d, `0a 00` at 0x7e–0x7f, and `00` at 0x80 — matching the deep-dive table. The audit's own offset table lists different bytes at 0x78–0x83 (`04 1a`, `ac b2 4f 27`, `09 00`, `00 00`, `00`, `00 08 ea c9 0a 00 00`) which match neither its hex dump nor the deep-dive table. All three renderings are preserved verbatim; the conflict is NOT resolved here — see ## Prior-Round Corrections and `RECONCILIATION.md`.

**Family B — 33 bytes** (`udp.length` = 41). Example frame 139, `radmin-mine.pcapng`, interface 0:

`b9 6b 32 c3 13 57 56 f8 77 8c de 71 90 21 59 16 c8 0f 08 af 22 1d ce fb 43 42 25 7e 46 9e 55 19 2f`

- Offset 0x08–0x0f: `90 21 59 16 c8 0f` — 6 bytes, possibly part of session identifier
- Offset 0x10–0x13: `08 af` — 2 bytes variable
- Last 4 bytes appear to be a checksum or trailer

**Family C — 28 bytes** (`udp.length` = 36). Example frame 187, `radmin-mine.pcapng`, interface 0:

`09 3e 08 ab b0 a6 17 91 e5 d4 c1 c5 bc 21 59 16 c8 0f 18 ac 77 1e 68 c7 9b e0 c5 0c`

- Offset 0x08–0x11: `e5 d4 c1 c5 bc 21 59 16 c8 0f` — complete 10-byte session identifier
- Offset 0x00–0x07: `09 3e 08 ab b0 a6 17 91` — variable field (8 bytes)
- Last 4 bytes: possibly checksum

**Family D — 99 bytes** (`udp.length` = 107). Example frame 143, `radmin-mine.pcapng`, interface 0:

`b5 29 7e d0 4f 09 38 8e e5 d4 c1 c5 bc 21 59 16 c8 0f 18 31 ff fc 43 50 cd d0 29 e4 01 23 d3 84 a7 22 26 26 3e 82 e6 91 14 40 58 97 3d 7d a7 0e 62 19 fe f1 22 b5 55 51 c5 b0 dd ff 79 3d 73 8b 17 dd 71 85 41 c4 20 37 fd 3c df 22 c8 4f ab d9 3d 4a 7c 5b 63 87 5f b1 6d 7e 4a 18 95 9d c0 f8 1c d1 b1`

- Contains session identifier `e5 d4 c1 c5 bc 21 59 16 c8 0f` in the same pattern

**Family E — 247–641 bytes** (connect phase). Large messages observed in `radmin-mine-host.pcapng` and `radmin-connect.pcapng` with session identifier present.

**Message families summary:**

| Family | Size | Common fields | Peers observed | Captures |
|---|---|---|---|---|
| A — Setup/complete | 137 bytes | Magic `25 2d ff 68`, session ID, TLV 0x0004 | `26.239.229.134` ↔ `26.172.178.79`, `192.168.15.15` ↔ [MASKED] | mine, mine-host |
| B — Short | 33 bytes | Partial session ID (6 bytes) | `192.168.15.15` ↔ `103.195.103.66` | mine, mine-host |
| C — Short keepalive | 28 bytes | Complete session ID (10 bytes) | `192.168.15.15` ↔ `25.33.236.186` | mine |
| D — Medium | 99 bytes | Complete session ID | `192.168.15.15` ↔ [MASKED] | mine |
| E — Large (connect) | 247–641 bytes | Complete session ID | [MASKED] ↔ `192.168.15.15` | mine-host, connect |

### 6.3 TLV Field `0x0004` (Peer IP + Port)

Byte sequence `00 04` followed by an IPv4 address and port in network byte order (big-endian) that match the UDP destination:

| Frame | Capture | Offset | Context |
|---|---|---|---|
| 116 | radmin-mine.pcapng | 0x6f–0x70 | `00 04` followed by `1a ac b2 4f 27 09` |
| 127 | radmin-mine.pcapng | 0x6f–0x70 | `00 04` followed by `b1 70 4f e2 27 09` |
| 117 | radmin-mine.pcapng | 0x6f–0x70 | `00 04` followed by `1a ac b2 4f 27 09` |

Frame 116 breakdown (offset 0x6f–0x76): `00 04` (possible TLV type), `1a ac b2 4f` = IPv4 `26.172.178.79`, `27 09` = port `9993`.

**Cross-verification:**

| Frame | Capture | UDP source IP | UDP dest IP | TLV IP | TLV port | Match |
|---|---|---|---|---|---|---|
| 116 | radmin-mine.pcapng (int=1) | 26.239.229.134 | 26.172.178.79 | 26.172.178.79 | 9993 | YES (matches dest IP) |
| 127 | radmin-mine.pcapng (int=0) | 192.168.15.15 | [MASKED] | [MASKED] | 9993 | YES (matches dest IP) |

**Classification:** STRONG INDICATION (not CONFIRMED): only 3 occurrences observed, all from the same session; no other message families contain this pattern; the field could be coincidental or serve a different purpose; not a standard STUN attribute (STUN type 0x0004 is SOURCE-ADDRESS, but the structure differs).

**Previous-claim correction:** earlier reports claimed TLV type `00 04` at offset 0x5e; raw bytes at 0x5e–0x5f are `1d ba`, not `00 04`. The `00 04` sequence appears at offset 0x6f–0x70; the IP appears at 0x71–0x74 (not 0x60–0x63 as previously claimed). Recorded under ## Prior-Round Corrections.

### 6.4 Hole Punching

The same base payload (137 bytes) is sent from multiple source ports to the same destination port 9993 (frames 116–118, `radmin-mine.pcapng`, interface 1):

- `26.239.229.134:9993` → `26.172.178.79:9993` (same payload)
- `26.239.229.134:48318` → `26.172.178.79:9993` (same payload)
- `26.239.229.134:48870` → `26.172.178.79:9993` (same payload)

Peer response: frame 269, 59 bytes from `26.172.178.79:9993` → `26.239.229.134:9993`, magic `a820016a`.

**Classification:**

| Step | Classification | Justification |
|---|---|---|
| Transmission from multiple ports | CONFIRMED | 3 frames with identical payload from ports 9993, 48318, 48870 |
| Peer response received | CONFIRMED | Frame 269 is a 59-byte response from peer |
| Bidirectional communication | CONFIRMED | Frames 116–118 (outbound) + frame 269 (inbound) |
| Successful NAT traversal | HYPOTHESIS | No proof that the response reached through a punched hole vs. an existing path |
| Established P2P data channel | HYPOTHESIS | Only one response observed; no sustained data exchange |
| Effective VPN data communication | INCONCLUSIVE | Payload is encrypted; cannot determine whether it is VPN data |

Frames 116 and 117 have identical payloads (confirming retransmission from multiple source ports). Frame 127 has a different magic (`5d a8 6b 96`) but the same session ID `e5 d4 c1 c5 bc 21 59 16 c8 0f` at offset 0x08–0x11.

### 6.5 Encryption Region (Family A)

Region 0x2e–0x5d: 48 bytes, high entropy, random appearance — consistent with block cipher encryption (48 bytes = 3 blocks of 16 bytes, compatible with AES-128 or AES-256 block mode). No nonce or IV is visible before the encrypted region. Plaintext header: first 46 bytes (0x00–0x2d) have predictable structure and repeated values between messages.

Correction: messages 116 and 128 were once cited as having the same fixed header but different encrypted regions; the audit establishes that messages 116, 117, 118 have IDENTICAL complete payloads including the "encrypted" region — the same message is retransmitted from multiple ports, not encrypted with a different nonce. Encryption algorithm cannot be determined without keys.

### 6.6 Session Identifier

`e5 d4 c1 c5 bc 21 59 16 c8 0f` (10 bytes). Appears only in UDP/9993 (offset 0x08–0x11 in 137-, 99-, and 28-byte messages); NOT in UDP/47836, TCP/17301, or TCP/17351.

Two interpretations: (1) a single 10-byte identifier; (2) concatenated fields — bytes 0–5 `e5 d4 c1 c5 bc 21` (possibly fixed part), bytes 6–7 `59 16` (possibly timestamp or counter), bytes 8–9 `c8 0f` (possibly sequence or checksum). The same 10 bytes appear consistently in all messages of the same session regardless of message size or direction; no evidence that the identifier changes during the capture. Which interpretation is correct cannot be determined without more evidence.

### 6.7 UDP/47836 Keepalive

4-byte payload (`udp.length` = 12 minus 8-byte UDP header), sequential little-endian counter, ~1 second interval, one direction only (from `26.228.88.155:47836` to `26.239.229.134:47836`), increment +1 per message, counter differs between captures (707, 802, 158 — possibly reset per session).

| Capture | Frame | Payload | Value |
|---|---|---|---|
| radmin-mine.pcapng | 66 | `c3 02 00 00` | 0x02c3 = 707 |
| radmin-mine.pcapng | 342 | `c4 02 00 00` | 0x02c4 = 708 |
| radmin-mine.pcapng | 543 | `c5 02 00 00` | 0x02c5 = 709 |
| radmin-mine-host.pcapng | 93 | `22 03 00 00` | 0x0322 = 802 |
| radmin-mine-host.pcapng | 213 | `23 03 00 00` | 0x0323 = 803 |
| radmin-connect.pcapng | 312 | `9e 00 00 00` | 0x0000009e = 158 |
| radmin-connect.pcapng | 957 | `9f 00 00 00` | 0x0000009f = 159 |

**Layout ambiguity (INCONCLUSIVE):** the 4-byte payload `XX YY 00 00` can be interpreted as either `uint16 LE counter + 2 zero bytes` (counter = 0x02c3 = 707, then `00 00`) or `uint32 LE counter` (counter = 0x000002c3 = 707). Both interpretations produce identical numeric values because the upper 16 bits are always `00 00`. No evidence distinguishes these interpretations.

### 6.8 Physical ↔ Virtual Correlation (UDP/9993)

Three frame pairs from `radmin-mine.pcapng`, byte-identical 137-byte payloads:

| Capture | Virtual frame | Physical frame | Virtual src:port | Physical src:port | Virtual dst:port | Physical dst:port | Payload match |
|---|---|---|---|---|---|---|---|
| radmin-mine.pcapng | 116 | 130 | 26.239.229.134:9993 | 192.168.15.15:9993 | 26.172.178.79:9993 | [MASKED]:9993 | IDENTICAL |
| radmin-mine.pcapng | 117 | 131 | 26.239.229.134:48318 | 192.168.15.15:48318 | 26.172.178.79:9993 | [MASKED]:9993 | IDENTICAL |
| radmin-mine.pcapng | 118 | 132 | 26.239.229.134:48870 | 192.168.15.15:48870 | 26.172.178.79:9993 | [MASKED]:9993 | IDENTICAL |

**TLV field transformation:** virtual TLV IP `26.172.178.79` / port `9993` vs physical TLV IP `26.172.178.79` / port `9993` — the TLV carries the virtual peer address, not the physical one.

**Classification:** CONFIRMED (limited) — the same UDP/9993 payload appears on both interfaces with byte-identical content for the 3 frame pairs observed; based on only 3 frame pairs from a single capture. The encapsulation mechanism between the virtual interface and the physical transport remains undocumented.

---

## 7. Virtual Interface / Encapsulation

**Interface:** `radminvpn0` (present in `radmin-connect`, `radmin-mine`, `radmin-mine-host`).
**Virtual IP:** `26.239.229.134/8` (CONFIRMED).

**Virtual MACs observed via ARP:**

| MAC | Association |
|---|---|
| 02:50:ce:a5:3a:26 | 26.239.229.134 (local client) |
| 02:08:62:e3:9a:28 | 26.239.229.134 (ARP response) |
| 02:50:eb:9a:6f:58 | 26.228.88.155 |
| 02:50:06:00:35:fd | 26.172.178.79 |

All are locally administered (prefix `02:`); no evidence that MACs are global or persistent identifiers across sessions.

**ARP frames:**

- Frame 115 (`radmin-mine.pcapng`): 02:50:ce:a5:3a:26 → Broadcast "Who has 177.112.79.226? Tell 26.239.229.134"
- Frame 272 (`radmin-mine.pcapng`): "Who has 192.168.15.122? Tell 26.239.229.134"
- Frame 274 (`radmin-mine.pcapng`): "Who has 25.33.236.186? Tell 26.239.229.134"
- Frame 314 (`radmin-connect.pcapng`): 02:50:eb:9a:6f:58 → Broadcast "Who has 26.239.229.134? Tell 26.228.88.155"
- Frame 315 (`radmin-connect.pcapng`): 02:08:62:e3:9a:28 → 02:50:eb:9a:6f:58 "26.239.229.134 is at 02:08:62:e3:9a:28"

**Virtual IPs:** `26.239.229.134` (local client), `26.172.178.79` (peer), `26.228.42.15` (peer), `26.228.88.155` (peer, keepalive), `25.33.236.186` (ambiguous, 25.x range), `26.255.255.255` (virtual broadcast).
**Peer physical IPs:** `[IP_PUBLICO_MASCARADO}` (peer physical IP), `103.195.103.66` (peer physical IP / relay), `25.33.236.186` (ambiguous physical/virtual IP).

**Encapsulation:** NOT determined. Section 6.8 shows the same payload on virtual and physical interfaces, but the packet format inside the VPN is unknown. Classification: virtual interface PARTIALLY CHARACTERIZED; packet encapsulation NOT READY.

**Auxiliary/background protocols on the virtual interface:**

| Protocol | Endpoint | Capture | Classification |
|---|---|---|---|
| IGMPv3 | 26.228.42.15 → 224.0.0.22 | radmin-mine-host | Auxiliary traffic (multicast join/leave) |
| SSDP | 26.172.178.79 → 239.255.255.250:1900 | radmin-mine-host | M-SEARCH (likely Windows background) |
| UDP/4445 | 26.239.229.134:60900 → 224.0.2.60:4445 | radmin-mine-host | Virtual multicast |
| MDNS | 192.168.15.9:5353 → 224.0.0.251 | radmin-mine-host | Auxiliary traffic |

Classification: auxiliary background traffic (likely Windows running via Wine), not essential to Radmin VPN communication.

---

## 8. Unified Timeline

| Time | Event | Capture | Inferred phase |
|---|---|---|---|
| T-114s | `radmin_vm.pcap` starts (18:05:28) | radmin_vm.pcap | VM initialization |
| T+0s | DNS queries (Windows/MS domains) | radmin_vm.pcap | Initialization |
| T+7s | Teredo Router Solicitation | radmin_vm.pcap | IPv6 connectivity |
| T+42s | TCP connects `148.113.190.78:17301` | radmin_vm.pcap / radmin_17301.pcap | Control connection |
| T+95s | STUN Binding Requests (multiple ports) | radmin_vm.pcap | NAT discovery |
| T+96s | TCP connects `45.162.230.182:17351` | radmin_vm.pcap | Alternative control |
| T+0 (connect) | `radmin-connect.pcapng` starts (14:22:04) | radmin-connect.pcapng | Connection phase |
| T+5s | TCP SYN → `148.113.190.78:17301` | radmin-connect.pcapng | Control handshake |
| T+5s | TCP data/17301 (196, 4420 bytes) | radmin-connect.pcapng | Negotiation |
| T+6s | TCP → `198.244.203.247:17301` | radmin-connect.pcapng | Alternative server |
| T+0 (mine) | `radmin-mine.pcapng` starts (14:31:21) | radmin-mine.pcapng | Active phase |
| T+0 | UDP/9993 between virtual peers | radmin-mine.pcapng | P2P established |
| T+0 | Keepalive UDP/47836 | radmin-mine.pcapng | Session maintenance |
| T+0 (mine-host) | `radmin-mine-host.pcapng` starts (14:32:56) | radmin-mine-host.pcapng | Active phase host |
| T+5s | ARP on virtual interface | radmin-mine-host.pcapng | Address resolution |

**Note:** file names (`radmin-connect`, `radmin-mine`, `radmin-mine-host`) suggest distinct phases (connection, active traffic, active traffic on host), but there is no direct confirmation in capture metadata. Timestamps indicate `radmin-mine` (14:31:21) precedes `radmin-mine-host` (14:32:56).

---

## 9. Prior-Round Corrections

The second round produced 20 analysis fronts (`PCAP_FORENSICS_DEEP_DIVE.md` §Summary of the 20 Fronts), of which front 01 audited the previous report and front 19 audited previous conclusions. The third-round audit (`PCAP_THIRD_ROUND_AUDIT.md`) re-audited all second-round documents against the captures and issued a master correction table (§3), document-specific findings (§3.2), a contradictions table (§16), and a revised readiness matrix (§15).

### 9.1 Master corrections

| # | Affirmation | Source | Audit result | Required correction |
|---|---|---|---|---|
| 1 | UDP/9993 message is 137 bytes, fully documented | Deep dive §Front 02 | Offsets 0x00–0x77 only (120 bytes); 17 bytes (0x78–0x88) undocumented | Document bytes 0x78–0x88 or revise size to 120 |
| 2 | TLV field `0x0004` at offset 0x5e | Deep dive §Front 03 | REFUTED — `00 04` at 0x6f–0x70; raw bytes at 0x5e–0x5f are `1d ba` | Correct offset to 0x6f–0x70 |
| 3 | STUN Binding Response is 98 bytes | Report §6.2; Flow Map §Phase 3 | Confusion — 98 = Ethernet `frame.len`, 56 = UDP payload (`udp.length` = 64 minus 8-byte header) | Clarify both measurements |
| 4 | STUN = standard RFC 5389 with magic cookie | Deep dive §Front 13 | REFUTED — no magic cookie, 16-byte TXID instead of 12 | Reclassify as non-standard STUN variant |
| 5 | STUN Transaction ID is 12 bytes | Deep dive §Front 13 | REFUTED — TXID is 16 bytes | Correct to 16 bytes |
| 6 | UDP/47836 is `uint16 LE` + 2 bytes OR `uint32 LE` | Deep dive §Front 06 | INCONCLUSIVE — both interpretations produce same values | Mark INCONCLUSIVE, document both |
| 7 | Hole punching CONFIRMED | Deep dive §Front 05; Flow Map §Confirmed | HYPOTHESIS — only transmission attempts observed, no proof of successful NAT traversal | Downgrade to HYPOTHESIS |
| 8 | Virtual interface READY for implementation | Readiness §11 | Contradiction — encapsulation is NOT READY | Downgrade to PARTIALLY CHARACTERIZED |
| 9 | STUN READY | Readiness §5 | Overestimated — attributes undecoded, no magic cookie | Downgrade to PARTIALLY CHARACTERIZED |
| 10 | `[IP_PUBLICO_MASCARADO}` delimiter | All second-round documents | Error — closing `}` instead of `]` | Fix to `[IP_PUBLICO_MASCARADO]` |
| 11 | Portuguese text in documents | Deep dive, readiness, corrections, flow map, catalog | Violates the English-only documentation rule | Translate all documents to English |

### 9.2 Contradictions between documents

- STUN response size: 98 vs 56 bytes (report vs deep dive vs catalog vs flow map) — 98 = `frame.len`, 56 = UDP payload.
- STUN magic cookie: documents claim present; packets show absent.
- STUN TXID: 12 vs 16 bytes — 16 bytes confirmed from raw packets.
- Hole punching: CONFIRMED vs HYPOTHESIS.
- Virtual interface: READY vs encapsulation NOT READY.
- UDP/47836: `uint16 LE` vs `uint32 LE`.
- TLV offset: 0x5e vs 0x6f–0x70.
- Mask delimiter: `}` vs `]`.
- Portuguese text vs English-only rule.

### 9.3 Handshake `00 00 00 04 03 00 00 00` — conflicting claims (NOT resolved)

**Claim 1 — handshake present in capture (`EVIDENCE_INDEX.md` §3 packet index):**

- `radmin_17301.pcap` frame #35: `192.168.122.77:49493 → 198.244.203.247:17301`, TCP (8 bytes): Magic Framing `00 00 00 04` + Magic Payload `03 00 00 00`.
- `radmin_17301.pcap` frame #44: `198.244.203.247:17301 → 192.168.122.77:49493`, TCP (8 bytes): Server Echo of the Magic: `00 00 00 04 03 00 00 00`.
- Followed by frame #46 RSA-2048 Client Hello (260 bytes), frame #48 Server Hello with the 4-byte session token, frame #50 first frame encrypted with AES-256-CBC and the 0xCC trailer.

**Claim 2 — handshake absent at connection start (`PCAP_FORENSICS_REPORT.md` §11; `PCAP_FLOW_MAP.md` §Flow Map Limitations; `PCAP_FORENSICS_DEEP_DIVE.md` §Front 19 / §Front 20):**

- The initial 8-byte handshake `00 00 00 04 03 00 00 00` does NOT appear at the start of any captured TCP connection; TCP/17301 captures start with PSH+ACK data; the handshake may occur before capture start or be filtered.

**Disposition:** Both claims are recorded verbatim. They contradict each other and are NOT resolved here — see `RECONCILIATION.md`.

Note: `EVIDENCE_INDEX.md` §1 lists `radmin_17301.pcap` at 85 packets yet indexes frames #35–#50 and #688–#710 in it; the packet-range conflict is preserved under ## Evidence Limitations and also points to `RECONCILIATION.md`.

---

## 10. Evidence Limitations

- **Encrypted traffic:** TCP/17301, TCP/17351 payloads and the UDP/9993 region 0x2e–0x5d are encrypted; no keys are available, so the application protocol inside these flows cannot be determined.
- **Handshake not captured:** the initial 8-byte handshake `00 00 00 04 03 00 00 00` does not appear at the start of any captured connection (see Claim 2 in §9.3); it may occur before capture start.
- **Relay not confirmed:** the high-volume flow to `[IP_PUBLICO_MASCARADO}:58358` (10,156 packets, 3.1 MB) may be relay traffic, direct P2P, or another service — insufficient evidence to classify.
- **NAT type not determined:** a single STUN response per server is insufficient to classify NAT behavior.
- **Limited frame pairs:** only 3 virtual↔physical frame pairs compared for encapsulation analysis.
- **Single session:** all observations come from one session between two peers; results may not generalize.
- **STUN variant non-standard:** no magic cookie and a 16-byte transaction ID mean standard STUN libraries may not work without modification; STUN response attributes are not fully decoded (no specific dissector).
- **Inventory inconsistencies:** `radmin_17301.pcap` size 30 kB (report) vs 1,258,496 bytes (`EVIDENCE_INDEX.md`); role "host 192.168.122.77 filter" vs "ports 17301/17351 relay"; frames #688–#710 indexed in an 85-packet capture.
- **TLV `0x30` (192 bytes):** previous reverse-engineering reports mention it with static-analysis references (`shelper.dll!0x100638f0`, initialization `0x10005250`, update `0x10004e50`, finalization `0x10004f30`, folding in caller `0x10069cdb`–`0x10069d0e`); no 192-byte field tagged `0x30` was found in any capture — INCONCLUSIVE (may exist in pre-capture handshake traffic, in unobserved message types, or in a different protocol version).
- **RSA operation** (padding, key exchange) and the **origin of the 32-byte AES key** are not determinable from encrypted traffic.

---

## Sources

The following 5 sources were read and are fully consumed by this draft:

1. `docs/PCAP_FLOW_MAP.md` — PCAP flow map: communication flow overview, detailed flow by phase, physical-virtual correlation, data flows by protocol, confirmed vs hypothetical paths, flow map limitations.
2. `docs/PCAP_FORENSICS_DEEP_DIVE.md` — second-round deep dive: summary of the 20 fronts, previous-report audit, UDP/9993 reconstruction, field `0x0004`, physical-virtual correlation, transport mechanism, keepalive, message comparison, session identifier, encryption, TCP/17301 and TCP/17351, TLV `0x30`, STUN, NAT, Teredo, ARP, auxiliary protocols, timeline, previous conclusion audit, implementation matrix.
3. `docs/PCAP_FORENSICS_REPORT.md` — first-round report: capture inventory, event timeline, endpoints and flows, TCP control analysis, STUN/NAT, Teredo, virtual interface, P2P and relay, capture comparison, correlation with previous findings, contradictions, recommended experiments, conclusion classifications.
4. `docs/PCAP_THIRD_ROUND_AUDIT.md` — third-round audit: master correction table, document-specific findings, UDP/9993 137-byte reconstruction, TLV `0x0004` audit, physical vs virtual correlation, hole punching re-evaluation, keepalive layout, STUN size/protocol audit, TCP/17301/17351 audit, NAT/relay audit, Teredo/DNS audit, TLV `0x30` audit, privacy audit, readiness matrix, contradictions, limitations, recommended experiments.
5. `docs/reverse-engineering/round-02/EVIDENCE_INDEX.md` — round-02 evidence index: binaries and artifacts table, functions and virtual addresses by front, packet index including handshake frames #35/#44, relay frames #688–#710, STUN packets (#796/#839, #676/#678), and Teredo packet #10.

No original `.pcap`/`.pcapng` files, binaries, DLLs, SYS files, or source code were used as direct evidence for this document; every technical claim is quoted from the five documents above.

---

## Provenance Note

This draft consolidates the PCAP forensics corpus into a single evidence-preserving document. Every capture filename, frame number, port, IP address, size, byte sequence, timestamp, protocol constant, and classification was copied verbatim from one of the five sources; no technical fact was invented, rounded, dropped, or reinterpreted. Overlapping capture descriptions across rounds were deduplicated, but every technical fact was kept. Where sources contradict each other (handshake presence/absence, TLV offset 0x5e vs 0x6f–0x70, STUN response size 98 vs 56 bytes, UDP/47836 layout, hole-punching classification, capture inventory sizes and packet ranges), both renderings are preserved verbatim and the conflict is NOT resolved — all such conflicts are flagged for `RECONCILIATION.md`. Classifications (CONFIRMED / STRONG INDICATION / HYPOTHESIS / INCONCLUSIVE / REFUTED) are reported as assigned by the sources; where sources disagreed, both classifications are listed. This draft writes no other file and modifies no source document.

---

## Evidence appendix (exact tokens from consolidated sources)

Exact addresses, hashes and identifiers from the consolidated sources that are not repeated in the prose above. They are preserved here so that no evidence anchor is lost during compaction; the full narrative for each source remains available in git history.

- `docs/PCAP_FORENSICS_REPORT.md`: `0x00000194`
- `docs/reverse-engineering/round-02/EVIDENCE_INDEX.md`: `0x00498fe0`, `0x010001df`, `0x010001e3`, `0x0200025e`, `0x040001e7`, `0x090001cd`, `0x10003b30`, `0x100412a0`, `0x1004a090`, `0x1004a115`, `0x1004ef1c`, `0x10051180`, `0x10051640`, `0x10052310`, `0x10062ca9`, `0x10062d60`, `0x10062e00`, `0x10065790`, `0x10065de8`, `0x10069c20`, `0x10069f90`, `0x1006a0c0`, `0x1006a2b0`, `0x1006a4cc`, `0x1006a512`, `0x1006b860`, `0x1006ba80`, `0x1400030cc`, `0x140003222`, `0x14000c05c`, `0x14000c08f`, `0x224018`, `0x224020`, `0x228014`, `0x22801c`, `0x22c004`, `0x40f052`, `0x41537e`, `0x47de40`, `0x488ae0`, `0x4aff8a`, `0x4b003a`, `0x4b00a4`, `0x4b0123`, `0x4b017f`, `0x4e2ac0`, `0x4e8eb0`, `0x4e8f78`, `0x519e74`, `0x5352d0`, `0xffffffff`, `fun_004e8eb0`
