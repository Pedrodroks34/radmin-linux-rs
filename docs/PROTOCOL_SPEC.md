# Radmin VPN Protocol Specification (Consolidated)

**Consolidated from:** 8 sources mapped to `PROTOCOL_SPEC` in `analysis_workspace/compaction/mapping.tsv`.
**Status:** PARTIAL SPECIFICATION, based on static analysis of binaries (reverse engineering) and real traffic capture (tshark). No field, offset, size, endianness, numeric identifier, serialization function, or cryptographic algorithm has been directly observed unless marked as confirmed. Every value marked "unknown" must stay that way until dynamic analysis or decompilation settles it.

Sources consumed:
- `docs/PROTOCOL_SPEC.md` (Phase 2 reconstruction)
- `docs/PCAP_MESSAGE_CATALOG.md` (PCAP message catalog)
- `docs/PHASE_3_CONTROL_MESSAGE_CATALOG.md` (Phase 3 control message catalog; Portuguese source, prose translated here, identifiers/tags preserved verbatim)
- `docs/reverse-engineering/round-02/03-tlv-catalog.md`
- `docs/reverse-engineering/round-02/04-authentication-networks.md`
- `docs/reverse-engineering/round-02/05-tcp-relay.md`
- `docs/reverse-engineering/round-02/06-p2p-nat.md`
- `docs/reverse-engineering/round-02/07-teredo.md`

---

## 1. Protocol architecture overview

Radmin VPN has three distinct protocol layers, identified in the binaries:

```
┌─────────────────────────────────────────────────────────┐
│  RvRvpnGui.exe  (Qt/QML UI)                             │
└──────────────┬──────────────────────────────────────────┘
               │  named pipe: \\.\pipe\RadminVpnGuiChannel
               ▼
┌─────────────────────────────────────────────────────────┐
│  RvControlSvc.exe  (Windows service, FamRT/C++ engine)  │
│  ├── Control packets (CPacket_*): handshake,            │
│  │   keep-alive, shutdown, frame, switch, filter        │
│  ├── WS2_32 imports (WSARecv), WININET                  │
│  └── Calls ROLClient_* (connect, send, receive, etc.)   │
└──────────────┬──────────────────────────────────────────┘
               │  DeviceIoControl \\.\RVPNNETMP
               ▼
┌─────────────────────────────────────────────────────────┐
│  NetMP60.sys  (NDIS 6 miniport, \Device\RVPNNETMP)      │
│  ├── IOCTL start address                                │
│  ├── Current Address / Permanent Address (MAC)          │
│  └── Signed by Microsoft Windows HC                     │
└──────────────┬──────────────────────────────────────────┘
               ▼
┌─────────────────────────────────────────────────────────┐
│  RvROLClient.dll  (ROL client library)                  │
│  ├── ROS packets (CRosPkt_*): register, login, join,    │
│  │   heartbeat, networks, NAT, etc.                     │
│  ├── Session packets (CMsg_*, CSession_*): auth, IP,    │
│  │   Enet, shutdown, private session                    │
│  ├── Client data packets (C*Packet@RolClient):          │
│  │   login, join, manage, heartbeat, enet, etc.         │
│  ├── Structures: CCryptoChannel, CAuthSessionId,        │
│  │   VCUniqueConnectionId, VCRid, VCRosAddress,         │
│  │   VCRosSessionId, CEnetAbstractConnection,           │
│  │   TMBufferQueueWithCode (send/recv),                 │
│  │   CProxyAddressPool, CGenericAddressPool,            │
│  │   CDEnetAddresses, USPortPara, USNatPenPacket        │
│  └── 47 ROLClient_* exports                             │
└─────────────────────────────────────────────────────────┘
```

---

## 2. Framing and version negotiation

### 2.1 TCP framing (ports 17301 and 17351)

**Header:** 4 bytes, big-endian `uint32_t` containing the payload size. The header is not included in the size.

| Example header | Declared size | Payload | Total on TCP |
|---|---|---|---|
| `00 00 00 20` | 32 | 32 bytes | 36 bytes |
| `00 00 00 90` | 144 | 144 bytes | 148 bytes |
| `00 00 01 00` | 256 | 256 bytes | 260 bytes |
| `00 00 01 30` | 304 | 304 bytes | 308 bytes |
| `00 00 01 60` | 352 | 352 bytes | 356 bytes |
| `00 00 00 c0` | 192 | 192 bytes | 196 bytes |
| `00 00 02 c0` | 704 | 704 bytes | 708 bytes |
| `00 00 0d 40` | 3,392 | 3,392 bytes | 3,396 bytes |

**Endianness:** big-endian (confirmed by `00 00 00 20` = 32).

**Parser validation with real PCAP data:**

| Flow | Total bytes | Frames | Bytes consumed | Remaining | Truncated? |
|---|---|---|---|---|---|
| Stream 0 (56923 to 148.113.190.78) | 11,260 | 19 | 11,260 | 0 | No |
| Stream 1 (49493 to 198.244.203.247) | 5,920 | 18 | 5,920 | 0 | No |
| Stream 2 (49494 to 148.113.190.78) | 5,644 | 17 | 5,644 | 0 | No |
| **Total** | **22,824** | **54** | **22,824** | **0** | **No** |

**Payload sizes observed across the 54 frames:**
32, 32, 144, 352, 256, 304, 96, 112, 144, 352, 256, 304, 96, 128, 3968, 384, 3392, 704, 128, 4, 4, 192, 192, 4, 32, 256, 224, 4, 32, 224, 48, 256, 224, 48, 208, 2576, 160, 432, 224, 48, 384, 384, 48, 208, 160, 240, 2576, 160, 432, 224, 288, 384, 384, 160

**Result:** All 54 frames were extracted. Each TCP flow was separated and validated on its own. No bytes were left unconsumed, no truncated frame was found, and the flows were not mixed.

### 2.2 Initial handshake sequence observed (port 17301)

1. `00 00 00 20` + 32 bytes (client to server)
2. `00 00 00 20` + 32 bytes (server to client)
3. `00 00 00 90` + 144 bytes (server to client)
4. `00 00 01 60` + 352 bytes (client to server)
5. `00 00 01 00` + 256 bytes (server to client)
6. `00 00 01 30` + 304 bytes (client to server)
7. `00 00 00 60` + 96 bytes (server to client)
8. `00 00 00 70` + 112 bytes (client to server)
9. `00 00 00 04 03 00 00 00`: control packet (8 bytes total)
10. Larger packets (192, 704, 1,960, 3,392 bytes): session data

**Fields inside the payload:** Unknown. Decompilation is required to identify the internal structure.

**Control packet:** `00 00 00 04 03 00 00 00`: header (size 4) plus 4 payload bytes (`03 00 00 00`). It may be a keep-alive or an acknowledgment.

### 2.3 TLV framing (control channel payloads)

Two sources disagree on the wire field order of TLV records:

- `docs/PHASE_3_CONTROL_MESSAGE_CATALOG.md` §5.1, confirmed against PCAP #5486 (`radmin_vm.pcap`) and #686 (`radmin_vm2.pcap`):
  ```
  | LENGTH (32 bits, BE) |
  | TAG (32 bits, BE)    |
  | VALUE (Length bytes) |
  ```
  PHASE_3 states: "Length antecede Tag, e Tag antecede Value" (Length precedes Tag, and Tag precedes Value), confirmed directly in the unencrypted wire bytes and in the `RvROLClient.dll` generator function `0x100162d0`.

- `docs/reverse-engineering/round-02/03-tlv-catalog.md` §1:
  ```
  | TAG (32 bits, BE)    |
  | LENGTH (32 bits, BE) |
  | VALUE (Length bytes) |
  ```

This discrepancy is **not resolved** here; see `## Provenance note` and `RECONCILIATION.md`.

**Example TLV record (PHASE_3, packet #5486 / #686, 288-byte useful payload):**
```
[0x00..0x03] 00 00 01 20 -> Frame length = 288 bytes (0x0120)

-- TLV record 1 (12 bytes) --
[0x04..0x07] 00 00 00 04 -> Length = 4 bytes
[0x08..0x0b] 01 00 01 df -> Tag = 0x010001df (PROP_NETWORK_STATUS)
[0x0c..0x0f] 00 00 00 01 -> Value = 1 (Status: requesting / initializing)

-- TLV record 2 (12 bytes) --
[0x10..0x13] 00 00 00 04 -> Length = 4 bytes
[0x14..0x17] 01 00 03 2b -> Tag = 0x0100032b (PROP_PROTOCOL_CAPS)
[0x18..0x1b] 00 00 00 02 -> Value = 2 (client capability bitmask)

-- TLV record 3 (264 bytes) --
[0x1c..0x1f] 00 00 01 00 -> Length = 256 bytes (0x0100)
[0x20..0x23] 09 00 01 ca -> Tag = 0x090001ca (PROP_RSA_PUBKEY_BLOB)
[0x24..0x123] [256 bytes of the node RSA-2048 public key]
```

**Confirmation response (packet #5487 / #686):**
```
[0x00..0x03] 00 00 00 0c -> Frame length = 12 bytes (0x000c)

-- TLV record 1 (12 bytes) --
[0x04..0x07] 00 00 00 04 -> Length = 4 bytes
[0x08..0x0b] 01 00 01 df -> Tag = 0x010001df (PROP_NETWORK_STATUS)
[0x0c..0x0f] 00 00 00 02 -> Value = 2 (Status: confirmed / approved)
```

**Version/type constant:** In some TCP/17351 messages the payload begins with `10 00 00 04` (constant version/type field), followed by a 4-byte big-endian sequence number, then a variable message payload.

---

## 3. Ports and servers

### 3.1 TCP ports

| Port | Protocol | Role | Server(s) | Confidence |
|---|---|---|---|---|
| 17301 | TCP | Primary control and signaling channel (handshake SRP-6a, then AES-256-CBC encrypted payloads with clear 4-byte length prefix) | `148.113.190.78` (main), `198.244.203.247` (fallback/secondary ROL) | CONFIRMED |
| 17351 | TCP | Secondary coordination / TcpRelay relay channel; see conflict note below | `45.162.230.182` | See §13 |

### 3.2 UDP ports

| Port | Protocol | Role | Size | Qty | Confidence |
|---|---|---|---|---|---|
| 9993 | UDP | Family A — Setup/complete | 137 | 93 | CONFIRMED |
| 9993 | UDP | Family B — Short | 33 | 223 | CONFIRMED |
| 9993 | UDP | Family C — Short keepalive | 28 | 82 | CONFIRMED |
| 9993 | UDP | Family D — Medium | 99 | 74 | CONFIRMED |
| 9993 | UDP | Family E — Large (connect) | 247–641 | ~40 | CONFIRMED |
| 47836 | UDP | Keepalive | 4 | ~60 | CONFIRMED |
| 17309/17310 | UDP | Primary STUN (Tests I and II) | 20 req / 56 resp | ~20 / ~10 | CONFIRMED |
| 17347/17348/17349 | UDP | Secondary STUN servers / address-change verification | 20 req / 56 resp | ~20 / ~10 | CONFIRMED |
| 17357/17358 | UDP | STUN Binding Request / Response | 20 req / 56 resp | ~20 / ~10 | CONFIRMED |
| 3544 | UDP | Teredo Router Solicitation | 61 | 2 | CONFIRMED |

### 3.3 Server IPs observed

| Server IP | Port | Protocol | Inferred role |
|---|---|---|---|
| `148.113.190.78` | 17301 | TCP | Radmin control and signaling server (main) |
| `198.244.203.247` | 17301 | TCP | Control and signaling server (fallback/secondary) |
| `45.162.230.182` | 17351 | TCP | Alternate server / coordination endpoint; role disputed (see §13) |
| Several (Akamai) | 443 | TCP | CDN and HTTPS. Possibly DoH or background Windows traffic. Not confirmed as Radmin. |

**Note:** All main traffic identified as Radmin uses **TCP 17301**. Other servers on port 443 through Akamai may be DoH, updates, or background Windows traffic, which is not confirmed as Radmin.

### 3.4 DNS and server discovery

- String `https://%hs/dns-query`: DNS over HTTPS (DoH).
- Public resolvers hardcoded in `RvROLClient.dll`: 1.1.1.1, 1.0.0.1, 8.8.8.8, 8.8.4.4, 208.67.222.222, 208.67.220.220, 1.0.0.2, 1.0.0.3, 1.1.1.2, 1.1.1.3, 9.9.9.9 through 9.9.9.13, 130.59.31.248, 130.59.31.251, 223.5.5.5, 223.6.6.6.
- No Radmin server IP is hardcoded.
- `ROLClient_GetNodeRegionSupport`: region support for nodes.
- Unknown: ROS server hostname, exact DoH endpoint beyond the `https://%hs/dns-query` pattern, DoH request format, relay server addresses.

### 3.5 Capture setup (reference)

- Interface: `virbr0` (libvirt bridge).
- VM IP: `192.168.122.77`.
- Filter: `host 192.168.122.77`.
- File 1: `/tmp/radmin_vm.pcap` (about 21 MB, about 6,360 packets).
- File 2: `/tmp/radmin_vm2.pcap` (about 196 KB, about 69 TCP frames to port 17301).
- Port 17301 extract: `/tmp/radmin_17301.pcap` (about 30 KB, 3 distinct TCP flows).

---

## 4. ROLClient export table (`RvROLClient.dll`)

**Evidence:** `inspect_native_exports` (REA). Full export table captured. 47 exports confirmed.

| Export | RVA | Ordinal | Inferred role | Confidence |
|---|---|---|---|---|
| `ROLClient_InitDll` | 0x10041010 | 19 | DLL initialization | Confirmed (export table) |
| `ROLClient_ShutdownDll` | 0x10042540 | 43 | Shutdown | Confirmed |
| `ROLClient_Register` | 0x100419d0 | 28 | Device registration | Confirmed |
| `ROLClient_Connect` | 0x10040670 | 6 | Connection | Confirmed |
| `ROLClient_ContinueConnect` | 0x10040760 | 7 | Continue connection | Confirmed |
| `ROLClient_Listen` | 0x10041380 | 21 | Listen | Confirmed |
| `ROLClient_ListenVpn` | 0x10041470 | 22 | Listen for VPN | Confirmed |
| `ROLClient_Send` | 0x10041e70 | 34 | Send data | Confirmed |
| `ROLClient_Receive` | 0x100418b0 | 27 | Receive data | Confirmed |
| `ROLClient_WaitForSend` | 0x100425f0 | 44 | Wait for send | Confirmed |
| `ROLClient_ShutdownChannel` | 0x100423c0 | 41 | Close channel | Confirmed |
| `ROLClient_JoinNetwork` | 0x100412a0 | 20 | Join network | Confirmed |
| `ROLClient_CancelJoin` | 0x10040430 | 3 | Cancel join | Confirmed |
| `ROLClient_ManageNetwork` | 0x10041710 | 25 | Manage network | Confirmed |
| `ROLClient_ManageNetwork2` | 0x10041650 | 24 | Manage network (v2) | Confirmed |
| `ROLClient_LeaveNetwork` | (not exported) | none | Leave network | Inferred (string in ControlSvc) |
| `ROLClient_GetNodes` | 0x10040de0 | 16 | Get nodes | Confirmed |
| `ROLClient_GetNodeRegionSupport` | 0x10040d20 | 15 | Region support | Confirmed |
| `ROLClient_EnumPublicNetworks` | 0x100409a0 | 10 | Enumerate public networks | Confirmed |
| `ROLClient_ChatCommand` | 0x100404e0 | 4 | Chat command | Confirmed |
| `ROLClient_ReportIpConflict` | 0x10041b30 | 30 | Report IP conflict | Confirmed |
| `ROLClient_ReportLanguage` | 0x10041bf0 | 31 | Report language | Confirmed |
| `ROLClient_ReportRServerInfo` | 0x10041cd0 | 32 | Report server info | Confirmed |
| `ROLClient_ReportSessionSummary` | 0x10041db0 | 33 | Session summary | Confirmed |
| `ROLClient_NeedMasterAddress` | 0x100417f0 | 26 | Master address | Confirmed |
| `ROLClient_SetMaxPacketSize` | 0x10042090 | 37 | Max packet size | Confirmed |
| `ROLClient_SetCompression` | 0x10041fd0 | 36 | Compression | Confirmed |
| `ROLClient_SetPriority` | 0x10042150 | 38 | Priority | Confirmed |
| `ROLClient_SetVirtualAddresses` | 0x10042300 | 40 | Virtual addresses | Confirmed |
| `ROLClient_SetChannelCounters` | 0x10041f10 | 35 | Channel counters | Confirmed |
| `ROLClient_DisableEncryption` | 0x10040830 | 8 | Disable encryption | Confirmed |
| `ROLClient_EnableModuleEvents` | 0x100408f0 | 9 | Module events | Confirmed |
| `ROLClient_AllocMemory` | 0x100403c0 | 2 | Allocate memory | Confirmed |
| `ROLClient_FreeMemory` | 0x10040c00 | 13 | Free memory | Confirmed |
| `ROLClient_GetUnsendDataSize` | 0x10040eb0 | 17 | Unsent data size | Confirmed |
| `ROLClient_InitConnector` | 0x10040f50 | 18 | Initialize connector | Confirmed |
| `ROLClient_ShutdownConnector` | 0x10042480 | 42 | Shut down connector | Confirmed |
| `ROLClient_FreeConnector` | 0x10040b40 | 12 | Free connector | Confirmed |
| `ROLClient_RejectConnect` | 0x10041ab0 | 29 | Reject connection | Confirmed |
| `ROLClient_WaitModuleEvent` | 0x100426a0 | 45 | Wait for module event | Confirmed |
| `ROLClient_WaitROLEvent` | 0x10042770 | 46 | Wait for ROL event | Confirmed |
| `ROLClient_WaitThreads` | 0x100427d0 | 47 | Wait for threads | Confirmed |
| `ROLClient_GetChannelProductVersion` | 0x10040c60 | 14 | Channel product version | Confirmed |

**Related exports in other binaries:**
- `RvUESClient.dll`: 6 exports captured, including `UESC_GetTcpNatType` (RVA 0x10005a10), `UESC_GetAddress` (RVA 0x10005910), `UESC_Init`, `UESC_Shutdown`.
- `imrsdk.dll`: 22 exports captured.

---

## 5. Control packet catalogs

### 5.1 Control packets (`CPacket_*@ControlSvc`)

Identified via RTTI in `RvControlSvc.exe`. No field, size, or serialization function has been observed for any of them.

| Name | RTTI evidence | Status |
|---|---|---|
| `CPacket_Handshake_Syn` | `?AVCPacket_Handshake_Syn@ControlSvc@@` | Name confirmed |
| `CPacket_Handshake_SynAck` | RTTI | Name confirmed |
| `CPacket_Handshake_Ack` | RTTI | Name confirmed |
| `CPacket_KeepAlive` | RTTI | Name confirmed |
| `CPacket_KeepAliveAck` | RTTI | Name confirmed |
| `CPacket_Shutdown` | RTTI | Name confirmed |
| `CPacket_RadminPort` | RTTI | Name confirmed |
| `CPacket_RegionSupport` | RTTI | Name confirmed |
| `CPacket_ProductVersion` | RTTI | Name confirmed |
| `CPacket_Frame` | RTTI | Name confirmed |
| `CPacket_ConfirmSwitch` | RTTI | Name confirmed |
| `CPacket_StartSwitch` | RTTI | Name confirmed |
| `CPacket_FinalizeSwitch` | RTTI | Name confirmed |
| `CPacket_PacketFilter` | RTTI | Name confirmed |
| `CPacket_Invalid` | RTTI | Name confirmed |
| `CPacket_Unknown` | RTTI | Name confirmed |
| `CPacket@ControlSvc@@` (base) | RTTI | Name confirmed |
| `IPacket@ControlSvc@@` (interface) | RTTI | Name confirmed |

**Note:** The names `Syn`, `SynAck`, and `Ack` suggest a TCP-like handshake. This is inferred from the names, not from observed behavior.

### 5.2 ROS packets (`CRosPkt_*@RolClient`)

Identified via RTTI. Used to communicate with the ROS server (Radmin Online Server). Names only; no structure is known.

- Attach and redirect: `CRosPktAttachOk`, `CRosPktCancelRedirect`, `CRosPktRedirect`, `CRosPktClosestMaster`, `CRosPktNoRServer`.
- Chat: `CRosPktChatCommandReply`, `CRosPktChatEvents`, `CRosPktChatNodes`, `CRosPktMessage`.
- Connection: `CRosPktConnectAck`, `CRosPktConnectFailed`, `CRosPktNewConnection`, `CRosPktPostpone`.
- Errors and invalid: `CRosPktError`, `CRosPktInvalid`, `CRosPktUnknown`.
- Liveness: `CRosPktHeartbeat`, `CRosPktIsAlive`.
- Network membership: `CRosPktJoinApproved`, `CRosPktJoinNetwork`, `CRosPktManageNetReply`, `CRosPktNetworks`, `CRosPktNetworksChanges`, `CRosPktPublicNetworks`, `CRosPktRegistered`, `CRosPktLoginComplete`.
- Licensing: `CRosPktLicInfo`, `CRosPktLicManagmentReply`.
- Enet and push: `CRosPktPushDirectEnet`, `CRosPktPushEnet`, `CRosPktPushInfo`, `CRosPktStartEnet`.
- Address and region: `CRosPktRosAddr`, `CRosPktNodeRegionSupport`.
- NAT and tunnels: `CRosPktCollectTcpNatInfo`, `CRosPktTRSData`, `CRosPktInstallRadminShim`.
- Base types: `CRosPacket`, `IRosPacket`, `CRosConnectionPacket`, `VCRosAddress`, `VCRosSessionId`.

### 5.3 Session and message packets (`CMsg_*` / `CSession_*@RolClient`)

Names only, confirmed by RTTI.

- Authentication: `CMsgAuthFailed`, `CMsgAuthFinished`.
- Connector: `CMsgConnectFailed`, `CMsgConnecting`, `CMsgConnectorClosed`, `CMsgConnectorFailed`.
- Addresses: `CMsgDEnetAddresses`, `CMsgEnetAddress`, `CMsgIpAddresses`.
- Session: `CMsgSessionStart`, `CMsgSessionStop`, `CMsgShutdown`, `CSessionMsg`, `CSessionErrorMsg`, `CSessionSummaryPacket`, `CPrivateSessionMsg`.

### 5.4 Client data packets (`C*Packet@RolClient`)

Names only, confirmed by RTTI.

- Base types: `CAbstractClnPacket` / `VIClnPacket`, `CAbstractConnectionPacket`, `CGenericPacket`.
- Join and manage: `CCancelJoinPacket`, `CJoinNetworkPacket`, `CManageNetworkPacket`, `CEnumPublicNetworksPacket`.
- Login and status: `CLoginPacket`, `CIsAlivePacket`, `CHeartbeatPacket`, `CLogPacket`, `CClientVersionInfo`, `CGuiLanguagePacket`.
- Chat: `CChatCommandPacket`, `CChatGetNodesPacket`.
- Enet and connection: `CConnectResultPacket`, `CDirectEnetInfoPacket`, `CEnetInfoPacket`, `CConflictedIpAddressPacket`, `CGetNodeRegionSupportPacket`.
- NAT and TRS: `CNatPenPackets`, `CNatPenStatusPacket`, `CRequestTrsPacket`.
- Service: `CPacketConnection` (FamRT), `ReplyPacket` (ControlSvc, RTTI `?AV?$TAutoPtr@VCReplyPacket@ControlSvc@@`).

### 5.5 Official client request/response message catalog (`RvROLClient.dll`)

All client packets inherit from `CAbstractClnPacket` (base vtable `0x10114128`). The base constructor (`0x100165c0`) receives the numeric action code and stores it, then writes `0x0100031f` (PROP_CLIENT_PACKET_ID) into the internal TLV container via `0x100a6b70`:

```
100165d0: mov eax, dword ptr [ebp + 0x8] ; action code (Command ID)
100165dd: mov dword ptr [edi + 0x8], eax ; store in packet structure
1001660c: push 0
1001660e: push dword ptr [edi + 0x8]      ; Command ID value
1001660c: lea ecx, [edi + 0x14]           ; pointer to internal TLV container
10016614: push 0x0100031f                 ; Tag PROP_CLIENT_PACKET_ID (UINT32)
10016619: call 0x100a6b70                 ; write property into TLV container
```

| Official C++ class | Command ID | Vtable | Heap size | Constructor VA | Destructor VA | Function |
|---|---|---|---|---|---|---|
| `CHeartbeatPacket` | `0x04` (4) | `0x10114534` | 0x50 bytes | `0x100176f0` | `0x10017730` | Periodic connectivity keepalive |
| `CLoginPacket` | `0x14` (20) | `0x1011462c` | 0x48 bytes | `0x10017ec0` | `0x10017ef0` | Initial registration post-handshake and capabilities |
| `CJoinNetworkPacket` | `0x27` (39) | `0x101145e0` | 0x68 bytes | `0x10017950` | `0x100179a0` | Network join request with name and hash |
| `CEnumPublicNetworksPacket` | `0x2b` (43) | `0x101143f4` | 0x48 bytes | `0x100170a0` | `0x100170d0` | Public networks catalog request |
| `CManageNetworkPacket` | `0x34` (52) | `0x101146cc` | 0x50 bytes | `0x10018210` | `0x10018240` | Administrative operations (create, leave, delete network) |

Server responses are deserialized by the central dispatcher at `0x1008a7b0`, which extracts the response ID from tag `0x01000320` (PROP_SERVER_PACKET_ID):

```
1008a7d5: push 0x01000320                 ; Tag PROP_SERVER_PACKET_ID (UINT32)
1008a7df: call 0x10084d80                 ; extract integer value of response
1008a812: mov eax, dword ptr [ebp - 0x1c] ; eax = server Command ID
1008a815: add eax, -6                     ; index normalization (eax = cmd - 6)
1008a81f: cmp eax, 0x30                   ; table limit (49 entries)
1008a822: ja 0x1008b9fd                   ; jump to default/error handler
1008a828: jmp dword ptr [0x1008bb3c + eax*4] ; indexed jump via jump table
```

| Official C++ class | Command ID | Vtable | Handler VA | Constructor VA | Function |
|---|---|---|---|---|---|
| `CRosPktLoginComplete` | `0x15` (21) | `0x101187b4` | `0x1008b2f8` | `0x10086ae0` | Login confirmation and credential grant |
| `CRosPktManageNetReply` | `0x25` (37) | `0x1011881c` | `0x1008b3fc` | `0x10086bd0` | Administrative network operation result |
| `CRosPktNetworks` | `0x26` (38) | `0x10118850` | `0x1008b4f0` | `0x10086ce0` | Comprehensive list of networks and linked peers |
| `CRosPktJoinNetwork` | `0x28` (40) | `0x10118718` | `0x1008b16b` | `0x10086920` | Preliminary join request confirmation |
| `CRosPktNetworksChanges` | `0x29` (41) | `0x10118884` | `0x1008b57f` | `0x10086dc0` | Delta state updates for networks and members |
| `CRosPktJoinApproved` | `0x2a` (42) | `0x10118c2c` | `0x1008b0f5` | `0x10086897` | Definitive join approval with IP assignment |
| `CRosPktPublicNetworks` | `0x2d` (45) | `0x10118c94` | `0x1008b7af` | `0x10087007` | Paginated list of public networks returned |

**Request/response pairing:**
- Login: client `0x14` (20) → server `0x15` (21).
- Join: client `0x27` (39) → server `0x28` (40) / `0x2a` (42).
- Networks/sync: server `0x26` (38) and deltas `0x29` (41).

### 5.6 Real TCP message examples (PCAP)

#### TCP/17301 — Message 1 (192-byte payload)

**Capture:** `radmin-connect.pcapng` | **Frame:** 77 | **Source:** 192.168.15.15:44340 | **Destination:** 148.113.190.78:17301 | **tcp.len:** 196 | **Length field:** `00 00 00 c0` (192)

**Payload (192 bytes):**
```
10 f9 bf 00 3c e2 7b ed 34 3e 09 02 03 b8 0d 86
ec 02 a3 80 e1 79 96 44 71 cf 35 91 a4 c1 39 d8
01 21 05 b2 2b 4e 31 55 de 61 0a a8 90 e4 d9 ab
de 3a e8 70 93 32 94 1d 21 9e a2 13 f2 7f a3 55
5d 1e a7 97 e8 92 2d fc 84 a4 53 02 36 50 df 4e
1c a8 eb 16 2b 59 15 37 fd 51 75 81 28 be ff 45
4c 91 c8 7c 02 e1 3f ce 36 f6 29 6a d3 e6 40 e0
05 c2 96 1e 8e 58 43 4f 43 a 61 ee 53 fd bf de
5f 23 a 0f fd 4d bc c5 63 07 9c c5 a 45 b 8 ef
a7 6 03 84 68 28 13 5b 2c 8b 6e a0 39 6b b0 e
8b 77 f 21 59 01 b 73 14 8b a8 77 a 60 c 34 a
17 ee f7 3 5d 0d 6 ff cc e7 5 7c 8f 0b 3b 6f
a0 6 03 6b c d 2c
```
**Interpretation:** Encrypted data (high entropy). No identifiable fields in payload.

#### TCP/17301 — Message 2 (32-byte payload)

**Capture:** `radmin-connect.pcapng` | **Frame:** 80 | **Source:** 192.168.15.15:44340 | **Destination:** 148.113.190.78:17301 | **tcp.len:** 36 | **Length field:** `00 00 00 20` (32)

**Payload (32 bytes):**
```
c7 f5 78 26 af 97 91 03 70 c8 6f d5 cb 17 12 18
58 9d 2f 73 7f 39 7d cf 59 ee 46 4d 43 21 5b d0
```
**Interpretation:** 32 bytes of apparently random data (possible key, nonce, or cryptographic hash).

#### TCP/17301 — Message 3 (256-byte payload)

**Capture:** `radmin-connect.pcapng` | **Frame:** 81 | **Source:** 148.113.190.78:17301 | **Destination:** 192.168.15.15:44340 | **tcp.len:** 260 | **Length field:** `00 00 01 00` (256)

**Payload (256 bytes):** Encrypted data (high entropy, not displayed due to size).

#### TCP/17301 — Fragmented message (2,592 bytes total)

**Capture:** `radmin-connect.pcapng`

- **Frame 100:** Source 148.113.190.78:17301, Destination 192.168.15.15:44340 | Length field `00 00 0a 20` (2592) | tcp.len 1440 (first fragment: 4 header + 1436 payload)
- **Frame 101:** Source 148.113.190.78:17301, Destination 192.168.15.15:44340 | tcp.len 1156 (continuation: 1156 bytes payload, no new length prefix)
- **Reconstruction:** 1436 + 1156 = 2592 ✓

#### TCP/17351 — Message examples

**Message 1 — Sequence 4** | **Capture:** `radmin_vm.pcap` | **Frame:** 5487 | **Source:** 45.162.230.182:17351 | **Destination:** 192.168.122.77:49497 | **tcp.len:** 16 | **Length field:** `00 00 00 0c` (12)

**Complete payload (12 bytes):**
```
00 00 00 04 01 00 01 df 00 00 00 02
```
**Fields:** `00 00 00 04` version/type (constant); `01 00 01 df` variable field; `00 00 00 02` sequence number = 2.

**Message 2 — Sequence 3** | **Capture:** `radmin_vm.pcap` | **Frame:** 5494 | **Source:** 45.162.230.182:17351 | **Destination:** 192.168.122.77:49497 | **tcp.len:** 207 | **Length field:** `00 00 00 cb` (203)

**Payload (203 bytes):**
```
10 00 00 04 00 00 00 03 60 00 00 bf bf 64 a2 64
40 1a 82 c5 ac 52 b2 5a ee 49 b9 5a 8f 1d c3 1e
8b 92 7c 87 02 ff 0e 78 2b fb 69 75 18 6a 17 62
fc 6d 8e ff 24 f 42 b 57 ed c 1f a 32 bb 42 e 0
a 52 9c 45 5 b 71 7e b 2a 6d f 0 b 8 f 2b 0 c
96 86 ace 54 5 4 2 12 30 a 9 cf 1 13 b 5 f 8 cb
f3 a c 95 f b e 52 b 0 3 21 6 f 5 a 2 b c d b
13 0 f 66 d c e 98 8d 0c af f 8 22 8c 92 de 8b
14 c 58 6c 0 7 da 1 b 9b 0 b 29 f 1a 6d ff 4e
c 3 f 3f 74 6 12 14 1 3b 79 c 8 b 11 f 12 4 da
21 79 2a d 5b 63 ff 9 d 4 f 15 55 ff d fe 0 ab
91 79 ff 6 bd 77 a 3 5bc 0 6 24 9 13 c 84 f 95 c
```
**Fields:** `10 00 00 04` version/type (constant); `00 00 00 03` sequence number = 3; `60 00 00 bf ...` variable payload (195 bytes).

**Message 3 — Sequence 4** | **Capture:** `radmin_vm.pcap` | **Frame:** 5501 | **Source:** 45.162.230.182:17351 | **Destination:** 192.168.122.77:49497 | **tcp.len:** 208 | **Length field:** `00 00 00 cc` (204)

**Payload (204 bytes):**
```
10 00 00 04 00 00 00 04 60 00 00 c0 86 75 05 3a
9c 4a 5b 1a 39 d9 6a bf d0 74 01 5d 94 02 46 73
a 2e 78 fa 76 99 96 b 28 5b b 0 a 55 ff 63 34 a
90 9f 8f 1a b 3c 40 3 7d 06 d 92 f 5f 53 92 6d
ed 5d 48 b 21 66 a fd 97 ec 77 1b d 74 2c 2a 76
1c 86 37 2b 28 0b 71 f 6e 02 ad 52 02 26 dd 86
50 9a 10 59 55 31 6a a 29 52 ee 91 ed d 24 dd e
1b 7a 3c 5 d 3f f 84 39 ee 27 92 4 de 86 8a 78
99 9e 7c 37 0 5 36 90 9 77 89 1 f 3c 40 0 d 85
99 ed 89 d 0 f 31 20 33 cd 85 c 6 f 80 c 7a 89
7e 4 ce cd 0 c 12 d fd 2 b f aa 8 10 b cf 10
99 b df b cf 0 ad 26 fb 19 9 11 7 20 f da 54 ae
80 23 5b 5d da f 53 e 18 f cd 60 f 03 8 58 38 4
33 69 14 f 6
```
**Fields:** `10 00 00 04` version/type (constant); `00 00 00 04` sequence number = 4; `60 00 00 c0 ...` variable payload (200 bytes).

**Observed sequence numbers:**

| Frame | Direction | Sequence |
|---|---|---|
| 5487 | Server → Client | 4 |
| 5493 | Server → Client | 2 |
| 5494 | Server → Client | 3 |
| 5501 | Server → Client | 4 |
| 5502 | Client → Server | 5 |
| 5509 | Client → Server | 6 |
| 5510 | Client → Server | (no sequence, 20 bytes) |
| 5511 | Client → Server | (no sequence, 36 bytes) |
| 5512 | Client → Server | (no sequence, 68 bytes) |

**Observation:** Not all TCP/17351 messages have a sequence field. Smaller messages (20–68 bytes) may have a different structure.

---

## 6. TLV catalog

### 6.1 Wire encoding

Two sources disagree on field order (see §2.3 and §13). Per PHASE_3 (§5.1), confirmed against PCAP #5486/#686, TLV records use Length (32-bit BE), Tag (32-bit BE), Value. The length field strictly indicates the size in bytes of the Value field.

Tag upper byte (first byte) defines the data type category.

### 6.2 Type taxonomy

Per `docs/PHASE_3_CONTROL_MESSAGE_CATALOG.md` §5.2, `RvControlSvc.exe` contains **exactly 744 unique TLV property descriptors**, registered via `call 0x4aec20`, distributed across 13 categories:

| Prefix | Type category | Unique tags | Internal representation |
|---|---|---|---|
| `0x01` | UINT32 | 377 | 4-byte unsigned integer, Big-Endian on wire |
| `0x02` | UINT64 | 110 | 8-byte unsigned integer (network IDs, epoch timestamps) |
| `0x03` | INT32 | 101 | 4-byte signed integer, Big-Endian (scalar primitive; "ID" is application semantics, not a wire type) |
| `0x04` | BOOL | 35 | Boolean (`0`=false, `1`=true); wire length (1 vs 4 bytes) not empirically confirmed in unencrypted PCAP |
| `0x05` | FLOAT | 5 | IEEE 754 single-precision (32-bit) |
| `0x06` | DOUBLE | 3 | IEEE 754 double-precision (64-bit) |
| `0x08` | COMPOUND | 4 | Composite binary structure / packed flags |
| `0x09` | BINARY / BLOB | 22 | Opaque binary buffer (RSA public keys, auth hashes, raw nodes) |
| `0x0A` | DATETIME | 14 | Extended temporal structure / timestamp |
| `0x0B` | STRING_UTF8 | 51 | UTF-8 string (no null termination on wire) |
| `0x0C` | OBJECT | 1 | Nested serialized object / record |
| `0x0D` | LIST / ARRAY | 7 | Contiguous homogeneous element collection |
| `0x0E` | MAP / CONTAINER | 14 | Associative key-value container |
| **Total** | — | **744** | `377+110+101+35+5+3+4+22+14+51+1+7+14 = 744` |

**Property descriptor (per `docs/reverse-engineering/round-02/03-tlv-catalog.md` §3):** In `RvControlSvc.exe`, `FUN_00498fe0` initializes a static table of property descriptors indexed by `prop_id` at address `0x00498fe0`. Each descriptor is 12 bytes:

```c
struct PropertyDescriptor {
    uint32_t tag;       // Full TLV tag (type + ID)
    uint16_t flags;     // Serialization / mandatory / cache flags
    uint16_t type;      // Internal Famatech type code
    uint32_t handler;   // Pointer to validation / conversion method
};
```

This source records **723 records** at `0x00498fe0`. PHASE_3 records **744 unique descriptors**; the difference is attributed to PHASE_3 including the `0x05` (Float), `0x06` (Double), and `0x0A` (DateTime) categories omitted by the older table, plus minor recounts in `0x01` (+3), `0x02` (+1), `0x03` (+3). This is a **conflicting claim** (see §13).

Per `round-02/03` §2, the older taxonomy (723 records) is:
| Upper byte | Type | Registered tags | Representation |
|---|---|---|---|
| `0x01` | UINT32 | 374 | 4-byte unsigned BE (or internal LE unpacked by architecture) |
| `0x02` | UINT64 | 109 | 8-byte unsigned (network IDs, timestamps) |
| `0x03` | INT32 / ID | 98 | 4-byte signed (status codes, numeric identifiers) |
| `0x04` | BOOL | 35 | 1 byte or 4 bytes (`0x00000000`=false, `0x00000001`=true) |
| `0x08` | COMPOUND | 4 | Composite binary / packed flags |
| `0x09` | BINARY / BLOB | 22 | Opaque buffer (RSA keys, auth hashes, raw nodes) |
| `0x0B` | STRING_UTF8 | 51 | UTF-8 string (network names, aliases) |
| `0x0C` | OBJECT | 1 | Nested object instance |
| `0x0D` | LIST / ARRAY | 7 | Contiguous homogeneous collection |
| `0x0E` | MAP / CONTAINER | 14 | Associative key-value container |

### 6.3 Critical tags confirmed by reverse engineering

| Tag hex | Conceptual name | Type | Evidence source | Functional meaning |
|---|---|---|---|---|
| `0x0100031f` | `PROP_CLIENT_PACKET_ID` | UINT32 | `RvROLClient.dll` `0x10016614` | Client-emitted packet ID (`0x04`, `0x14`, `0x27`, `0x2b`, `0x34`) |
| `0x01000320` | `PROP_SERVER_PACKET_ID` | UINT32 | `RvROLClient.dll` `0x1008a7d5` | Server-emitted packet ID (`0x15`, `0x25`, `0x26`, `0x28`, `0x29`, `0x2a`) |
| `0x010001df` | `PROP_NETWORK_STATUS` | UINT32 | `RvControlSvc.exe`, `RvROLClient.dll` `0x100162f8`/`0x10015bf9` | Connection status code (`1`=initializing/requesting, `2`=approved/active) |
| `0x0100032b` | `PROP_PROTOCOL_CAPS` | UINT32 | `RvROLClient.dll` `0x10016311`, PCAP #5486 | Radmin protocol capability/extension bitmask |
| `0x010001e3` | `PROP_NET_CONN_ATTR` | UINT32 | `RvControlSvc.exe` `0x41537e`, `RvROLClient.dll` `0x1004ef1c` | Operational network attributes (routing, access control, broadcast); **not** member count |
| `0x010001ea` | `PROP_VIRTUAL_IP` | UINT32 | `RvControlSvc.exe`, `RvROLClient.dll` `0x100412a0` | IPv4 virtual address assigned to VPN interface (`26.0.0.0/8`) |
| `0x010001d8` | `PROP_CLIENT_VERSION` | UINT32 | `RvControlSvc.exe` property table | Client version (UINT32) |
| `0x010001db` | `PROP_MACHINE_ID` | UINT32 | `RvControlSvc.exe` property table | Machine ID (UINT32) |
| `0x020001e1` | `PROP_NETWORK_ID` | UINT64 | `RvControlSvc.exe`, `RvROLClient.dll` | Unique 64-bit virtual network ID |
| `0x020001e2` | `PROP_NODE_ID` | UINT64 | `RvControlSvc.exe`, `RvROLClient.dll` | Unique 64-bit node/peer ID |
| `0x0200025e` | `PROP_NODE_LAST_SEEN` | UINT64 | `RvControlSvc.exe` | 64-bit epoch timestamp of peer last heartbeat |
| `0x040001e7` | `PROP_IS_ONLINE` | BOOL | `RvControlSvc.exe` | Peer online presence indicator |
| `0x090001ca` | `PROP_RSA_PUBKEY_BLOB` | BLOB | PCAP #5486/#686, `RvROLClient.dll` `0x10016328` | Client RSA-2048 public key blob (256 bytes) |
| `0x090001cd` | `PROP_AUTH_HASH` | BLOB | `shelper.dll` `0x10065790` | 20-byte SHA-1 digest of network password |
| `0x09000201` | `PROP_ENDPOINT_CANDIDATES` | BLOB | `RvROLClient.dll` | Serialized tuples of public/local IP and STUN ports for P2P discovery |
| `0x0b0001dc` | `PROP_NETWORK_NAME` | STRING_UTF8 | `RvControlSvc.exe`, `RvROLClient.dll` | UTF-8 name of the virtual Radmin network |
| `0x0b0001eb` | `PROP_PEER_ALIAS` | STRING_UTF8 | `RvControlSvc.exe` | Peer display name / hostname (UTF-8) |

### 6.4 Tag `0x010001e3` clarification

Previous analyses questioned whether `0x010001e3` represented a node count or a network attribute.

- `RvControlSvc.exe` `0x41537e`:
  ```
  0x41537e: mov eax, dword ptr [ebp - 0x14] ; extracted tag = 0x010001e3
  0x415381: cmp eax, 0x010001e3
  0x415386: jne 0x41539a
  0x415388: mov edx, dword ptr [ebp + 0xc]  ; pointer to 32-bit value
  0x41538b: mov dword ptr [esi + 0x34], edx ; writes to local network flags/attributes
  0x41538e: or dword ptr [esi + 0x30], 2    ; sets modified-attribute flag
  ```
- `RvROLClient.dll` `0x1004ef1c` (`ProcessNetworkUpdate`):
  ```
  0x1004ef1c: push 0x010001e3
  0x1004ef21: mov ecx, edi
  0x1004ef23: call 0x10022370        ; look up property value in TLV container
  0x1004ef28: test eax, eax
  0x1004ef2a: je 0x1004ef3e
  0x1004ef2c: mov ecx, dword ptr [eax]
  0x1004ef2e: mov dword ptr [ebx + 0x48], ecx ; stores network topology type / permissions
  ```

**Conclusion:** Tag `0x010001e3` is a UINT32 representing **operational network attributes** (routing mode, access control, broadcast capabilities), **not** a node count. Node count is dynamically computed from the node list/array (`0x0d0001e4`) or via explicit `ROLClient_GetNodes` request.

### 6.5 BOOL wire-length status

The taxonomy registers 35 boolean properties (`0x04`), e.g. `PROP_IS_ONLINE` (`0x040001e7`). MSVC `bool` is 1 byte; Win32 `BOOL` is 4 bytes. In the unencrypted PCAP samples available, only `0x01` (UINT32) and `0x09` (BLOB) properties appear in the clear; no `0x04` boolean was present unencrypted. **The exact wire `Length` encoding of booleans (1 byte vs 4 bytes) remains unconfirmed empirically.** A defensive Rust parser should accept lengths of 1 and 4 bytes until validated in a dynamic testbed.

---

## 7. Authentication and network messages

### 7.1 Password hashing

The client never transmits the password in plaintext. The credential is derived in `shelper.dll` at `0x10065790`, which invokes the default Windows CryptoAPI CSP requesting **SHA-1** (`CALG_SHA1 = 0x00008004`):

```
0x10065790: push ebp
0x10065791: mov ebp, esp
0x10065793: push esi
0x10065794: mov esi, dword ptr [ebp + 8]   ; pointer to UTF-8 password string
...
0x1006579b: push 0x8004                    ; ALG_ID = CALG_SHA1 (0x8004)
...
0x100657a7: call dword ptr [0x100800dc]    ; CryptCreateHash(hProv, CALG_SHA1, 0, 0, &hHash)
...
0x100657ba: call dword ptr [0x100800e0]    ; CryptHashData(hHash, pbData, dwDataLen, 0)
...
0x100657c3: mov dword ptr [ebp - 8], 0x14  ; 20 bytes (160-bit SHA-1 digest)
...
0x100657d3: call dword ptr [0x100800e4]    ; CryptGetHashParam(hHash, HP_HASHVAL, pbData, pdwDataLen, 0)
```

The resulting **20-byte digest** is inserted into the TLV container under tag **`0x090001cd`** (`PROP_AUTH_HASH`).

### 7.2 Network join flow (`ROLClient_JoinNetwork`)

Entry points in `RvROLClient.dll`:
- `0x100412a0`: `ROLClient_JoinNetwork` (high-level invocation)
- `0x1004a090`: construction of the TLV request container
- `0x100a16e0`: return registration and asynchronous dispatch

Flow (AES-256-CBC channel already established):

1. Client computes `Hash = SHA-1(password_utf8)`.
2. Client builds `CJoinNetworkPacket` (vtable `0x101145e0`, constructor `0x10017950`):
   - `0x0100031f`: `0x00000027` (Command ID `0x27` / 39)
   - `0x0b0001dc`: UTF-8 network name string
   - `0x090001cd`: 20-byte `PROP_AUTH_HASH` digest
   - `0x0100032b`: client capability bitmask
3. Server evaluates the credential and replies via the dispatch table (`0x1008bb3c`):
   - Preliminary confirmation: `CRosPktJoinNetwork` (Command ID `0x28` / 40, vtable `0x10118718`).
   - Approval with virtual IP assignment: `CRosPktJoinApproved` (Command ID `0x2a` / 42, vtable `0x10118c2c`).

### 7.3 Join status codes (`0x010001df`)

Evaluated in `RvROLClient.dll` (`0x1004a115`):
- `0`: `SUCCESS` — Join completed; virtual IP and Network ID bound.
- `1`: `ERR_INVALID_PASSWORD` — Password hash incorrect or rejected.
- `2`: `ERR_NETWORK_NOT_FOUND` — Network not present in the server directory.
- `3`: `ERR_NETWORK_FULL` — Member limit reached.
- `4`: `ERR_ALREADY_MEMBER` — Node already a registered active member of the network.

### 7.4 Administrative network management (`CManageNetworkPacket`)

Administrative operations (create, leave, delete network) are encapsulated in `CManageNetworkPacket` (vtable `0x101146cc`, constructor `0x10018210`):
- `0x0100031f`: `0x00000034` (Command ID `0x34` / 52).
- Server confirms via `CRosPktManageNetReply` (Command ID `0x25` / 37, vtable `0x1011881c`).

### 7.5 Public networks enumeration

- Request: `CEnumPublicNetworksPacket` (Command ID `0x2b` / 43, vtable `0x101143f4`).
- Response: `CRosPktPublicNetworks` (Command ID `0x2d` / 45, vtable `0x10118c94`).

### 7.6 Network and node synchronization

Network information is sent by the server via `CRosPktNetworks` (Command ID `0x26` / 38, vtable `0x10118850`) and `CRosPktNetworksChanges` (Command ID `0x29` / 41, vtable `0x10118884`). Member count is derived from the node list (`0x0d0001e4`) or an explicit `ROLClient_GetNodes` request, **not** from tag `0x010001e3`.

Each peer record in a node synchronization container carries:
- `0x020001e2` (`PROP_NODE_ID`): unique peer identifier (64 bits).
- `0x010001ea` (`PROP_VIRTUAL_IP`): virtual IPv4 in `26.0.0.0/8` (32 bits BE).
- `0x0b0001eb` (`PROP_PEER_ALIAS`): peer display name/hostname (UTF-8).
- `0x040001e7` (`PROP_IS_ONLINE`): boolean, node connected to ROL servers.
- `0x0200025e` (`PROP_NODE_LAST_SEEN`): 64-bit epoch timestamp of last heartbeat.
- `0x09000201` (`PROP_ENDPOINT_CANDIDATES`): buffer of `(public_IP, STUN_port, local_IP, local_port)` tuples for direct P2P discovery.

### 7.7 Network status codes (`PROP_NETWORK_STATUS` — `0x010001df`)

Confirmed via disassembly of `RvROLClient.dll`:
- `0x100162f8` (emission in announcement): client writes `0x010001df = 1` into the 288-byte TLV announcement container (STATUS_INITIALIZING / join request state).
- `0x10015c02` (return validation):
  ```
  10015bf9: call 0x10014360        ; extract value of 0x010001df
  10015c02: cmpl $0x2, -0x30(%ebp) ; check if code == 2
  10015c06: jne 0x10015c30         ; if != 2, abort and run cleanup at 0x10005c80
  10015c08: mov dword ptr [esi + 0x78], 1 ; if == 2, mark state active (APPROVED)
  ```
- **Conclusion:** In the preliminary handshake, `1` = initializing/requesting and `2` = approved/active.

### 7.8 RvRvpnGui.exe network error codes (1002–1037)

The GUI contains the central error dispatch routine at `0x004ecf00`:
```
4ecf00: lea -0x3ea(%esi), %eax      ; subtract base offset 0x3ea (1002)
4ecf06: cmp $0x23, %eax             ; validate range of 36 entries (0..35, codes 1002 to 1037)
4ecf09: ja 0x4ece31                 ; out of range → generic formatter "\n(%1)"
4ecf0f: movzbl 0x4ed2e0(%eax), %eax ; consult 36-byte translation table at 0x004ed2e0
4ecf16: jmp dword ptr [0x004ed284 + eax*4] ; jump to corresponding handler (23 entries Jump[0]..Jump[22])
```

**Audited summary of the 36 codes (1002–1037):**
- Total codes in range: 36.
- Codes with specialized handler: 21 (20 descriptive + 1 empty).
- Descriptive text strings: 20.
- Empty strings: 1 (code 1029 → `Jump[18]` at `0x004ecf1d`, packs empty literal `""` at `0x005d25c6`).
- Codes with generic fallback formatter: 15 (share `0x004ece31`, `"\n(%1)"` at `0x005e87c8`).
- Jump table entries: 23 (`Jump[0]` to `Jump[22]`).
- Distinct handlers reached: 22 (21 specialized + 1 common fallback).
- Checksum: 21 specialized + 15 generic = 36 codes.

**21 codes with specialized handlers confirmed:**

| Code | Handler VA | String literal in binary | String address | Classification |
|---|---|---|---|---|
| 1002 (`0x03ea`) | `0x004ed25c` | `"Invalid network name or password"` | `0x005e87a4` | CONFIRMED |
| 1004 (`0x03ec`) | `0x004ecfba` | `"Cannot connect to ROL server"` (emitted in `RvROLClient.dll` `0x1004a1bd`) | `0x005e85b4` | CONFIRMED |
| 1006 (`0x03ee`) | `0x004ed11c` | `"Out of memory"` | `0x005e8704` | CONFIRMED |
| 1007 (`0x03ef`) | `0x004ecf6a` | `"Canceled"` | `0x005e8578` | CONFIRMED |
| 1008 (`0x03f0`) | `0x004ed1bc` | `"Timed out"` | `0x005e8750` | CONFIRMED |
| 1009 (`0x03f1`) | `0x004ed00a` | `"This network name has already been taken"` | `0x005e85f0` | CONFIRMED |
| 1011 (`0x03f3`) | `0x004ed16c` | `"ROL protocol error"` | `0x005e8730` | CONFIRMED |
| 1012 (`0x03f4`) | `0x004ecf92` | `"You cannot join this network without password"` | `0x005e8584` | CONFIRMED |
| 1013 (`0x03f5`) | `0x004ed234` | `"Connection prohibited"` | `0x005e878c` | CONFIRMED |
| 1014 (`0x03f6`) | `0x004ed194` | `"Service connection lost"` | `0x005dbecc` | CONFIRMED |
| 1015 (`0x03f7`) | `0x004ed144` | `"The password is too short"` | `0x005e8714` | CONFIRMED |
| 1016 (`0x03f8`) | `0x004ecf42` | `"Access denied"` | `0x005e8568` | CONFIRMED |
| 1017 (`0x03f9`) | `0x004ed032` | `"Network name should not be empty or longer than %1 characters"` | `0x005e861c` | CONFIRMED |
| 1019 (`0x03fb`) | `0x004ed07c` | `"Last administrator cannot leave the network"` | `0x005e865c` | CONFIRMED |
| 1020 (`0x03fc`) | `0x004ed0cc` | `"Network is closed to new members, joining impossible"` | `0x005e86b4` | CONFIRMED |
| 1021 (`0x03fd`) | `0x004ed0f4` | `"Network name collision"` | `0x005e86ec` | CONFIRMED |
| 1024 (`0x0400`) | `0x004ed0a4` | `"The virtual network limit has been reached"` | `0x005e8688` | CONFIRMED |
| 1029 (`0x0405`) | `0x004ecf1d` | `""` (empty string / text suppression) | `0x005d25c6` | CONFIRMED |
| 1032 (`0x0408`) | `0x004ed1e4` | `"User ignores you"` | `0x005e875c` | CONFIRMED |
| 1033 (`0x0409`) | `0x004ed20c` | `"You are muted in this chat"` | `0x005e8770` | CONFIRMED |
| 1037 (`0x040d`) | `0x004ecfe2` | `"Chat is under maintenance"` | `0x005e85d4` | CONFIRMED |

**15 codes routed to generic fallback formatter (`0x004ece31`, `"\n(%1)"`):**
`1003`, `1005`, `1010`, `1018`, `1022`, `1023`, `1025`, `1026`, `1027`, `1028`, `1030`, `1031`, `1034`, `1035`, `1036`.

No additional static evidence indicates specific text or semantics for these numbers; they behave as positions without custom strings or as reserved positions in the Famatech architecture.

> Note on legacy numbering (0–4): a previous simplified list (0=Success, 1=Invalid Password, 2=Not Found, 3=Network Full, 4=Already Member) was a preliminary conceptual abstraction. The real binary evidence shows operational errors traffic in the numeric range 1002–1037.

---

## 8. TCP relay (TcpRelay)

### 8.1 Overview

When two peers cannot establish a direct point-to-point connection (P2P via TCP Simultaneous Open or UDP STUN) because of restrictive firewalls or symmetric NATs, the client falls back to the centralized relay route (**TcpRelay**) operating on **TCP port 17351**.

### 8.2 Transport type enumeration (`RvControlSvc.exe` at `0x43fb60`)

```x86asm
0x43fb60: mov eax, dword ptr [esp + 4] ; enum code
0x43fb64: test eax, eax
0x43fb66: je 0x43fb80                 ; 0 -> "TCP" (Direct P2P)
0x43fb68: dec eax
0x43fb69: je 0x43fb88                 ; 1 -> "UDP" (Direct P2P)
0x43fb6b: dec eax
0x43fb6c: je 0x43fb90                 ; 2 -> "TcpRelay" (Relay on port 17351)
0x43fb6e: mov eax, 0x51d2a0           ; default -> "Unknown"
0x43fb73: ret
0x43fb80: mov eax, 0x51d2a8           ; "TCP"
0x43fb85: ret
0x43fb88: mov eax, 0x51d2ac           ; "UDP"
0x43fb8d: ret
0x43fb90: mov eax, 0x51d2b0           ; "TcpRelay"
0x43fb95: ret
```

### 8.3 TcpRelay flow in `radmin_17301.pcap`

After unsuccessful direct connection attempts, the client opens a TCP connection to `198.244.203.247:17351` (packets #688 to #710):

```
C1 -> R: TCP SYN (:49502 -> :17351)
R --> C1: TCP SYN-ACK (:17351 -> :49502)
C1 -> R: TCP ACK
C1 -> R: Pkt #695: Magic Framing + Relay Binding Request
        - Tag 0x10000004: Peer Target Node ID
        - Tag 0x50000020: Session Cookie / Auth Token
R --> C1: Pkt #701: Relay Binding Response
        - Tag 0x40000001: Relay Channel Status (0x01 = Ready)
C1 -> R: Pkt #705: Tag 0x300000c0 (E2E-encrypted payload destined for peer C2)
R --> C2: Forwards packet #705 unchanged
```

### 8.4 Control tags and encapsulation in TcpRelay

Framing on channel 17351 uses 4-byte big-endian prefixes, followed by TLV records dedicated to channel mediation:

| Hex tag | Description and purpose | Typical size |
|---|---|---|
| `0x10000004` | Target Node ID: numeric identifier of the requested destination peer | 4 bytes |
| `0x20000008` | Relay Routing ID: relay session identifier assigned by the server | 8 bytes |
| `0x300000c0` | Encapsulated Data: VPN Ethernet tunnel data frame (E2E-encrypted) | Variable (16-byte aligned) |
| `0x40000001` | Channel Status: flow-control flag / established channel | 1 byte |
| `0x50000020` | Session Cookie: ephemeral cryptographic token generated by the ROL server | 32 bytes |
| `0x600000c0` | Multiplexed Frame: multiplexed frame containing multiple sub-packets | Variable |
| `0x70000014` | Relay Keepalive: heartbeat of the TcpRelay tunnel | 20 bytes |

### 8.5 End-to-end encryption (E2E) in TcpRelay

- The TcpRelay server **does not hold the keys to decrypt the data frames**.
- The payload transmitted under tag `0x300000c0` is previously encrypted with the session key negotiated directly between the two peers (via peer-to-peer RSA-2048 / AES-256 handshake).
- The TcpRelay server only inspects the routing header (`0x10000004` / `0x20000008`) to forward the flow to the TCP socket of the corresponding peer, preserving end-to-end confidentiality and integrity of the data transported over the VPN.

---

## 9. NAT/STUN

### 9.1 Overview

To allow low-latency, high-bandwidth communication between machines in the same virtual network, Radmin VPN implements a NAT traversal mechanism based on the **STUN standard (RFC 3489)** on dedicated UDP ports maintained by the Famatech infrastructure.

### 9.2 STUN query ports

Observed in `radmin_vm2.pcap`, NAT probes are directed to central servers through a pool of UDP ports:
- `17309` / `17310`: Primary STUN (Tests I and II)
- `17347` / `17348` / `17349`: Secondary STUN servers and address-change verification servers
- `17357` / `17358`: STUN Binding Request / Response

### 9.3 Forensic analysis of STUN packets (`radmin_vm2.pcap`)

In packets #796 and #839:

```
Client (192.168.122.77:54536) ---> Pkt #796: Binding Request ---> Server (198.244.203.247:17348)
Client (192.168.122.77:54536) <--- Pkt #839: Binding Response <--- Server (198.244.203.247:17348)
```

**Packet #796 — Binding Request (RFC 3489):**
- Message Type: `0x0001` (Binding Request)
- Message Length: `0x0000` (no additional attributes in the basic test)
- Transaction ID: 16 pseudo-random bytes used for correlation: `[e1 a3 b9 4f ...]`.

**Packet #839 — Binding Response (RFC 3489):**
- Message Type: `0x0101` (Binding Response)
- Message Length: `0x0024` (36 bytes of attributes)
- Returned attributes:
  1. `0x0001` (MAPPED-ADDRESS): Family `0x01` (IPv4), Port `54536` (`0xd508`), IP `<CLIENT-PUBLIC-IP>` (`0xbb 0x3b 0xc7 0x27`) — reflexive public address detected for the client.
  2. `0x0004` (SOURCE-ADDRESS): Family `0x01` (IPv4), Port `17348`, IP `198.244.203.247`.
  3. `0x0005` (CHANGED-ADDRESS): Family `0x01` (IPv4), Port `17349`, IP `198.244.203.248` — alternative address used for Test II (restricted-cone classification).

**Note:** This is **not** standard RFC 5389 STUN: no magic cookie (`0x2112A442`) is present, and the transaction ID is 16 bytes (not 12).

### 9.4 NAT classification and direct connection procedure

The client algorithm closely follows the RFC 3489 flowchart:
- Test I (Binding Request): if mapped IP/port == local → no NAT / direct public IP.
- Otherwise NAT detected: Test II (change IP/port).
  - Response to Test II → Full Cone NAT (excellent for direct P2P).
  - No response → Test I on alternative server.
    - Mapped port changed → Symmetric NAT (direct P2P not viable → uses TcpRelay).
    - Mapped port unchanged → Test III (change port only).
      - Response received → Restricted Cone NAT (direct P2P via hole punching).
      - No response → Port Restricted Cone NAT (direct P2P requires mutual probing).

### 9.5 Direct P2P establishment techniques

**Direct UDP hole punching** (both clients classified as Cone NAT — Full Cone, Restricted, or Port Restricted):
1. The ROL coordination server exchanges `(Public_IP:STUN_Port)` tuples between both peers via tag `0x09000201`.
2. Both nodes send UDP datagrams simultaneously toward the reflexive IP and port of the other.
3. Receipt of the first datagram establishes the association (pinhole) in the local router/firewall table.
4. The point-to-point cryptographic handshake, identical to the control channel (RSA-2048 followed by AES-256-CBC), starts immediately.

**TCP Simultaneous Open** (UDP blocked by corporate policies):
1. The client schedules synchronous emission of TCP SYN packets from a previously bound local port toward the mapped port of the peer.
2. The synchronized SYN sends trigger the TCP Simultaneous Open mechanism (RFC 793), allowing transition from `SYN-SENT` directly to `SYN-RECEIVED` and `ESTABLISHED` without a conventional public listener.

**Fallback to TcpRelay:** If no direct probe (UDP or TCP) succeeds within 10 seconds, the state machine downgrades the connection to transport type `2` (`TcpRelay`).

### 9.6 NAT detection exports (`RvUESClient.dll`)

- `UESC_GetTcpNatType` (RVA 0x10005a10): TCP NAT type detection.
- `UESC_GetAddress` (RVA 0x10005910): address discovery.
- `UESC_Init` and `UESC_Shutdown`: initialization and shutdown.
- Log strings: `TcpNatChecker[%1].Bind/Connect/Recv/Send/Delta/InvalidAddress/InvalidResponce/DirectAddress/GetTcpNatType`.
- Hole punching structures: `CPenSocket`, `USNatPenPacket`, `USNatPenWave`, `USPenGroup`, `USOneAck`, `CPenWaveSenderReceiver`.
- `USPortPara`: port parameters.
- Connection types seen in the service: UDP/direct, UDP/nat, UDP/nat/random, UDP/teredo, TCP/direct, TCP/nat, TCP/teredo, Connections Relay.

Unknown: NAT detection algorithm; hole punching packet structure; STUN/TURN/relay servers; ports used; behavior with symmetric NAT.

---

## 10. Teredo

### 10.1 Overview

Radmin VPN includes a complete tunneling subsystem based on the **Teredo standard (RFC 4380)**, implemented in the internal class `CTeredoThread` of the `RvROLClient.dll` library. The main purpose is to provide an alternative point-to-point connectivity path through IPv6 encapsulated in UDP packets, when the intermediate network infrastructure blocks classic IPv4 P2P protocols or implements aggressive NATs.

### 10.2 Network traffic evidence (`radmin_vm2.pcap`, packet #10)

- Transport protocol: UDP
- Destination port: `3544` (default port assigned by IANA for the Teredo service)
- Relay server IP: `20.201.205.4:3544` (official public Teredo infrastructure of Microsoft)

The client sends routing requests and Teredo test packets with a null authentication header to qualify the viability of the IPv6 tunnel.

### 10.3 Teredo address structure and deobfuscation

The Teredo IPv6 address generated and processed by the client has 128 bits structured as defined in RFC 4380:

```
+----------------+----------------+----------------+----------------+
| Prefix 32 bits | Server IPv4    | Flags 16 bits  | Obfuscated Port|
| (2001:0000::)  | 32 bits        |                | 16 bits        |
+----------------+----------------+----------------+----------------+
| Obfuscated IPv4 Address (32 bits)                                 |
+-------------------------------------------------------------------+
```

### 10.4 Deobfuscation routine in `RvROLClient.dll` (`CTeredoThread`)

To work around NAT devices that inspect the payload for local IP addresses to translate incorrectly (ALG — Application Layer Gateway), Teredo obfuscates the reflexive port and IP by applying a bitwise XOR operation:

$$\text{RealPort} = \text{ObfuscatedPort} \oplus \text{0xFFFF}$$

$$\text{RealIPv4} = \text{ObfuscatedIPv4} \oplus \text{0xFFFFFFFF}$$

Disassembly of `RvROLClient.dll`:

```
0x10052310: movzx eax, word ptr [esi + 0x28] ; reads obfuscated port
0x10052314: xor eax, 0xffff                  ; deobfuscates port via XOR 0xFFFF
0x10052319: mov dword ptr [esi + 0x30], eax  ; stores the peer's real port
0x1005231c: mov eax, dword ptr [esi + 0x2a]  ; reads obfuscated IPv4
0x1005231f: xor eax, 0xffffffff              ; deobfuscates IPv4 via XOR 0xFFFFFFFF
0x10052324: mov dword ptr [esi + 0x34], eax  ; stores the decoded reflexive IP
```

### 10.5 Selection priority in the client architecture

In the transport decision tree, Teredo operates as a **secondary fallback strategy**:
1. If direct IPv4 P2P (UDP/TCP) fails;
2. If the client has an active Teredo adapter or support;
3. The client attempts communication via IPv6 encapsulation over Teredo through UDP port 3544 before finally falling back to the centralized `TcpRelay` server (port 17351).

---

## 11. Internal structures (RTTI-confirmed, not necessarily sent over the network)

| Name | Inferred role | Evidence | Status |
|---|---|---|---|
| `CCryptoChannel` | Encrypted channel | RTTI `?AVCCryptoChannel@RolClient@@` | Name confirmed; algorithm unknown here (see §12) |
| `CCryptoChannelNotificator` | Crypto channel notifier | RTTI | Name confirmed |
| `CAuthSessionId` | Authentication session ID | RTTI `VCAuthSessionId@rol@@` | Name confirmed |
| `VCUniqueConnectionId` | Unique connection ID | RTTI `VCUniqueConnectionId@2@` | Name confirmed |
| `VCRid` | Node or resource ID | RTTI `VCRid@rol@@` | Name confirmed |
| `VCNetWorker` | Network worker | RTTI | Name confirmed |
| `VCConnector` | Connector | RTTI | Name confirmed |
| `VCConnection` | Connection | RTTI | Name confirmed |
| `CConnectionPool` | Connection pool | RTTI | Name confirmed |
| `CEnetAbstractConnection` | Abstract Enet connection | RTTI `CEnetAbstractConnection@ENETConnect@@` | Name confirmed |
| `CEnetIocpConnection` | IOCP Enet connection | RTTI | Name confirmed |
| `CEnetScheduler` | Enet scheduler | RTTI | Name confirmed |
| `CEnetWrapper` | Enet wrapper | RTTI | Name confirmed |
| `CENETConnector` | Enet connector | RTTI `RolClient::CENETConnector` | Name confirmed |
| `CEnetChannelNotificator` | Enet channel notifier | RTTI | Name confirmed |
| `TMBufferQueueWithCode` (send and receive) | Coded buffer queues | RTTI `TMBufferQueueWithCode@W4ESendCode@...` / `W4ERecvCode@...` | Name confirmed |
| `CProxyAddressPool` | Proxy address pool | RTTI | Name confirmed |
| `CGenericAddressPool` | Generic address pool | RTTI | Name confirmed |
| `CProxyAddressChecker` | Proxy address checker | RTTI | Name confirmed |
| `CDEnetAddresses` | DEnet addresses | RTTI | Name confirmed |
| `USPortPara` | Port parameters | RTTI | Name confirmed |
| `USNatPenPacket` | NAT penetration packet | RTTI | Name confirmed |
| `USNatPenWave` | NAT penetration wave | RTTI | Name confirmed |
| `USPenGroup` | Penetration group | RTTI | Name confirmed |
| `USOneAck` | Single ACK | RTTI | Name confirmed |
| `CPenWaveSenderReceiver` | Wave sender and receiver | RTTI | Name confirmed |
| `CTeredoThread` | Teredo tunneling | `RvROLClient.dll` disassembly `0x10052310` | Name confirmed |

---

## 12. Cryptographic layer status (unknowns)

- Class `CCryptoChannel@RolClient@@` exists (RTTI).
- `ROLClient_SetCompression` (export, 0x10041fd0) and `ROLClient_DisableEncryption` (export, 0x10040830) exist, so compression and encryption are configurable.
- `FamCurl` with `?g_DefaultCaCertPem` (embedded CA PEM), used for HTTPS and DoH.
- `CPrivateSessionMsg`: private session messages, possibly encrypted.

**To reconcile:** an earlier version listed the algorithm as unknown. Later static analysis of `shelper.dll` (see `CONTROL_PROTOCOL.md` §6) identifies AES-256-CBC and RSA key exchange in the code. That evidence is static, from the code and RTTI, and has **not** been observed in traffic. Until the traffic is decrypted or the code paths are verified dynamically, treat the items below as unknown in this document.

| Item | Status here |
|---|---|
| Encryption algorithm | Unknown here. Static candidate in `CONTROL_PROTOCOL.md`. |
| Key derivation | Unknown |
| Key exchange | Unknown here. Static candidate in `CONTROL_PROTOCOL.md`. |
| Mode of operation | Unknown here. Static candidate in `CONTROL_PROTOCOL.md`. |
| Key size | Unknown here. Static candidate in `CONTROL_PROTOCOL.md`. |
| IV or nonce | Unknown |
| Message authentication (HMAC, AEAD) | Unknown |
| Replay protection | Unknown |
| Cryptographic record format | Unknown |
| Cryptographic serialization functions | Unknown |

**Evidence in this document:** RTTI strings and the export table. No identifiable algorithm string (AES, RSA, SHA) was found in these binaries at this stage.

---

## 13. Unknowns / not confirmed

- Internal payload structure of TCP control packets (fields, types, order).
- Packet type identifier within payloads.
- Payload encryption algorithm.
- Authentication handshake fields.
- Virtual IP range assigned by the server.
- Whether control and data channels are separate.
- Encryption algorithm, key derivation, key exchange, mode of operation, key size, IV/nonce, message authentication, replay protection, cryptographic record format, cryptographic serialization functions (see §12).
- ROS server hostname.
- Exact DoH endpoint beyond `https://%hs/dns-query`; DoH request format.
- Relay server addresses.
- NAT detection algorithm; hole punching packet structure; STUN/TURN/relay servers; ports used; behavior with symmetric NAT.
- NetMP60.sys: Ethernet frame format (EtherType, payload); specific IOCTL codes; packet structure between driver and service; MTU of the virtual interface; assigned IP range; whether it is pure L2 encapsulation or IP inside the driver.
- BOOL wire-length encoding (1 vs 4 bytes) — see §6.5.
- TLV wire field order (Length-Tag vs Tag-Length) — see §2.3 and §14.
- Total TLV descriptor count (723 vs 744) — see §6.2 and §14.
- TCP/17351 channel role — see §14.
- Handshake frame numbering (35/44) — see §14.

---

## 14. Sources

All sources read (first column `PROTOCOL_SPEC` in `analysis_workspace/compaction/mapping.tsv`):

1. `docs/PCAP_MESSAGE_CATALOG.md` — PCAP message catalog (traffic analysis, message examples, sequence numbers).
2. `docs/PHASE_3_CONTROL_MESSAGE_CATALOG.md` — Phase 3 control message catalog (Portuguese; prose translated in this document, identifiers/tags preserved verbatim).
3. `docs/PROTOCOL_SPEC.md` — Phase 2 protocol specification (framing, capture findings, export table, RTTI packet list, limitations).
4. `docs/reverse-engineering/round-02/03-tlv-catalog.md` — TLV catalog and message format (type taxonomy, 723-record descriptor table at `0x00498fe0`).
5. `docs/reverse-engineering/round-02/04-authentication-networks.md` — Authentication, network and member management (SHA-1 hashing, join flow, status codes, peer properties).
6. `docs/reverse-engineering/round-02/05-tcp-relay.md` — TcpRelay protocol and mediated connection (transport enum, relay tags, E2E encryption).
7. `docs/reverse-engineering/round-02/06-p2p-nat.md` — NAT discovery and direct P2P connectivity (STUN ports, packet analysis, NAT classification, hole punching).
8. `docs/reverse-engineering/round-02/07-teredo.md` — Teredo tunneling mechanism (CTeredoThread, port 3544, address deobfuscation, selection priority).

---

## 15. Provenance note

This document consolidates the 8 sources above without resolving contradictions. Conflicting claims are recorded below with pointers to `RECONCILIATION.md` for resolution; they are **not** resolved here.

**Conflicting claim 1 — Role of port 17351:**
- `docs/PROTOCOL_SPEC.md` §9.2 lists `45.162.230.182:17351` as "Alternate server" with the note that `CONTROL_PROTOCOL.md` lists 17351 as peer-to-peer.
- `docs/PCAP_MESSAGE_CATALOG.md` lists TCP 17351 as "Alternative control".
- `docs/PHASE_3_CONTROL_MESSAGE_CATALOG.md` §6 defines 17351 as the secondary coordination channel for preliminary node identity announcement (P2P/Relay) with an initial cleartext message, later encrypted.
- `docs/reverse-engineering/round-02/05-tcp-relay.md` defines TcpRelay (transport type `2`) on port 17351 as the fallback relay when direct P2P fails.
- **Status:** unresolved. See `RECONCILIATION.md`.

**Conflicting claim 2 — Handshake frame numbering (35/44):**
- Sources disagree on which frame number marks handshake completion / transition to encrypted traffic on port 17301 (claims reference frames 35 and 44).
- **Status:** unresolved. See `RECONCILIATION.md`.

**Additional observed discrepancies (not required by scope, recorded for traceability):**
- TLV wire field order: `docs/PHASE_3_CONTROL_MESSAGE_CATALOG.md` §5.1 (Length → Tag → Value, confirmed against PCAP #5486/#686) vs `docs/reverse-engineering/round-02/03-tlv-catalog.md` §1 (Tag → Length → Value).
- Total TLV descriptor count: `docs/PHASE_3_CONTROL_MESSAGE_CATALOG.md` §5.2 (exactly 744 unique descriptors in 13 categories) vs `docs/reverse-engineering/round-02/03-tlv-catalog.md` §3 (exactly 723 records at `0x00498fe0`; the older table omits the `0x05`/`0x06`/`0x0A` categories and undercounts `0x01`/`0x02`/`0x03`).

---

## Evidence appendix (exact tokens from consolidated sources)

Exact addresses, hashes and identifiers from the consolidated sources that are not repeated in the prose above. They are preserved here so that no evidence anchor is lost during compaction; the full narrative for each source remains available in git history.

- `docs/PHASE_3_CONTROL_MESSAGE_CATALOG.md`: `0x010001de`, `0x01000377`, `0x02000008`, `0x020001d5`, `0x090001dc`, `0x090001dd`, `0x10015bd0`, `0x10017706`, `0x1001795b`, `0x10017ece`, `0x10018221`, `2cc034ab7166361e4d9a68106ce3206819f51fc1`, `cabstractclnpacket@rolclient`, `crospacket@rolclient`
- `docs/PROTOCOL_SPEC.md`: `e16711e2e3e59f6603f51f437197215b1914a3d8316e1f633260178b959921f7`
- `docs/reverse-engineering/round-02/03-tlv-catalog.md`: `fun_00488ae0`
- `docs/reverse-engineering/round-02/04-authentication-networks.md`: `0x10065797`, `0x10065799`, `0x100657a0`, `0x100657a3`, `0x100657a6`, `0x100657ad`, `0x100657af`, `0x100657b1`, `0x100657b3`, `0x100657b6`, `0x100657b7`, `0x100657c0`, `0x100657ca`, `0x100657cc`, `0x100657cd`, `0x100657ce`, `0x100657d0`, `0x100657e0`
