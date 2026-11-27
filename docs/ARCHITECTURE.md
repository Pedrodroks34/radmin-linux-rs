# Architecture: Radmin VPN 2.1.4951.1 (consolidated reverse engineering)

Consolidated from 5 source files under `docs/`. All addresses, VAs, offsets, hashes, sizes, ports, frame numbers, function/class names, constants, evidence IDs, and confidence classifications are preserved verbatim from the sources. Repeated boilerplate is deduplicated; no technical fact is removed. Conflicts between sources are recorded in `## Provenance note` with a pointer to `RECONCILIATION.md` and are not resolved here.

---

## 1. Components and binaries

### 1.1 Official package (installer `Radmin_VPN_2.1.4951.1.exe`)

- Installer: 54.3 MB, Inno Setup with a nested MSI. Source: `docs/REVERSE_ENGINEERING.md` (Executive summary). Classification: Confirmed.
- `RvRvpnGui.exe`: GUI, Qt 5.15 / QML (`docs/REVERSE_ENGINEERING.md`); Qt / MFC (`docs/reverse-engineering/round-02/10-architecture.md`). Classification: Confirmed (binary identity); GUI toolkit naming differs between sources — see `## Provenance note`.
- `RvControlSvc.exe`: Windows service, FamRT/C++ engine with IOCP; runs with `SYSTEM` privileges (`NT AUTHORITY\SYSTEM`). Classification: Confirmed.
- `RvROLClient.dll`: ROL client; 47 exports (connect, register, join network, send, receive, NAT, and others); client protocol for the Famatech cloud (Radmin Online). Classification: Confirmed (export count and role).
- `RvUESClient.dll`: NAT type detection; asynchronous event queue and internal telemetry between subsystems. Classification: Confirmed.
- `NetMP60.sys` / `NetMP60_1_1_64.sys`: virtual NDIS driver, `\\Device\RVPNNETMP`, L2 Ethernet; PDB project name `RvNetMP60.pdb`; driver version `NetMP60_1_1` (`.inf` and `.sys` strings); signed by Microsoft WHQL (`inspect_pe_certificates`). Classification: Confirmed.
- `shelper.dll`: cryptographic security isolation layer; static OpenSSL routines (`RSA_public_encrypt`, `RSA_private_decrypt`, `AES_set_encrypt_key`, `AES_cbc_encrypt`, `RAND_bytes`) and a 64-bit additive integrity sum. Classification: Confirmed (imports/strings).
- Legacy Radmin Server 3 components: `Radmin.exe`, `rchatx.dll`, `voicex.dll`, and others. Classification: Confirmed (present in installer contents).

### 1.2 External reference project (Wine-based)

- Target: https://github.com/baptisterajaut/radmin-vpn-linux (cloned to `references/radmin-vpn-linux/`, git-ignored). License: GPL-3.0.
- `rvpnnetmp.sys`: PE driver (mingw); emulates the NDIS miniport `NetMP60.sys`; creates `\Device\RVPNNETMP`; accepts IOCTLs from the service; queues frames in an IRP queue; routes by MAC; sends and receives through FIFOs.
- `tap_bridge`: native C binary; reads and writes frames between the Linux TAP and the FIFOs; two threads (incoming and outgoing); ARP snooping and gratuitous ARP; Minecraft multicast replication; JSON filters.
- `adapter_hook.dll`: injected PE DLL; IAT hooks in `RvControlSvc.exe` and `RvROLClient.dll`: renames the adapter, no-op `RegSetKeySecurity`, `GetProcAddress` hook for `GetNameInfoW`, perflib stubs, `LoadLibrary` watcher for `RvROLClient.dll`.
- `rvpn_launcher.exe`: PE injector; creates `RvControlSvc.exe` suspended and injects `adapter_hook.dll` with `CreateRemoteThread` and `LoadLibraryA`.
- `drvinst.exe`: PE stub; replaces Famatech's NDIS driver installer (would `abort()` under Wine); returns 0.
- `netsh.exe` / `netsh64.exe`: PE wrappers; translate Radmin `netsh interface ip` commands into `ip addr` and `ip link` on Linux through a relay file.
- `rvpn_dnsfix.so`: LD_PRELOAD (glibc); intercepts `getnameinfo` and `gethostbyaddr`; private addresses return numeric form immediately.
- `rvpn_reuseport.so`: LD_PRELOAD (wineserver); forces `SO_REUSEPORT` on every TCP socket created by the wineserver.

Scope note from source: findings in the reference project's sections 2 and 3 describe the external project's own work and are not verified by this repository's captures unless cross-checked.

---

## 2. Process tree and module inventory

### 2.1 Privilege split (Confirmed)

The official Windows environment splits Radmin VPN into two independent processes with different privilege levels:

1. `RvControlSvc.exe` (system service / background service): `NT AUTHORITY\SYSTEM`. Manages the virtual network adapter, interacts with the ROL coordination servers, manages keys and routes VPN traffic.
2. `RvRvpnGui.exe` (graphical user interface): logged-in user context (Session 1). Displays the UI, receives connect/disconnect clicks, shows networks and members; delegates everything to the service through IPC commands on the named pipe; no direct encryption code, no VPN sockets.

### 2.2 Module responsibilities

| Module | Responsibility |
|---|---|
| `RvRvpnGui.exe` | Presents the interface to the end user; delegates all VPN work to the service via named-pipe IPC |
| `RvControlSvc.exe` | Central orchestrator in user space; lifecycle of the network interface, routes, name resolution, packet dispatch |
| `RvROLClient.dll` | Client protocol for Famatech cloud (Radmin Online); user authentication, network listing, member join/leave, node discovery; NAT tests (RFC 3489 STUN); orchestrates Teredo tunneling (`CTeredoThread`) |
| `RvUESClient.dll` | Asynchronous event queue and internal telemetry between subsystems |
| `shelper.dll` | Cryptographic security isolation layer (OpenSSL routines + 64-bit additive integrity sum) |
| `NetMP60_1_1_64.sys` | Virtual NDIS driver exposing a Layer 2 Ethernet interface to the OS |

### 2.3 Concurrency and thread model (Confirmed via thread tracing)

In `RvControlSvc.exe` + `RvROLClient.dll`, the following specialized execution threads were identified:

1. Control I/O thread: maintains the TCP connection to port 17301 of the ROL servers.
2. Packet pump thread: continuously reads Ethernet frames from the network interface and hands them to the encryption layer.
3. IPC server thread: waits for graphical interface instances to connect to the named pipe.
4. Pipe Read Thread (IPC worker): carries GUI commands.
5. STUN / NAT thread: UDP probing; reflexive candidates.
6. Teredo Thread (`CTeredoThread`): IPv6/UDP 3544 tunnel.

### 2.4 Packet types identified via RTTI (`RvROLClient.dll`)

Extracted from C++ class names in the binaries (strings like `?AV*Packet@RolClient@@`). Binary structures are unknown (Classification: Unknown). Packet → inferred role:

| Packet | Inferred role |
|---|---|
| `CAbstractClnPacket` / `VIClnPacket` | Abstract client packet / interface |
| `CAbstractConnectionPacket` | Abstract connection packet |
| `CCancelJoinPacket` | Cancel joining a network |
| `CChatCommandPacket` | Chat command |
| `CChatGetNodesPacket` | Get nodes via chat |
| `CClientVersionInfo` | Client version information |
| `CConflictedIpAddressPacket` | IP conflict detection |
| `CConnectResultPacket` | Connection result |
| `CDirectEnetInfoPacket` | Direct Enet network info |
| `CEnetInfoPacket` | Enet network info |
| `CEnumPublicNetworksPacket` | Enumerate public networks |
| `CGenericPacket` | Generic packet |
| `CGetNodeRegionSupportPacket` | Node region support |
| `CGuiLanguagePacket` | GUI language |
| `CHeartbeatPacket` | Heartbeat / keep-alive |
| `CIsAlivePacket` | Liveness check |
| `CJoinNetworkPacket` | Join a virtual network |
| `CLoginPacket` | Login / authentication |
| `CLogPacket` | Log packet |
| `CManageNetworkPacket` | Manage a virtual network |
| `CMsgAuthFailed` | Authentication failed |
| `CMsgAuthFinished` | Authentication finished |
| `CMsgBadServerPacket` | Bad or invalid server |
| `CMsgNetPacket` | Network packet |
| `CMsgRosIgnored` | ROS message ignored |
| `CNatPenPackets` / `CNatPenStatusPacket` | NAT penetration packets |
| `CPacketConnection` (FamRT) | Packet connection |
| `CRequestTrsPacket` | TRS request |
| `CRosConnectionPacket` | ROS connection |
| `CRosPacket` / `IRosPacket` | ROS packet (interface) |
| `CRosPktChatCommandReply` | ROS chat command reply |
| `CRosPktCollectTcpNatInfo` | Collect TCP NAT info |
| `CRosPktLicInfo` | License info |
| `CRosPktPushInfo` | Info push (notification) |
| `CRServerInfoPacket` | R server info |
| `CSessionSummaryPacket` | Session summary |
| `CStartEnetPacket` | Start Enet |
| `CTcpInfoPacket` | TCP info |
| `CTcpNatInfoPacket` | TCP NAT info |
| `ReplyPacket` (ControlSvc) | Service reply packet |

Supporting classes identified: `CPenSocket`, `USNatPenPacket`, `USNatPenWave`, `USPenGroup`, `USPortPara`, `CAuthSessionId`, `CRosAddress`, `CRosSessionId`, `CCryptoChannel`, `VCRosSessionId`, `VCConnector`, `VCConnection`, `CConnectionPool`, `CEnetScheduler`, `CChatRegionSupportCache`, `CNodeMapEntry`, `CVNetWorker`, `CConContainer`, `NTcpConnect`, `NTrsConnect`, `ENETConnect`.

---

## 3. Named-pipe IPC

### 3.1 Channel identification (Confirmed)

Communication between GUI and service happens exclusively through Windows named pipes. Canonical identifier in UTF-16: `\\.\pipe\RadminVpnGuiChannel`.

### 3.2 Server side (`RvControlSvc.exe`)

Initialization routine at `0x40f040` creates the named pipe with capacity for up to 200 simultaneous client instances:

```
0x40f040: push ebp
0x40f041: mov ebp, esp
0x40f043: push 0xc8                 ; nMaxInstances = 200 (0xC8)
0x40f048: push dword ptr [ebp + 8]  ; security attributes (SECURITY_ATTRIBUTES)
0x40f04b: add ecx, 0xe0
0x40f051: push 0x519e74             ; L"\\\\.\\pipe\\RadminVpnGuiChannel"
0x40f056: call 0x47de40             ; CreateNamedPipeW(..., PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED, ...)
0x40f05b: movzx eax, al
0x40f05e: pop ebp
0x40f05f: ret 4
```

Pipe creation at `0x47de40`; string VA `0x519e74`; `PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED`.

### 3.3 Client side (`RvRvpnGui.exe`, routine `FUN_004e8eb0`)

The GUI locates the pipe at memory address `0x5e7fe4` and connects asynchronously through `0x5352d0`:

```
0x4e8f28: push dword ptr [0x5e7fd4] ; connection timeout
0x4e8f2e: mov ecx, ebx
0x4e8f30: push dword ptr [0x5e7fd0] ; open mode
0x4e8f36: push dword ptr [esi + 0x11c] ; overlapped I/O handle
0x4e8f3c: push 0x5e7fe4             ; L"\\\\.\\pipe\\RadminVpnGuiChannel"
0x4e8f41: call 0x5352d0             ; CreateFileW / WaitNamedPipeW
0x4e8f46: test al, al
0x4e8f48: je 0x4e8fb0
```

### 3.4 Message structure and command protocol

An initial 25-byte handshake frame is exchanged as soon as the GUI connects to the named pipe, to validate the IPC channel version. Commands are then serialized through routine `FUN_004e2ac0`.

Confirmed command identifiers (`FUN_004e2ac0`, from disassembly of callers):

| Code (Hex) | Code (Dec) | Call site | Meaning / Operation | Parameters |
|---|---|---|---|---|
| `0x3f6` | 1014 | `0x4e8f78` | Service event subscription: sent immediately by the GUI after opening the pipe to register interest in network state notifications | `param = 0` |
| `0x3ec` | 1004 | `0x4e92b6` | Connect / re-enable VPN command: sent when the user clicks the main connect or reconnect button | `param = 1` |
| `0x3ed` | 1005 | `0x4e9304` | Disconnect / pause VPN command: turns off traffic on the virtual adapter | `param = 0` |
| `0x3ee` | 1006 | `0x4e9352` | Adapter status query: requests the current status of the NDIS driver and the assigned IP address | `param = 0` |
| `0x3ef` | 1007 | `0x4e9295` | Connected-state notification: signals the GUI has assumed the active, ready state | `param = eax` |

### 3.5 IPC message envelope format

Each message sent over the named pipe has a fixed header followed by the payload:

```
+-----------------------------+-----------------------------+-----------------------------+
| MAGIC IDENTIFIER (4 bytes)  | COMMAND_ID (4 bytes, LE)    | PAYLOAD_LENGTH (4 bytes, LE)|
+-----------------------------+-----------------------------+-----------------------------+
| DATA PAYLOAD (Length bytes...)                                                          |
+-----------------------------------------------------------------------------------------+
```

### 3.6 Architectural equivalent for the Linux client

On native Linux, the equivalent mechanism with full functional parity:
- Mechanism: UNIX domain sockets (`AF_UNIX`) bound to `/var/run/radmin-vpn.sock` (or under `XDG_RUNTIME_DIR/radmin-vpn.sock` in user mode).
- Access security: POSIX file permissions `0660`, assigned to the `radminvpn` group or to local administrators (`root`).
- Protocol: the Rust client can implement the native binary envelope for compatibility with any ported GUI, or expose an IPC API based on JSON-RPC over the UNIX socket.

---

## 4. NDIS virtual adapter and IOCTLs

### 4.1 Driver overview (Confirmed)

On Windows, the virtual network interface is implemented by the kernel-mode driver `NetMP60_1_1_64.sys` (PDB project name `RvNetMP60.pdb`), designed as an NDIS 6.0+ miniport driver that creates a control device accessible from user mode via `NdisRegisterDeviceEx`.

Initialization routine in `NetMP60_1_1_64.sys` at `0x14000c05c` registers the following identifiers in the Windows Object Manager:

- Kernel device name: `\Device\RVPNNETMP` (offset `0x9dd0`, VA `0x14000d7d0`)
- Symbolic link for user mode: `\DosDevices\RVPNNETMP`, accessible via `CreateFileW(L"\\\\.\\RVPNNETMP", ...)` by the class `rvpn::CNetMPDevice` in `RvControlSvc.exe`
- Registry parameter for the MAC address: `NetVRadminMacAddress`

### 4.2 IOCTL codes (Confirmed; see conflict note below)

Static analysis of `DeviceIoControl` calls in `RvControlSvc.exe` revealed exactly 5 IOCTL codes (`docs/reverse-engineering/round-02/09-ndis-driver.md`). `CTL_CODE(DeviceType=0x22, Function, Method=METHOD_BUFFERED (0), Access)`:

| IOCTL hex | Function dec | Access | In/Out buffer | Disassembly / call site | Semantics and purpose |
|---|---|---|---|---|---|
| `0x22c004` | 1 | READ \| WRITE | In: 8 B, Out: 12 B | `0x4b017f` in `RvControlSvc.exe` | Central device control: exchange of synchronization events and pointers to asynchronous I/O buffer descriptors |
| `0x228014` | 5 | FILE_WRITE_DATA | In: 6 B, Out: 0 B | `0x4b0123` (`push 6` at `0x4b0117`) | MAC address configuration: sets the 6-byte Ethernet MAC address of the virtual adapter |
| `0x224018` | 6 | FILE_READ_DATA | In: 0 B, Out: 4 B | `0x4b003a` (`push 4` at `0x4b002d`) | Statistics / MTU query: obtains link speed or the driver's MTU limit |
| `0x22801c` | 7 | FILE_WRITE_DATA | In: 4 B, Out: 0 B | `0x4b00a4` (`push 4` at `0x4b0098`) | Operational state / MTU setting: enables/disables packet flow or changes the MTU |
| `0x224020` | 8 | FILE_READ_DATA | In: 0 B, Out: 1 B | `0x4aff8a` (`push 1` at `0x4aff7d`) | Media status query: returns `0x01` for a connected cable (`MediaConnectStateConnected`) or `0x00` for disconnected |

The reference project (`docs/REFERENCE_PROJECT_ANALYSIS.md` §2.2) lists 7 IOCTLs derived from its own reverse engineering of `RvNetMP60.sys` and call sites in `RvControlSvc.exe`, partially overlapping the 5 above but with conflicting semantics on shared codes and two additional codes (`0x00224010`, `0x00228024`):

| IOCTL | Code | Input | Output | Inferred role (reference project) |
|---|---|---|---|---|
| `IOCTL_RVPN_VERSION` | `0x0022C004` | 8 bytes (version and MAC) | 12 bytes | Version registration. If version is 4, returns `[status=0][MAC 6 bytes][pad 2]`. Otherwise `[status=1]`. |
| `IOCTL_RVPN_STATUS` | `0x00224018` | 0 | 4 bytes | Adapter status. Bit 0 means media present and active; the service checks `status != 0 && (status & 1)`. |
| `IOCTL_RVPN_CONNECT` | `0x00224020` | 0 | 1 byte | NDIS connection state. Returns `0x20` (`NdisMediaStateConnected`). If 0 bytes are written, `DeviceIoControl` fails and the service sees `CDeviceRemoved`. |
| `IOCTL_RVPN_SETLINK` | `0x00224010` | 0xB8B | 0xB8 | Statistics or link. Responds with a zeroed block of 0xB8 bytes. |
| `IOCTL_RVPN_SETUP` | `0x0022801C` | 4 bytes (mode) | 0 | Sets the TLV format mode. Mode 2 or higher enables `dest_mac_prefix` in the read TLV. |
| `IOCTL_RVPN_PEERMAC` | `0x00228014` | 6 bytes (MAC) | 0 | Registers which `FILE_OBJECT` (handle) answers for which peer MAC. Used by the RX thread to route unicast. |
| `IOCTL_RVPN_SETMAC` | `0x00228024` | variable | variable | Per-peer ownership ACK. Returns 1 byte. |

Conflicts between the two IOCTL catalogs (code count 5 vs 7; differing semantics on shared codes `0x224018`, `0x224020`, `0x228014`, `0x22801c`) are recorded in `## Provenance note` and not resolved here.

### 4.3 Ethernet frame pump mechanism (packet pump)

Dispatch routine in `NetMP60_1_1_64.sys` (`0x1400030cc` to `0x140003259`) confirms the asynchronous packet I/O model:

**Outbound (VPN transmission):**
1. Windows TCP/IP stack sends an Ethernet frame (e.g., ping to `26.x.x.x`) to the driver.
2. Driver completes the pending read IRP with the frame bytes (14 B Ethernet header + IP payload); IRP completed successfully (1514 bytes).
3. `RvControlSvc` (`rvpn::CNetMPDevice`) encrypts the Ethernet frame via AES-256-CBC.
4. Service forwards to servers or peers through the tunnel.

**Inbound (VPN reception):**
1. Service receives and decrypts the Ethernet frame from the tunnel.
2. Service issues `WriteFile` / IOCTL with the decrypted Ethernet frame to the driver.
3. Driver calls `NdisMIndicateReceiveNetBufferLists` to inject the frame into the OS network stack.

### 4.4 Linux equivalent (TAP)

On native Linux, the NDIS driver infrastructure is unnecessary. Standard TAP interface `/dev/net/tun` with flags `IFF_TAP | IFF_NO_PI`:
1. Operates at Layer 2, receiving/transmitting raw Ethernet frames of 14-byte header plus IP payload.
2. Default MTU 1500 bytes (maximum frame size 1514 bytes) set natively with `ioctl(SIOCSIFMTU)`.
3. 6-byte MAC address assigned natively with `ioctl(SIOCSIFHWADDR)`.
4. Packet pumping performed by simple asynchronous `read`/`write` calls on the `AsyncFd` of `/dev/net/tun`.

---

## 5. Reference project / Wine analysis

### 5.1 Overview

The external project (https://github.com/baptisterajaut/radmin-vpn-linux, cloned to `references/radmin-vpn-linux/`, git-ignored; GPL-3.0) runs the official Windows client (`RvControlSvc.exe` and `RvRvpnGui.exe`) under Wine, replacing incompatible components with native Linux implementations. Goal: extract RE findings from the external project and cross-check them against this repository's static RE and captured traffic, to build an independent Rust client without Wine, Windows drivers, DLLs, or external hooks as dependencies. The project's own sections 2 and 3 are not verified by this repository's captures unless cross-checked in §4 of that document.

Data flow:

```
RvControlSvc.exe (Wine)
    ├─ DeviceIoControl \\.\RVPNNETMP (IOCTLs: VERSION, STATUS, CONNECT, SETUP, PEERMAC, ...)
    │     │
    │     ▼
    └─ rvpnnetmp.sys (PE shim driver, running under Wine)
            │ TLV-encoded frames over named pipes (FIFOs)
            │   Z:\tmp\rvpn_b2d         (bridge to driver)
            │   Z:\tmp\rvpn_d2b_high    (driver to bridge, high priority)
            │   Z:\tmp\rvpn_d2b_low     (driver to bridge, low priority)
            ▼
    tap_bridge (native Linux)
            │ [u16 len][frame] over FIFO / raw frame over TAP
            ▼
    TAP device (radminvpn0) ←─ virtual L2 network visible to Linux
```

### 5.2 Frame protocol (TLV — reference project claims, not verified here)

Extracted from comments and code of `rvpnnetmp.c`:

| Context | Format | Field 1 | Field 2 | Field 3 |
|---|---|---|---|---|
| Service read (driver to service) | TLV, mode 2 or higher | `u32 dest_mac_prefix` (host byte order, byte-swapped) | `u32 frame_len` | `frame_data` (minimum 60 bytes, zero-padded) |
| Service write (service to driver) | raw frame | Ethernet frame (14 bytes header plus payload) | none | none |
| Bridge FIFO (driver and tap_bridge) | `[u16 len][frame]` | `u16 frame_len` (native byte order) | `frame_data` | none |

Important detail: `dest_mac_prefix` is the first 4 bytes of the destination MAC of the Ethernet frame, byte-swapped (`ntohl`). The service compares it with the MACs of peers registered through `IOCTL_RVPN_PEERMAC`. Without the byte swap, unicast frames match no peer and are silently dropped. Frames shorter than 60 bytes are zero-padded to 60 bytes (Ethernet minimum).

Two distinct framings coexist in the evidence: the 4-byte big-endian payload-size header on the TCP control channel (capture-confirmed, see §6) and the TLV `[dest_mac_prefix][frame_len][frame_data]` on the service↔driver FIFO (reference project claim, not verified). They operate at different layers and are not in conflict.

### 5.3 FIFOs (named pipes through Wine's `Z:` drive)

| Path | Direction | Purpose |
|---|---|---|
| `Z:\tmp\rvpn_b2d` | bridge to driver | Frames from the TAP arriving at the service (RX) |
| `Z:\tmp\rvpn_d2b_high` | driver to bridge | High priority: TCP, ICMP, unicast UDP, ARP |
| `Z:\tmp\rvpn_d2b_low` | driver to bridge | Low priority: broadcast, multicast, non-IP |
| `Z:\tmp\rvpn_d2b` | legacy | Single legacy pipe, not used by the new code |

### 5.4 MAC routing (PeerMAC)

The driver keeps a table of pairs `(FILE_OBJECT, MAC[6])`. Dynamic: starts with 16 slots and doubles up to 4,096. Unicast frames go to the `FILE_OBJECT` whose MAC matches the destination. Group frames (broadcast or multicast, bit 0 of the first MAC byte set) are delivered to one IRP per distinct `FILE_OBJECT`.

### 5.5 Priority detection (driver to bridge)

| Protocol | Priority |
|---|---|
| ARP (`0x0806`) | High |
| IPv4 TCP (6), ICMP (1) | High |
| IPv4 UDP unicast (17, bit 0 of destination MAC clear) | High |
| IPv6 TCP (6), ICMPv6 (58) | High |
| IPv6 UDP unicast (17, bit 0 of destination MAC clear) | High |
| Broadcast and multicast, non-IP | Low |

### 5.6 Uplink address detection

Two methods:
1. `GetBestInterface(8.8.8.8)`: trusted only if the IfIndex appears in the adapter enumeration.
2. Fallback: the only adapter that is UP, has a `FirstGatewayAddress`, and has a routable IPv4 address (not loopback, not link-local 169.254/16, not CGNAT 100.64/10).

If ambiguous (0 or more than 1 candidate), returns 0 and does not filter (safe behavior).

### 5.7 Interface filtering (`GetAdaptersAddresses` / `GetAdaptersInfo`)

`adapter_hook.dll` intercepts both IPHLPAPI functions:
- Renames the TAP adapter to `Famatech Radmin VPN Ethernet Adapter` or `Radmin VPN`.
- Hides every adapter that is neither the TAP nor the default route, by zeroing `FirstUnicastAddress` (GAA) or `IpAddressList` (GAI).
- Stops the ROL connector from advertising the IPs of docker0, vmnet, or tailscale as NAT candidates.

### 5.8 Reverse DNS short-circuit (`rvpn_dnsfix.so`)

LD_PRELOAD on glibc (service). Intercepts `getnameinfo` and `gethostbyaddr`. For private addresses (loopback 127/8, 10/8, 172.16/12, 192.168/16, APIPA 169.254/16, CGNAT 100.64/10; IPv6 loopback, link-local, site-local, ULA fc00::/7) returns the numeric address and numeric port immediately without DNS. Public addresses go to the real function.

### 5.9 SO_REUSEPORT (`rvpn_reuseport.so`)

LD_PRELOAD on `wineserver`. Intercepts `socket()`; for TCP sockets forces `SO_REUSEPORT` before `bind()`. Enables Radmin 2.1 TCP port-reuse NAT traversal: bind a listener on `uplink:PORT`, advertise the mapping, then bind outgoing sockets to the same local port. Without it, the Linux kernel rejects the second bind with `EADDRINUSE`, which the wineserver relabels as `WSAEACCES`.

### 5.10 Perflib stubs

Wine is missing four `advapi32` exports: `PerfIncrementULongCounterValue`, `PerfIncrementULongLongCounterValue`, `PerfDecrementULongCounterValue`, `PerfDecrementULongLongCounterValue`. Radmin 2.1 resolves seven exports in a cascade. If any fails, the counterset is not created, the per-peer counter object stays NULL, and the peer handshake is discarded, producing `error: 0x700000000`. The project answers with no-op stubs (`ERROR_SUCCESS`) through a `GetProcAddress` hook.

### 5.11 Minecraft multicast replication

`tap_bridge` detects IPv4 UDP packets to `224.0.2.60` (Minecraft LAN) and replicates them as broadcast to `26.255.255.255` and `255.255.255.255`, recalculating the IP checksum and zeroing the UDP checksum.

### 5.12 Internal driver structures (`rvpnnetmp.c`)

```c
struct _DEVICE_EXTENSION {
    BOOLEAN Connected;
    UCHAR   MacAddress[6];
    LONG    IoctlCount;
    LONG    StatusCount;
    ULONG   SetupMode;       // set by IOCTL_RVPN_SETUP (0x22801c)
    HANDLE  FifoB2D;         // bridge to driver (RX)
    HANDLE  FifoD2B_High;    // driver to bridge, high priority
    HANDLE  FifoD2B_Low;     // driver to bridge, low priority
};

struct _PEER_ROUTE {
    PFILE_OBJECT fo;
    UCHAR mac[6];
};

struct _RX_RING {
    volatile ULONG write_idx;
    volatile ULONG read_idx;
    struct { USHORT len; UCHAR data[1600]; } frames[16];
};
```

### 5.13 Ethernet frame format

Standard Ethernet II fields:
- Offset 0 to 5: destination MAC.
- Offset 6 to 11: source MAC.
- Offset 12 to 13: EtherType (big-endian): `0x0800` IPv4, `0x0806` ARP, `0x86DD` IPv6.
- Offset 14 onward: payload.

For IPv4:
- Offset 14 + 9 (byte 23 of the frame): IP protocol (1 ICMP, 6 TCP, 17 UDP).
- Offset 14 + 12 (byte 26 of the frame): source IP.
- Offset 14 + 16 (byte 30 of the frame): destination IP.

### 5.14 Cross-check: reference project vs this repository's RE and captures

Independent confirmations (reference project finding → our evidence → status):

| Finding of the external project | Our evidence | Status |
|---|---|---|
| `\\Device\RVPNNETMP` | Strings in `NetMP60_1_1_64.sys` | Confirmed |
| Driver is an NDIS 6 miniport, x86-64 | `file` and `.sys` strings | Confirmed |
| Service is `RvControlSvc.exe` | PE imports (`StartServiceCtrlDispatcherW`, and others) | Confirmed |
| GUI connects through named pipe `\\.\pipe\RadminVpnGuiChannel` | Service strings | Confirmed |
| Control port TCP 17301 | Wireshark capture (non-HTTP port with significant traffic) | Confirmed |
| Server `148.113.190.78:17301` | Wireshark capture | Confirmed |
| Frame header: 4-byte big-endian payload size | Wireshark capture (several examples) | Confirmed |
| Control packet `00 00 00 04 03 00 00 00` | Wireshark capture | Confirmed (structure), meaning not confirmed |
| Reconnection opens a new TCP connection (different source port) | Wireshark capture (port 49526 after 56923) | Confirmed |
| Driver signed by Microsoft WHQL | `inspect_pe_certificates` | Confirmed |
| Driver version `NetMP60_1_1` | `.inf` and `.sys` strings | Confirmed |
| DNS over HTTPS `https://%hs/dns-query` | `RvROLClient.dll` strings | Confirmed |
| Hardcoded public resolvers (1.1.1.1, 8.8.8.8, 9.9.9.9, and others) | `RvROLClient.dll` strings | Confirmed |

Findings of the external project that corroborate this repository's RE:

| Finding | External evidence | Our evidence | Status |
|---|---|---|---|
| Emulated NDIS driver replaces `NetMP60.sys` | Code of `rvpnnetmp.sys` | Strings of the original `.sys` | Confirmed |
| Ethernet frames travel over the virtual adapter | Code of `tap_bridge` and `rvpnnetmp.c` | Wireshark capture (we see TCP 17301, not Ethernet frames) | Probable |
| MAC routing for multiple peers | Driver code (`g_peer_routes`) | RTTI `VCUniqueConnectionId`, `VCConnection` | Probable |
| Frame priority (TCP and ICMP above broadcast) | Driver code (`classify_high_priority`) | Not observed directly | Hypothesis |
| Per-peer NAT traversal with SO_REUSEADDR and TCP port reuse | Code of `rvpn_reuseport.so` and docs | Strings `TcpNatChecker` and `Connections TCP/nat` in the service | Probable |
| Peer handshake fails without perflib counters | `wine-perflib.md` docs | RTTI `CAuthSessionId`, `CMsgAuth*` | Probable |

Architectural differences (reference project vs independent Rust client):

| Aspect | External project | Our project (independent Rust) |
|---|---|---|
| Client execution | Wine plus official Windows client | Native Rust code (no Wine) |
| Network driver | `rvpnnetmp.sys` (PE) emulated under Wine | Native Linux TUN/TAP |
| Service-to-driver channel | Named FIFOs plus Windows IOCTL | Not applicable (no Windows driver) |
| Driver-to-TAP channel | FIFOs plus `tap_bridge` | TUN/TAP directly from Rust |
| netsh translation | `netsh_wrapper.exe` | `netlink` / `rtnetlink` in Rust |
| Reverse DNS fix | `rvpn_dnsfix.so` (LD_PRELOAD on glibc) | Not needed (Rust controls its own DNS) |
| SO_REUSEPORT fix | `rvpn_reuseport.so` (LD_PRELOAD on wineserver) | Rust controls sockets directly |
| Perflib stubs | IAT hook on `advapi32` | Not applicable (we do not use `advapi32`) |
| Interface filtering | Hook on `GetAdaptersAddresses` / `GetAdaptersInfo` | Not needed (we control which IPs to advertise) |
| GUI | Windows client Qt (under Wine) | Rust CLI (optional TUI later) |

Reusable components (concepts, not code; external project code is GPL-3.0 and cannot be copied):

| Concept | Source | Use in our Rust client |
|---|---|---|
| TLV framing: 4-byte length prefix | `rvpnnetmp.c`, `tlv_encode_frame` | Parser for TCP framing in our `transport` module |
| TLV with destination MAC prefix (4 bytes) | `rvpnnetmp.c` | Peer addressing structure |
| TCP and ICMP priority over broadcast | `classify_high_priority` | Priority queue in our transport |
| Unicast routing by MAC | `g_peer_routes` | Peer table keyed by virtual address |
| ARP snooping and gratuitous ARP | `tap_bridge.c` | Virtual address cache in our `network` module |
| Numeric reverse DNS for private addresses | `rvpn_dnsfix.c` | Not needed (Rust does not call glibc `getnameinfo` indirectly) |
| SO_REUSEPORT for NAT traversal | `rvpn_reuseport.c` | Rust sets `SO_REUSEADDR` and `SO_REUSEPORT` directly on sockets |
| Perflib counters for peer handshake | `wine-perflib.md` | Session and authentication structure to be found through dynamic RE |
| Minecraft multicast to broadcast | `replicate_mcast_to_bcast` | Not needed (limited scope) |

Limitations of the reference project:
- GPL-3.0 license: C/C++ code cannot be copied into the Rust project without making it GPL-3.0 and documenting origin; used only as conceptual reference.
- Not a native client: runs the official Windows client under Wine; contains no native network protocol code, only environment adaptation.
- Specific version: validated against Radmin VPN 2.1.4951.1 (same version as this target); 2.0.4899.9 also works; 1.4 not supported.
- Does not reveal the packet protocol: never decoded the content of TCP Ethernet frames between peers; ROS control protocol and data packets remain unknown.
- Does not reveal the authentication handshake.
- Does not reveal the encryption algorithms: `CCryptoChannel` not analyzed by either project.

Remains unknown (both projects):
- Binary structure of ROS packets (`CRosPkt*`, `CMsg*`, `CLoginPacket`, and others).
- Device-to-server authentication handshake.
- Encryption algorithms in `CCryptoChannel` (static candidates in `CONTROL_PROTOCOL.md`).
- Format of Ethernet frames between peers (what is inside the TLV payload).
- Virtual IP addressing (the `26.x.x.x` range not confirmed by either project).
- Peer-to-peer ports (NAT traversal uses port 17301 for control; data ports unknown).

---

## 6. Evidence index

| Evidence ID | Source file(s) | Detail | Classification |
|---|---|---|---|
| `Radmin_VPN_2.1.4951.1.exe` | `docs/REVERSE_ENGINEERING.md` | Installer, 54.3 MB, Inno Setup + nested MSI | Confirmed |
| `\\Device\RVPNNETMP` | `docs/reverse-engineering/round-02/09-ndis-driver.md`; cross-checked `docs/REFERENCE_PROJECT_ANALYSIS.md` | Kernel device name, offset `0x9dd0`, VA `0x14000d7d0` | Confirmed |
| `NetMP60_1_1_64.sys` | `docs/reverse-engineering/round-02/09-ndis-driver.md` | NDIS 6.0+ miniport; PDB `RvNetMP60.pdb`; init `0x14000c05c`; dispatch `0x1400030cc`–`0x140003259` | Confirmed |
| Driver version `NetMP60_1_1` | `docs/REFERENCE_PROJECT_ANALYSIS.md` §4.1 | `.inf` and `.sys` strings | Confirmed |
| WHQL signature | `docs/REFERENCE_PROJECT_ANALYSIS.md` §4.1 | `inspect_pe_certificates` | Confirmed |
| `RvControlSvc.exe` | `docs/REVERSE_ENGINEERING.md`; `docs/reverse-engineering/round-02/08-windows-ipc.md` | System service, SYSTEM privileges; named pipe creation `0x40f040`/`0x47de40` | Confirmed |
| `RvRvpnGui.exe` | `docs/REVERSE_ENGINEERING.md` | GUI; Qt5 imports | Confirmed |
| `\\.\pipe\RadminVpnGuiChannel` | `docs/reverse-engineering/round-02/08-windows-ipc.md` | Named pipe; client string at `0x5e7fe4`; `CreateFileW`/`WaitNamedPipeW` via `0x5352d0` | Confirmed |
| IPC commands `0x3ec`–`0x3f6` | `docs/reverse-engineering/round-02/08-windows-ipc.md`; diagram ref in `docs/reverse-engineering/round-02/10-architecture.md` | 5 confirmed command IDs | Confirmed |
| `RvROLClient.dll` | `docs/REVERSE_ENGINEERING.md` | 47 exports; RTTI packet class names; structures unknown | Confirmed (names), Unknown (structures) |
| `shelper.dll` | `docs/reverse-engineering/round-02/10-architecture.md` | `RSA_public_encrypt`, `RSA_private_decrypt`, `AES_set_encrypt_key`, `AES_cbc_encrypt`, `RAND_bytes`; 64-bit additive integrity sum | Confirmed |
| AES-256-CBC frame encryption | `docs/reverse-engineering/round-02/09-ndis-driver.md` | Packet pump encryption in service | Confirmed |
| IOCTL catalog (5 codes) | `docs/reverse-engineering/round-02/09-ndis-driver.md` | `0x22c004`, `0x228014`, `0x224018`, `0x22801c`, `0x224020` | Confirmed |
| IOCTL catalog (7 codes) | `docs/REFERENCE_PROJECT_ANALYSIS.md` §2.2 | `0x22C004`, `0x224018`, `0x224020`, `0x224010`, `0x22801C`, `0x228014`, `0x228024` | Confirmed (external project claim) |
| TCP control port 17301 | `docs/REVERSE_ENGINEERING.md` §Traffic findings; cross-checked `docs/REFERENCE_PROJECT_ANALYSIS.md` §4.1 | Wireshark capture | Confirmed |
| Server `148.113.190.78:17301` | `docs/REVERSE_ENGINEERING.md`; `docs/REFERENCE_PROJECT_ANALYSIS.md` §4.1 | Main server; alternates `198.244.203.247`, `45.162.230.182` | Confirmed |
| Frame header | `docs/REVERSE_ENGINEERING.md` | 4-byte big-endian `uint32_t` payload size; header not included in size | Confirmed |
| Header validation | `docs/REVERSE_ENGINEERING.md` | 54 frames from 3 TCP flows; 22,824 bytes consumed; 0 left over; no truncation; streams 0/1/2: 19/18/17 frames, 11,260/5,920/5,644 bytes | Confirmed |
| Control packet `00 00 00 04 03 00 00 00` | `docs/REVERSE_ENGINEERING.md` | Header size 4, payload `03 00 00 00`; meaning not confirmed (keep-alive / ACK / handshake) | Confirmed (structure) |
| Reconnection | `docs/REVERSE_ENGINEERING.md` | New TCP connection from different source port after disconnect; ~30 s; ports 49526 after 56923 | Confirmed |
| PCAP files | `docs/REVERSE_ENGINEERING.md` | `/tmp/radmin_vm.pcap` (~21 MB, ~6,360 packets); `/tmp/radmin_vm2.pcap` (~196 KB, ~69 TCP frames); `/tmp/radmin_17301.pcap` (~30 KB, 3 TCP flows) | Evidence location |
| DoH `https://%hs/dns-query` | `docs/REFERENCE_PROJECT_ANALYSIS.md` §4.1 | `RvROLClient.dll` strings | Confirmed |
| Hardcoded resolvers | `docs/REFERENCE_PROJECT_ANALYSIS.md` §4.1 | `1.1.1.1`, `8.8.8.8`, `9.9.9.9`, and others | Confirmed |
| ROS servers not hardcoded | `docs/REVERSE_ENGINEERING.md` | No server IP found in binaries | Confirmed |
| Encryption/compression exports | `docs/REVERSE_ENGINEERING.md` | `SetCompression`, `DisableEncryption` | Confirmed to exist |
| NAT traversal classes | `docs/REVERSE_ENGINEERING.md` | `CPenSocket`, `USNatPenPacket`, `USNatPenWave` | Confirmed to exist |
| Extraction directory | `docs/REVERSE_ENGINEERING.md` | `/tmp/opencode/radmin_ext/` (outside repository) | Evidence location |
| Ghidra project | `docs/REFERENCE_PROJECT_ANALYSIS.md` §8 | `/tmp/opencode/ghidra_project/radmin_project.rep` | Evidence location |
| Reference project | `docs/REFERENCE_PROJECT_ANALYSIS.md` | `references/radmin-vpn-linux/`, git-ignored, GPL-3.0 | Evidence location |
| Framing parser | `docs/REVERSE_ENGINEERING.md` | `src/protocol/framing.rs` (8 passing tests); `src/transport/mod.rs` (5 integration tests) | Implemented |

Capture setup (`docs/REVERSE_ENGINEERING.md`): interface `virbr0` (libvirt bridge); VM IP `192.168.122.77`.

---

## Sources

The following 5 source files were consumed for this draft:

1. `docs/REFERENCE_PROJECT_ANALYSIS.md`
2. `docs/REVERSE_ENGINEERING.md`
3. `docs/reverse-engineering/round-02/08-windows-ipc.md`
4. `docs/reverse-engineering/round-02/09-ndis-driver.md`
5. `docs/reverse-engineering/round-02/10-architecture.md`

---

## Provenance note

This draft consolidates, but does not resolve, conflicts between the 5 sources. Conflicting items are flagged below with a pointer to `RECONCILIATION.md`, where they must be adjudicated:

1. **IOCTL catalog size and semantics.** `docs/reverse-engineering/round-02/09-ndis-driver.md` states exactly 5 IOCTL codes (`0x22c004`, `0x228014`, `0x224018`, `0x22801c`, `0x224020`). `docs/REFERENCE_PROJECT_ANALYSIS.md` §2.2 lists 7 IOCTLs, adding `0x00224010` (`IOCTL_RVPN_SETLINK`) and `0x00228024` (`IOCTL_RVPN_SETMAC`). Shared codes carry conflicting semantics: `0x224018` is "Statistics / MTU query" (round-02) vs "Adapter status, bit 0 = media present" (reference); `0x224020` returns `0x01`/`0x00` (round-02) vs `0x20` (`NdisMediaStateConnected`) (reference); `0x228014` is "MAC address configuration" (round-02) vs "register `FILE_OBJECT` per peer MAC" (reference); `0x22801c` is "operational state / MTU" (round-02) vs "TLV format mode" (reference). See `RECONCILIATION.md`.

2. **GUI toolkit.** `docs/REVERSE_ENGINEERING.md` names `RvRvpnGui.exe` as Qt 5.15 / QML; `docs/reverse-engineering/round-02/10-architecture.md` names it Qt / MFC. See `RECONCILIATION.md`.

3. **Encryption placement.** `docs/reverse-engineering/round-02/09-ndis-driver.md` places AES-256-CBC encryption of Ethernet frames inside the service's packet pump; `docs/reverse-engineering/round-02/10-architecture.md` places RSA-2048 / AES-256 / SHA-1 in `shelper.dll` used by `RvROLClient.dll`; `docs/REFERENCE_PROJECT_ANALYSIS.md` states `CCryptoChannel` encryption algorithms are unknown to both projects. See `RECONCILIATION.md`.

4. **IOCTL buffer sizes on shared codes.** `docs/reverse-engineering/round-02/09-ndis-driver.md` gives `0x224018` as In 0 B / Out 4 B; `docs/REFERENCE_PROJECT_ANALYSIS.md` gives `IOCTL_RVPN_STATUS` output as 4 bytes — sizes agree, semantics conflict (see item 1). See `RECONCILIATION.md`.

Non-conflicting but distinct: two frame formats coexist at different layers — the capture-confirmed 4-byte big-endian payload-size header on the TCP control channel (port 17301), and the reference project's unverified TLV `[dest_mac_prefix][frame_len][frame_data]` on the service↔driver FIFO. Both are preserved; neither invalidates the other.

All unverified reference-project claims (§5.2–5.13, "not verified here") are preserved verbatim with their origin noted; none are promoted to confirmed status in this draft.
---

## Evidence appendix (exact tokens from consolidated sources)

Exact addresses, hashes and identifiers from the consolidated sources that are not repeated in the prose above. They are preserved here so that no evidence anchor is lost during compaction; the full narrative for each source remains available in git history.

- `docs/reverse-engineering/round-02/08-windows-ipc.md`: `0x40f052`
- `docs/reverse-engineering/round-02/09-ndis-driver.md`: `0x00000103`
- `docs/reverse-engineering/round-02/10-architecture.md`: `0x300000c0`
