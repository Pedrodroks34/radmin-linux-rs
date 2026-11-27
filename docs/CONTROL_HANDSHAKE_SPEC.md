# Control Handshake Specification — SRP-6a (Canonical, Consolidated)

> **Project**: Radmin VPN Linux (Interoperability with the Official Client)
> **Status**: Canonical SRP-6a specification; consolidated from phase reports 10.13–10.19 and the pre-existing `docs/CONTROL_HANDSHAKE_SPEC.md`
> **Binary reference**: `shelper.dll` (sha256 `d89daf6bcd5cafa3c7f6173f835ccf045baf8e7134f868819db6fd7615959ac4`), `RvROLClient.dll` (sha256 `6ba7dfecd38183d4bff0fc53f1c8c05d25e636077fe753b1220912aa58938177`), `RvControlSvc.exe` (sha256 `546efad9ab3ff85c2a50d61524d754bec94a3f3e30d6ae8addef481a1e8daa1e`)
> **Reference PCAP captures**: `radmin_17301.pcap`, `radmin_vm.pcap`, `radmin_vm2.pcap`
> **Control port**: TCP `17301`

---

## Scope and Canonical Status

This document is the canonical SRP-6a control-handshake specification. It consolidates (dedupes) phase reports 10.13 through 10.19 plus the pre-existing `docs/CONTROL_HANDSHAKE_SPEC.md` into one narrative. Every technical fact is backed by static disassembly of the shipped binaries; nothing is invented.

Where phases contradict each other, both claims are recorded with addresses and the open question is flagged rather than silently resolved. Two contradictions are central:

1. **Step endianness.** The pre-existing spec claimed little-endian step values on the wire; later phases established big-endian emission (`00 00 00 01` for step 1) and refuted the little-endian claim. History is recorded in §5.
2. **The `k` multiplier.** The pre-existing spec claimed `k = 3` CONFIRMED at `shelper.dll!0x100607d0`. Later phases established a second, SRP-6a path computing `k = SHA-1(N ‖ PAD192(g))` at `0x10060810` (client) and `0x10060ec0` (server), while the literal-3 slot at `0x100607d0` remains confirmed but its runtime selection (which class/descriptor is instantiated) is unresolved. History is recorded in §4.

See `docs/CRYPTO_PHASE_10_10_RECONCILIATION.md` (RECONCILIATION target) for the cross-phase reconciliation of `k`, step endianness, identity encoding, and the AES key split. The password encoding remains `UNKNOWN` throughout (see §11 and §14).

---

## 1. Overview and Discovery Context

In Phase 1 (`SHelper_RSession_*`), reverse engineering identified that `shelper.dll` exports two independent and mutually exclusive families of cryptographic handshake:

1. **Family A — `SHelper_RSession_*`** (`0x1006b860`, `0x1006a2b0`, `0x1006ba80`):
   - RSA-2048 handshake (`RSA_PKCS1_PADDING`) with an exchange of a 256-byte block containing 64 bytes of CSPRNG output (`RAND_bytes`).
   - Implemented and verified in Phase 1.
2. **Family B — `SHelper_*`** (`0x1006ab90`, `0x1006ad20`, `0x1006b1e0`, `0x1006b010`, `0x1006b1d0`):
   - Mutual authentication and key agreement handshake based on **SRP-6a** (Secure Remote Password, tjw / Thomas J. Wu implementation) with a 1536-bit modular prime and generator $g = 5$.
   - Used by the control and network-management subsystem (`RvROLClient.dll!FamRT::CSRPHelperInstance`, `RolClient::CSRPClient`, `RolClient::CRosProtocol_SRP_ManageNetwork`).
   - It is the protocol executed on the TCP control connections on port `17301` identified in the PCAPs (`radmin_17301.pcap` flows `49494` and `49493`, and `radmin_vm2.pcap` flows `49526`, `49537`, `49538`).

### Forensic Confidence Matrix (pre-existing baseline, updated in §4–§5)

| Component / Characteristic | Classification | Binary / Network Evidence |
|---|---|---|
| Cryptographic algorithm (SRP-6a) | **CONFIRMED** | Method tables `0x100ad75c` (`"SRP-6a client (tjw)"`) and `0x100ad7b4` (`"SRP-6a server (tjw)"`) in `shelper.dll`. |
| Network protocol version (`version = 3`) | **CONFIRMED** | `shelper.dll!0x1006b1d0` (`return 3`), `0x1006ab80` (`param_1 == 3`), verified in all PCAP flows in the initial packet `00 00 00 04 03 00 00 00`. |
| Modular SRP group (1536 bits, $g = 5$) | **CONFIRMED** | 192-byte buffer verified at `shelper.dll!0x100ac280`, checked at `0x100699e0` (modulus validator), and 1-byte generator at `0x100ac279` (`0x05`). |
| TLV item framing (`0x100626e0` / `0x10062900`) | **CONFIRMED** | Tag in the top 5 bits (`0xF8000000`), length in the lower 27 bits (`0x07FFFFFF`), 4-byte header in network byte order (big-endian). |
| Handshake tags (`0x10`..`0x70`) | **CONFIRMED** | Disassembly of `0x10066680` (Client) and `0x100670d0` (Server). |
| Client state machine (Cases 0, 2, 4, 6) | **CONFIRMED** | Full disassembly of `shelper.dll!0x10066680`. |
| Server state machine (Cases 1, 3, 5) | **CONFIRMED** | Full disassembly of `shelper.dll!0x100670d0`. |
| Key derivation function (40-byte KDF) | **CONFIRMED** | `shelper.dll!0x10061790`: iterative SHA-1 over $S \parallel counter\_be32$ producing 40 bytes (`0x28`). |
| AES-256 key installation in the `CChannel` | **CONFIRMED** | `RvROLClient.dll!0x1003dd40` and `0x100df250`: extracts the first 32 bytes (`0x20`) and installs them in `SHelper_CChannel_SetKeyEnc` / `SetKeyDec`. |
| Identity / username encoding | **CONFIRMED** (wire); **CONFIRMED** (hash, UTF-16LE) | `shelper.dll!0x10066680` Case 0: explicit conversion of little-endian `wchar_t` to big-endian UTF-16 (16-bit word byte swap). Hash reads `obj+0x8` raw (UTF-16LE) at `0x10060361`. |
| Credential structure after the handshake | **PARTIAL** | Exchange of authenticated messages in the TLV catalog after the keyed handshake (Phase 3). |
| Password encoding | **UNKNOWN** | Caller outside `shelper.dll`; no direct `call 0x10060340` / `0x10060c80` found. |

---

## 2. Cryptographic Group Parameters (SRP-1536)

The cryptographic group used by `shelper.dll` is a 1536-bit group compatible with the SRP parameters of Tom Wu / RFC 5054.

### 2.1 Modular Prime $N$ (1536 bits / 192 bytes)

Location: `shelper.dll!0x100ac280` (pinned via `memcmp` at `0x100699e0`):

```
e634471e75f2d76a0a3f5e252c5a6efb48edad645d31d9ecbc400416e14f5c6c
2ed378602d6eb8e9478b99e6474932393538b4be7177e0e05d3aaed17b5ae87a
a20f3dad37af019518f45b6dde76b2bfdfb140f379cc15383b304b7975b90796
7553cd6fdaf08d68832b603120430a501067d21beb2ce2275a20036a2dc80f1c
9d3ab9221afd5baceda5c2a31077c54fc6f274aaeba17ddd0b5c68f4f8e751a8
90a58648147a82e6f4f532ccdc939a12942799a713500e17dd4f6ff216cd54c7
```

Fail-closed group pinning: 192-byte $N$ and 1-byte $g$ compared against the pinned table at `0x100699e0` (client state 2 / server state 1). Mismatch aborts the handshake.

### 2.2 Generator $g$

Location: `shelper.dll!0x100ac279`:

```
g = 5 (0x05)
```

Descriptor `0x100ac358 → (0x100ac279, 1)`.

### 2.3 Hash Function

- **SHA-1** ($160$ bits / $20$ bytes output), standard IV `67452301 efcdab89 98badcfe 10325476 c3d2e1f0`, big-endian 20-byte digest.
- Internal routines: `0x10028810` (`SHA1_Init`), `0x100285f0` (`SHA1_Update`), `0x100286d0` (`SHA1_Final`).
- Init sets H0=`0x67452301`, H1=`0xefcdab89`, H2=`0x98badcfe`, H3=`0x10325476`, H4=`0xc3d2e1f0`, zeros the 0x60-byte state buffer.
- Final pads with `0x80`, zero-fills, appends the 64-bit big-endian bit length, outputs the big-endian 20-byte digest.

---

## 3. The $k$ Multiplier — k-Class Question (History + Current Status)

This section records the contradiction explicitly rather than picking a winner.

### 3.1 Legacy path — $k = 3$ (pre-existing spec claim)

Location: `shelper.dll!0x100607d0`:

```asm
100607d5: 6a 03                 push 0x3
100607d7: e8 04 ef ff ff        call 0x1005f6e0    ; BN from the immediate 3
100607ee: e8 1d fd ff ff        call 0x10060510    ; BN-based routine with the multiplier object
100607f6: e8 05 f2 ff ff        call 0x1005fa00    ; release multiplier object
```

- The literal integer `3` is passed through a BIGNUM object (`0x1005f6e0` constructor, `0x1005fa00` release).
- This routine sits at method-table slot `0xad74c` (file offset `0xabd4c`) of the `.data` method table; the table's name pointer at `0xad75c` → `0x100a3df0` (`"SRP-6a client (tjw)"` per some reports) / the neighboring table at `0xad760`..`0xad780` is the server table.
- The pre-existing `docs/CONTROL_HANDSHAKE_SPEC.md` classified this as **CONFIRMED**: "SRP multiplier ($k = 3$): `shelper.dll!0x100607d0`: `piVar1 = FUN_1005f6e0(3)` passing `k = 3` to `0x10060510`."

### 3.2 SRP-6a path — $k = \text{SHA-1}(N \parallel \text{PAD}_{192}(g))$ (later phases)

Locations: `shelper.dll!0x10060810` (client) and `shelper.dll!0x10060ec0` (server).

Client `0x10060810` (referenced from client descriptor offset `0x1c`):

1. `SHA1_Init(stack_ctx)` at `0x10060833`
2. BIGNUM copy of $N$ (from `context+0x0c`, width 192) via `0x1005fad0`
3. `SHA1_Update(N\_bytes, 192)`
4. Flag-controlled padding branch (`*(byte *)(param_1 + 4) & 2`; flags `= 3`, so the padded branch is live):
   - Padded: `0x1005f760` copies + left-zero-pads $g$ (from `context+0x10`) to 192 bytes
   - Unpadded: `0x1005fad0` copies $g$ raw
5. `SHA1_Update(g\_bytes, g\_len)`
6. `SHA1_Final` → 20-byte digest $k$
7. Digest → BIGNUM via `0x1005f710`; passed to `0x10060510` for the $u$/$S$ computation

Result: **$k = \text{SHA-1}(N \parallel \text{PAD}_{192}(g))$**, 20-byte digest. Independent arithmetic verification yields the known-answer digest `7b12a483fe77c3ed56e5a4dd8e7acc4fe7ec1233` for `SHA-1(N ‖ PAD(5,192))`.

Server `0x10060ec0` (referenced from server descriptor offset `0x18`): computes the same $k = \text{SHA-1}(N \parallel \text{PAD}_{192}(g))$.

### 3.3 Class-descriptor evidence

| Descriptor | VA (ptr) | String VA | String | VTable | `k` routine (offset 0x1c) |
|---|---|---|---|---|---|
| Client | `0x100ad75c` | `0x100a3df0` | `"SRP-6a client (tjw)"` | `0x100ad760` | `0x10060810` → $k = \text{SHA-1}(N \parallel \text{PAD}(g))$ |
| Server | `0x100ad7b4` | `0x100a3e18` | `"SRP-6a server (tjw)"` | `0x100ad7b8` | `0x10060ec0` → $k = \text{SHA-1}(N \parallel \text{PAD}(g))$ |

Notes:
- The legacy `k = 3` routine `0x100607d0` is referenced from table slot `0xad74c`; some reports place it in a legacy vtable `0x100ad74c` (server class). Its connection to an active SRP-6a descriptor is **not proven**.
- `0x10060810` hashes two BIGNUM serializations ($N$ then $g$); the operand provenance is established for the client descriptor path. Whether the digest is $k$ specifically, or another SRP digest role, was debated across phases (see §4 of the dispatch audit).
- Server $k$ provenance: `0x10060fa0` takes $k$ externally at object offset `+0x20`; whether the server's externally provided $k$ equals the client's $\text{SHA-1}(N \parallel \text{PAD}(g))$ is **UNKNOWN** (requires tracing `RvROLClient.dll` / `RvControlSvc.exe` callers).

### 3.4 Current status

- `FUN_100607d0` (literal `3`): **CONFIRMED** as disassembly; **STRONGLY_INFERRED** reachable via the `.data` method table at `0xad74c`; no direct call site traced; runtime selection **UNKNOWN**.
- `FUN_10060810` / `FUN_10060ec0` ($\text{SHA-1}(N \parallel \text{PAD}(g))$): **CONFIRMED** as disassembly; linked to the SRP-6a client/server descriptors; described by later phases (10.16/10.17/10.18/10.19, plus the 10.10 reconciliation) as the effective SRP-6a multiplier.
- Dispatch (which class the Radmin control channel instantiates): **NOT PROVEN**. The dispatch-audit phase (10.8/10.x) downgraded the "active SRP-6a dispatch" claim to an unverified hypothesis and classified $k$ as **UNKNOWN**, not `CONFIRMED_MISMATCH`.
- Resolution point: `docs/CRYPTO_PHASE_10_10_RECONCILIATION.md` (RECONCILIATION) consolidates the conflict and recommends SRP-6a ($k = \text{SHA-1}(N \parallel \text{PAD}_{192}(g))$) as the working assumption while flagging dispatch as unresolved.

---

## 4. Step Endianness History

### 4.1 Pre-existing spec claim (REFUTED)

The pre-existing `docs/CONTROL_HANDSHAKE_SPEC.md` claimed step values are **little-endian** on the wire (`01 00 00 00` for step 1) and that `RADMIN_SRP_K = 3` is correct.

### 4.2 Later-phase establishment (CONFIRMED)

`docs/CRYPTO_SRP_ANALYSIS.md` §3.1:

> The builder emits the step as **4-byte big-endian** (`00 00 00 01` for step 1), **NOT** little-endian. The existing `docs/CONTROL_HANDSHAKE_SPEC.md` claim of little-endian step values is **REFUTED**. Class: CONFIRMED for emission; STRONG INDICATION for receive-side dispatch (parser header is big-endian; step dispatch consistent).

`docs/CRYPTO_SRP_INTEGER_SERIALIZATION_AUDIT.md` §7–8 retracts the broader "Rust uses little-endian SRP integers" claim: Rust SRP BIGNUM integers (`N`, `g`, `A`, `B`, `S`, `u`) serialize **big-endian**; the `to_le_bytes()` uses in the codebase are 32-bit protocol step/version fields, not SRP integers.

### 4.3 Current on-wire step encoding

**Big-endian**, 4 bytes:

| Step | Wire bytes |
|---|---|
| 1 | `00 00 00 01` |
| 2 | `00 00 00 02` |
| 3 | `00 00 00 03` |
| 4 | `00 00 00 04` |
| 5 | `00 00 00 05` |
| 6 | `00 00 00 06` |

The version field (`version = 3`) is confirmed as value `3` (`0x1006b1d0` returns `3`; `0x1006ab80` checks `param_1 == 3`); its on-wire endianness is **unverified** (the initial PCAP frame `00 00 00 04 03 00 00 00` shows length `4` big-endian followed by `03 00 00 00`, but the version sub-field endianness was not separately established).

---

## 5. TLV Framing Protocol

Control communication on TCP port `17301` occurs in two framing layers:

### 5.1 Outer Layer: TCP Transport (Length-Prefixed)

Each message carried over the TCP connection has a 4-byte prefix in **big-endian**, indicating the exact length of the payload that follows:

```
+-------------------------+-----------------------------------------+
| Length (4B big-endian)  | Payload (N bytes)                       |
+-------------------------+-----------------------------------------+
```

### 5.2 Initial Protocol Version Negotiation

Immediately after the TCP connection is established (SYN / SYN-ACK / ACK):

1. The client sends a 4-byte frame containing the version:
   - Wire bytes: `00 00 00 04 03 00 00 00` (Length = 4, Protocol Version = 3).
2. The server responds by echoing the version frame:
   - Wire bytes: `00 00 00 04 03 00 00 00`.
3. Validation (`0x1006ab80`): if the value is different from `3`, the connection is aborted.

### 5.3 Inner Layer: TLV Items (`0x100626e0` builder, `0x10062900` parser)

Within the SRP handshake payloads, data is organized as a sequence of compact TLV items. Each item has a fixed 4-byte header, assembled in **big-endian**:

$$\text{Header} = (\text{Tag} \ \& \ \text{0xF8000000}) \ | \ (\text{Length} \ \& \ \text{0x07FFFFFF})$$

- Bits 31..27 (5 bits): Tag identifier (`0x10`, `0x20`, `0x30`, `0x40`, `0x50`, `0x60`, `0x70`)
- Bits 26..0 (27 bits): Length of the value in bytes (`0` .. `134,217,727`)

Parser bounds checks assert tag constants; each value is capped at `0x2800` bytes.

#### Catalog of Official Tags (`shelper.dll!0x10066680` and `0x100670d0`)

| Tag Value | Mapping in SRP | Description and Structure |
|---|---|---|
| `0x10000000` | Step Number | Protocol sub-state (4 bytes, `u32` **big-endian**: 1, 2, 3, 4, 5, 6). |
| `0x20000000` | Identity / Username | User/machine identity (UTF-16 byte-swapped characters on the wire; UTF-16BE per code unit). |
| `0x30000000` | Salt ($s$) | User salt generated by the server ($S$ bytes, typically 16 or 32 bytes). |
| `0x40000000` | Modulus $N$ | 1536-bit modular prime (192 bytes big-endian) or generator. |
| `0x50000000` | Generator $g$ | Generator $g = 5$ (1 byte) or auxiliary parameter. |
| `0x60000000` | Public Ephemeral | Public ephemeral key ($A$ sent by the client; $B$ sent by the server; 192 bytes). |
| `0x70000000` | Proof ($M_1$ / $M_2$) | Proof of key possession (20 bytes SHA-1: $M_1$ from the client; $M_2$ from the server). |

---

## 6. Step Table

| Step | Direction | Tags | Payload Semantics |
|---|---|---|---|
| 1 | C→S | `0x10` + `0x20` | step = `00 00 00 01` (BE), identity |
| 2 | S→C | `0x10` + `0x30` + `0x40` + `0x50` | step = `00 00 00 02`, salt, $N$, $g$ |
| 3 | C→S | `0x10` + `0x60` | step = `00 00 00 03`, $A = g^a \bmod N$ |
| 4 | S→C | `0x10` + `0x60` | step = `00 00 00 04`, $B = g^b \bmod N$ |
| 5 | C→S | `0x10` + `0x70` | step = `00 00 00 05`, $M_1$ |
| 6 | S→C | `0x10` + `0x70` | step = `00 00 00 06`, $M_2$ |

The state machine executes a synchronous sequence of 6 steps between Client and Server (Phase 0 = version validation; Phases 1–6 = the table above).

---

## 7. Client State Machine (Client States 0, 2, 4, 6)

Entry / jump table at `shelper.dll!0x10066680` (jump-table trace at `0x10066fdc`; note: Ghidra resolves `0x100665b0–0x100667a7` to a logging helper and `0x10066680` is not a clean function entry — state numbers rest on the earlier trace plus vtable bytes).

### State 0: Client Initialization (`0x10066680` Case 0)
- **Input**: None (`in_buf == NULL`).
- **Actions**:
  1. Sets `state = 1`, builds Item `0x10000000` with value `00 00 00 01` (4 bytes BE).
  2. Obtains the user identity (`wchar_t`), reverses the endianness of each 16-bit character to UTF-16BE for the wire (`0x100667b0` region: load u16 LE on x86, byte-swap, store).
  3. Stores the internal identity buffer at object `+0x08` (retained in its internal form).
  4. Builds Item `0x20000000` with the identity buffer (wire UTF-16BE).
  5. Transitions to `state = 2` (`WaitingServerParams`).
- **Output**: Concatenated buffer containing Item 1 + Item 2.

### State 2: Client Receives Server Parameters (`0x10066680` Case 2)
- **Input**: Buffer from Step 2.
- **Validations**:
  - Item `0x10000000` with value `2`.
  - Item `0x30000000` (salt $s$).
  - Items `0x40000000` and `0x50000000` validated against the expected group ($N$ and $g$) via the group pinning at `0x100699e0`; divergence transitions immediately to `Failed` (fail-closed).
- **Actions**:
  1. Stores salt at object `+0x14`.
  2. Computes $x$ (`0x10060340`), then $v = g^x \bmod N$ (`0x100602f0`).
  3. Generates ephemeral secret $a$ via CSPRNG (1536 bits of entropy); computes $A = g^a \bmod N$ (`0x10060410`). Context `+0x20` = $A$.
     - Note: the binary applies **no rejection sampling** (`RAND_bytes(192)` then `BN_add_word(a, 1536)` at `0x1005f830`); Rust's bounded-rejection loop is a behavioral divergence, not an interop difference (only $A$ matters).
  4. Builds Item `0x10000000` with value `00 00 00 03`.
  5. Builds Item `0x60000000` with $A$ (192 bytes big-endian).
  6. Transitions to `state = 4` (`WaitingServerProof`).

### State 4: Client Computes Proof $M_1$ (`0x10066680` Case 4)
- **Input**: Buffer from Step 4.
- **Validations**:
  - Item `0x10000000` with value `4`.
  - Item `0x60000000` containing $B$: strict canonical validation via `validate_srp_public_value` (`0x10060510` region): exact length 192 bytes, $1 \le B < N$, $B \bmod N \ne 0$; rejection of null/truncated/$\ge N$ values → `Failed`. Additional validation: base $(B - k \cdot v) \bmod N \ne 0$ (aborts with `InvalidPublicEphemeral` if null).
- **Actions**:
  1. Computes the random scrambler $u = \text{SHA-1}(\text{PAD}(A) \parallel \text{PAD}(B))$ (`0x10060810` → `0x10060510`).
  2. Computes the pre-master secret $S = (B - k \cdot (g^x \bmod N))^{a + u \cdot x} \pmod N$ (`0x10060510`: `BN_sub`/`BN_mul`/`BN_add`/`BN_mod`/`BN_mod_exp`).
  3. Runs the KDF over $S$ (`0x10061790`) to derive the 40-byte master key $K_{\text{full}}$.
  4. Computes the client proof $M_1$ (`0x100601b0` + `0x10060510`): $M_1 = \text{SHA-1}(H(N) \oplus H(g) \parallel H(I) \parallel \text{salt} \parallel A \parallel B \parallel K_{\text{full}})$. Optional auxiliary buffer `obj+0x30` appended when `len > 0` (writer and whether ever non-empty: **UNKNOWN**).
  5. Builds Item `0x10000000` with value `00 00 00 05`.
  6. Builds Item `0x70000000` with $M_1$ (20 bytes).
  7. Transitions to `state = 6`.

### State 6: Client Verifies $M_2$ and Completes (`0x10066680` Case 6)
- **Input**: Buffer from Step 6.
- **Actions**:
  1. Validates Item `0x10000000` with value `6` and Item `0x70000000` with $M_2$.
  2. Computes expected $M_2 = \text{SHA-1}(A \parallel M_1 \parallel K_{\text{full}})$ (`0x10060900`).
  3. Compares received vs computed.
  4. If identical: sets `is_established = true`, `is_complete = true`; session key available via `SHelper_GetKey` (`0x1006b010`); key = $K_{\text{full}}[0..32]$.

---

## 8. Server State Machine (Server States 1, 3, 5)

Entry `0x100670d0`, dispatcher `DEC EAX` → states 1/3/5 at `0x100676b1` / `0x100673fa` / `0x10067165`.

### State 1: Server Receives Client Initialization (`0x100670d0` Case 1)
- **Input**: Buffer from Step 1.
- **Validations**:
  - Item `0x10000000` with value `1`.
  - Item `0x20000000` (identity).
- **Actions**:
  1. Byte-swaps the UTF-16 identity back to little-endian (`0x100677d0`); stores it (internal form UTF-16LE).
  2. Locates user data (salt $s$ and verifier $v = g^x \pmod N$).
  3. Builds Item `0x10000000` with value `00 00 00 02`.
  4. Builds Item `0x30000000` with salt $s$.
  5. Builds Item `0x40000000` with the modular prime $N$ (192 bytes).
  6. Builds Item `0x50000000` with the generator $g = 5$ (1 byte).
  7. Transitions to `state = 3`.

### State 3: Server Computes Ephemeral $B$ (`0x100670d0` Case 3)
- **Input**: Buffer from Step 3.
- **Validations**:
  - Item `0x10000000` with value `3`.
  - Item `0x60000000` containing $A$: strict canonical validation (`validate_srp_public_value`): exact length 192 bytes, $1 \le A < N$, $A \bmod N \ne 0$; rejection → `Failed`.
- **Actions**:
  1. Generates secret ephemeral exponent $b$ (1536 bits, $1 < b < N - 1$).
  2. Computes $B = (k \cdot v + g^b) \pmod N$ (`0x10060ec0` → `0x10060d80`; context `+0x20` = $B$).
  3. Computes $u$, $S = (A \cdot v^u)^b \pmod N$ (`0x10060fa0`).
  4. Builds Item `0x10000000` with value `00 00 00 04`.
  5. Builds Item `0x60000000` with $B$ (192 bytes big-endian).
  6. Transitions to `state = 5`.

### State 5: Server Verifies $M_1$, Emits $M_2$ (`0x100670d0` Case 5)
- **Input**: Buffer from Step 5.
- **Actions**:
  1. Validates Item `0x10000000` with value `5` and Item `0x70000000` with $M_1$.
  2. Computes $S = (A \cdot v^u)^b \pmod N$, derives $K_{\text{full}}$, computes expected $M_1$.
  3. Compares received $M_1$ with expected; on divergence, rejects. **Non-constant-time, word-by-word early-exit comparison** (`0x100612f0`) — timing-sensitive.
  4. **Double-acceptance path (CONFIRMED):** the server accepts two $M_1$ forms — the canonical $M_1$ (accumulator `ctx+0x60`) and a legacy form $H(B \parallel A \parallel K)$ finalization (`ctx+0x120`). On the canonical path it appends $M_1$ and $K$ to `ctx+0x00` (which holds $A$) ⇒ $M_2 = \text{SHA-1}(A \parallel M_1 \parallel K)$; on the legacy path it finalizes `ctx+0xC0` (holds $A \parallel K$ only) ⇒ $H(A \parallel K)$.
  5. Canonical-path digest destination (`ctx+0x6a` in decompiler output vs `ctx+0x1A8` read by `0x10061450`) is **UNRESOLVED** — re-disassemble `0x10061000–0x100612F0`.
  6. Builds Item `0x10000000` with value `00 00 00 06`.
  7. Builds Item `0x70000000` with $M_2$ (20 bytes).
  8. Marks the handshake as established and complete.

---

## 9. Object and Context Layout

Object layout (both classes, confirmed from init/destroy and method bodies):

| Offset | Field |
|---|---|
| `+0x00` | Class tag (`0x0c` client / `0x1c` server) |
| `+0x04` | Flags = `3` (bit 1 = PAD mode active; `flags & 2 == 2` selects padding branch) |
| `+0x08` | Identity buffer (`{ptr, len}`; internal UTF-16LE) |
| `+0x0c` | $N$ (BIGNUM) |
| `+0x10` | $g$ (BIGNUM) |
| `+0x14` | Salt buffer (`{ptr, len}`) |
| `+0x18` | $v = g^x \bmod N$ (verifier) |
| `+0x1c` | $x$ (private password value, stored via `BN_bin2bn`-style conversion `0x1005feb0` client / `0x1005f710` server) |
| `+0x20` | Own public ephemeral ($A$ client / $B$ server) |
| `+0x24` | Private exponent ($a$ / $b$) |
| `+0x28` | $u$ (scrambler) |
| `+0x2c` | $S$ (shared secret) |
| `+0x30` | Auxiliary buffer (checked `len > 0`; appended to $M_1$ hash when non-empty; writer unknown) |
| `+0x34` | Vtable field |
| `+0x38` | Hash-context block (`malloc(0xE8)` client / `malloc(0x1BC)` server) |

SHA-1 context block (four 0x60-byte contexts at `context+0x38`):

| Offset | Purpose | Initialized at |
|---|---|---|
| `+0x00` | Primary SHA-1 context | `0x10060a42` |
| `+0x60` | $M_1$/$M_2$ accumulator | `0x10060a4e` |
| `+0xc0` | $K$ context (session key material) | `0x10060a5d` |
| `+0x120` | $M_2$ verification context | `0x10060a6c` |

Initializers: client `FUN_10060140` (`0x10060140`, class tag `0xc`, context `0xE8`, inits contexts at `+0x00` and `+0x60`); server `FUN_10060a80` (`0x10060a80`, class tag `0x1c`, context `0x1BC`, inits all four contexts).

Descriptor accessors: client `FUN_10060a10` (`0x10060a10`), server `FUN_100614c0` (`0x100614c0`).

---

## 10. SRP Mathematics

Notation: $\text{PAD}(x)$ = 192-byte left-zero-padded big-endian; $\text{RAW}(x)$ = minimal big-endian; $\oplus$ = byte-wise XOR of 20-byte digests; $H$ = SHA-1; $\parallel$ = concatenation.

### 10.1 Password verifier $x$ (CONFIRMED)

Client `0x10060340`, server `0x10060c80` (structurally identical):

$$
h_{\text{cred}} = H(\text{identity\_bytes} \parallel \text{":"} \parallel \text{password\_bytes})
$$

$$
x = H(\text{salt\_bytes} \parallel h_{\text{cred}})
$$

- Separator: single byte `:` (`0x3a`) at `0x10094218` (data `3a 00 00 00 20 20 20 20`; length passed is 1, so only `:` is hashed).
- Concatenation order: identity $\parallel$ `:` $\parallel$ password (inner); salt **prepended** to inner digest (outer).
- Identity read from `obj+0x8` as `{ptr, len}` raw bytes (UTF-16LE internal); salt from `obj+0x14` as `{ptr, len}`.
- Password passed by caller as `(ptr, len)` from stack (`[ebp+0x10]` ptr, `[ebp+0xc]` len); **no transformation inside `shelper.dll`** — no null terminator, no Unicode normalization, no case conversion, no trimming.
- `x` digest stored at `obj+0x1c`; $v = g^x \bmod N$ computed separately (`0x100602f0` client / inline in `0x10060c80` server).
- The server independently reconstructs $x$ (it receives the plaintext password from the caller — consistent with verifier setup / password-store retrieval).

### 10.2 Multiplier $k$

See §3. Two candidates:
- Legacy: $k = 3$ (`0x100607d0`, literal `3` via BIGNUM).
- SRP-6a: $k = H(N \parallel \text{PAD}_{192}(g))$ (`0x10060810` client / `0x10060ec0` server).
- Which class/descriptor is instantiated at runtime: **UNKNOWN** (dispatch unresolved; see `docs/CRYPTO_PHASE_10_10_RECONCILIATION.md`).

### 10.3 Scrambling parameter $u$

Per `docs/CRYPTO_SRP_ANALYSIS.md` §4.3 and `docs/CRYPTO_SRP_SCRAMBLING_VERIFICATION.md`:

$$
u = H(\text{PAD}(A) \parallel \text{PAD}(B))
$$

More precisely (padding branch active, flags `= 3`):
- Client `0x10060510`: $u = H(\text{context}_{+0x20} \parallel B)$ where context `+0x20` = $A$ (own ephemeral); for typical 192-byte values: $H(A \parallel B)$.
- Server `0x10060fa0`: $u = H(A \parallel \text{context}_{+0x20})$ where context `+0x20` = $B$ (own ephemeral); for typical 192-byte values: $H(A \parallel B)$.
- **Symmetric**: both sides compute $H(A \parallel B)$ given context `+0x20` = own ephemeral. The earlier "asymmetric $u$" claim (client $H(k \parallel B)$ vs server $H(A \parallel k)$) was caused by variable misidentification and is **not supported** by the decompiled evidence.
- $u$ stored at `context+0x28`.

### 10.4 Shared secret $S$

Client `0x10060510`:

$$
\text{base} = (B - k \cdot v) \bmod N \qquad \text{exp} = a + u \cdot x \qquad S = \text{base}^{\text{exp}} \bmod N
$$

Server `0x10060fa0`:

$$
S = (A \cdot v^u)^b \bmod N
$$

Both arrive at the same $S$.

### 10.5 Key derivation function (KDF) (CONFIRMED)

`0x10061790(out, 0x28, S\_bytes, S\_len)`:

$$
K[0..20] = H(S \parallel \text{BE32}(0)) \qquad K[20..40] = H(S \parallel \text{BE32}(1))
$$

- Counter is 4-byte big-endian; output 40 bytes (`0x28`).
- Session key = first 32 bytes of $K_{\text{full}}$ (see §12).

### 10.6 Client proof $M_1$ (CONFIRMED ordering)

$$
H_{\text{xor}} = H(N) \oplus H(g) \qquad H_I = H(\text{identity\_bytes})
$$

$$
M_1 = H(H_{\text{xor}} \parallel H_I \parallel \text{salt} \parallel A \parallel B \parallel K_{\text{full}})
$$

- Client accumulator `ctx+0x00`; sequence: `0x100601b0` appends $H(N)\oplus H(g)$, $H(I)$, salt; `0x10060410` appends $A$; `0x10060510` appends $B$, then $K$ (40 B), then optional auxiliary `obj+0x30`; `0x100609a0` finalizes.
- Server: `0x10060b10` appends $H(N)\oplus H(g)$, $H(I)$, salt; `0x10060fa0` appends $A$ (peer), $B$ (own), $K$.
- $A$ and $B$ are hashed in **RAW** minimal form (`BN_bn2bin` without padding) inside $M_1$, while $u$ uses padded 192-byte forms — a potential leading-zero sensitivity.
- Optional `obj+0x30$ extra block: **UNKNOWN** (writer and whether ever non-empty not determined).

### 10.7 Server proof $M_2$

- Structure (CONFIRMED): $M_2 = H(A \parallel M_1 \parallel K_{\text{full}})$.
- Client `0x100609a0` / `0x10060900`: computes and compares $M_2$.
- Server `0x100612f0`: generates $M_2$ on the canonical path; also accepts a legacy $M_1$ form ($H(B \parallel A \parallel K)$ → legacy $M_2 = H(A \parallel K)$).
- Byte ordering through the BIGNUM step: **PARTIALLY_CONFIRMED**. The 20-byte $M_1$ digest enters `SHA1_Final` → BIGNUM via `0x1005f620` (a **BIGNUM resize**, not an integer conversion: no leading-zero stripping, no endianness change, no sign byte) and is hashed as raw 20 bytes at `0x100609e9`; $K$ (40 bytes from `ctx+0xc0`) hashed at `0x100609fe`. Whether the primary context accumulated $A \parallel M_1$ before finalization is not fully reconstructable statically, so Rust's `SHA-1(A \parallel M_1 \parallel K)` vs the binary's possible `SHA-1(H(A \parallel M_1) \parallel K)` cannot be conclusively distinguished without dynamic capture.

### 10.8 Security observations

- **Non-constant-time $M_1$ comparison (CONFIRMED):** `0x100612f0` compares received proof word-by-word with early exit on first mismatch — timing-sensitive.
- **Double-acceptance path (CONFIRMED):** server accepts two $M_1$ forms, widening the accepted-proof surface (deliberate legacy compatibility).
- SHA-1 contexts are memset (`0x60` bytes) after stage 1 of the $x$ computation (`0x100603e2`, call `0x1006c120`); no explicit zeroization of $x$/$v$ in the `x` function itself.

---

## 11. Identity and Password Encoding

### 11.1 Three separate identity contexts

| Context | Buffer | Transformation | Encoding |
|---|---|---|---|
| SRP hash input ($x$, $H(I)$ in $M_1$) | `obj+0x8` (read directly at `0x10060361`) | None (raw bytes) | **UTF-16LE** (internal) |
| Wire serialization | Copy from `+0x68`/`+0x70` fields, byte-swapped at `0x100667b0` | Byte-swap per u16 | **UTF-16BE** (after swap) |
| Rust `encode_identity()` | `username.encode_utf16()` → `(c>>8, c&0xFF)` | BE output | **UTF-16BE** |

### 11.2 Identity byte-swap evidence

At `0x100667b0` (wire serialization path):

```asm
0x1006679b: mov -0x24(%ebp),%edi       ; buffer ptr
0x100667b0: mov (%edi,%edx,2),%ax        ; load u16 (LE on x86)
0x100667b4: movzbl 0x1(%edi,%edx,2),%ecx ; high byte
0x100667b9: shl $0x8,%ax                 ; shift
0x100667bd: or %ax,%cx                   ; byte swap
0x100667c0: mov %cx,(%edi,%edx,2)        ; store swapped
...
0x100667cc: push $0x20000000             ; TAG_IDENTITY
0x100667d6: call 0x100626e0              ; serialize TLV
```

- The swap converts each u16 from LE to BE (on x86, loading LE then byte-swapping gives BE).
- Happens on a **copy** of the identity (from `0x10062800` fill at `0x10066789`), not on `obj+0x8` itself. The original `obj+0x8` buffer is **not** modified.
- Server swaps back at `0x100677d0` (UTF-16BE → UTF-16LE).

### 11.3 Identity hash encoding

At `0x10060361` (SRP $x$ computation):

```asm
0x10060361: mov 0x8(%esi),%eax          ; identity struct ptr (obj+0x8)
0x10060364: mov 0x4(%eax),%ecx          ; length
0x10060367: mov (%eax),%edx             ; data ptr
0x1006036f: call SHA1_Update            ; hash raw bytes from obj+0x8
```

- The hash reads `obj+0x8` directly, with no swap. The buffer at `obj+0x8` was set during SRP object creation (`CreateClient`/`CreateServer`) and retains its internal form.
- Windows native string format is UTF-16LE; internal form at `obj+0x8` is set by Windows code. Therefore identity hash input = **UTF-16LE** (**STRONGLY_SUPPORTED**, not yet CONFIRMED via dynamic breakpoint).

### 11.4 Test vectors (identity)

Test identity "José" (`J`=0x004A, `o`=0x006F, `s`=0x0073, `é`=0x00E9):

| Encoding | Bytes |
|---|---|
| UTF-8 | `4A 6F 73 C3 A9` |
| UTF-16LE | `4A 00 6F 00 73 00 E9 00` |
| UTF-16BE | `00 4A 00 6F 00 73 00 E9` |

- Binary hash input: `4A 00 6F 00 73 00 E9 00` (UTF-16LE).
- Wire: `00 4A 00 6F 00 73 00 E9` (UTF-16BE).
- Rust `encode_identity()`: UTF-16BE (wire ✔, hash ✘ until Phase 10.14/10.17 remediation).

### 11.5 Password encoding — UNKNOWN

At `0x10060384`–`0x1006038d` (client $x$):

```asm
0x10060384: mov 0x10(%ebp),%edx        ; password ptr (from caller stack)
0x10060387: push %edx
0x1006038b: push %edi                  ; password len (from 0xc(%ebp))
0x1006038d: call SHA1_Update           ; hash password raw bytes
```

- The password is passed as caller-supplied `(ptr, len)` with no transformation inside `shelper.dll`.
- No direct `call 0x10060340` / `0x10060c80` exists anywhere in `shelper.dll` (confirmed by search); the caller is in consumer code outside the DLL (`RvROLClient.dll` or `RvControlSvc.exe`), reached via vtable dispatch / function-pointer table.
- Both consumer binaries import `MultiByteToWideChar` / `WideCharToMultiByte` / `LCMapStringW` / `GetACP`, but no conversion call was traced to the SRP password path.
- `RvControlSvc.exe` was **not available** for local analysis; `RvROLClient.dll` uses indirect dispatch (IAT slot `0x10175158`, 4705 call sites) that defeated static xref tracing.
- Password encoding hypotheses (unverified): UTF-16LE (HIGH — Windows native format, same source as identity), UTF-8 (MEDIUM), ANSI/code page (LOW), UTF-16BE (VERY LOW).
- Test password "päss": UTF-8 `70 C3 A4 73 73`; UTF-16LE `70 00 E4 00 73 00 73 00`; UTF-16BE `00 70 00 E4 00 73 00 73`.
- **Classification: UNKNOWN** (the sole unresolved P0 blocker; requires dynamic breakpoint on `0x10060340` / `0x10060c80` observing `EDX`/`EDI`).
- Rust currently hashes `password.as_bytes()` (UTF-8); changing it without proof would be speculation.

### 11.6 Rust remediation status (identity)

- Phase 10.14: added `encode_identity_le()` (UTF-16LE) for the SRP hash input; `compute_srp_x()` now hashes UTF-16LE while `encode_identity()` (UTF-16BE) is preserved for the wire. Wire regression tests pass.
- Phase 10.17: fixed `compute_srp_m1()` to use `encode_identity_le()` instead of `username.as_bytes()` (UTF-8) for $H(I)$ in $M_1$.
- Password handling unchanged (still UTF-8, pending dynamic evidence).

---

## 12. Session Key Installation

As disassembled in `RvROLClient.dll!0x1003dd40` and `0x100df250`:

1. `SHelper_GetKey` (`0x1006b010`) extracts the derived 40-byte key $K_{\text{full}}$.
2. The secure channel requires a 32-byte (`0x20`) key for AES-256:

   $$
   K_{\text{session}} = K_{\text{full}}[0..32]
   $$

3. Two independent call paths traced (`0x10096f21` via `0x100dce30`; `0x1003de50` via `0x100df250`) both pass the **same buffer pointer with the same length** for encryption and decryption; `0x100df250` normalizes both lengths to `0x20`.
4. The key $K_{\text{session}}$ is installed in the `FamatechCipherState` / `CChannel`:
   - `key_enc = K_session` (`CChannel_SetKeyEnc`, `+0xc0` API-table slot)
   - `key_dec = K_session` (`CChannel_SetKeyDec`, `+0xc4` API-table slot)
   - Bytes `[32..64]` unused.
5. All subsequent messages over the control connection are protected by **AES-256-CBC** with Famatech padding (folded MD5 checksum + pad length byte).
6. AES split mapping: `SAME_32_BYTE_MATERIAL_BOTH_DIRECTIONS` — both AES contexts receive the first 32 bytes of the 64-byte secret (**RESOLVED_STRONGLY_SUPPORTED**). Rust's `from_rsession_key` (`key_material[..32]` for both directions) is **COMPATIBLE**.
7. Remaining uncertainty: only `RvROLClient.dll` paths traced; `RvControlSvc.exe` resolves `GetKey` (`FUN_00442290`) but its consumer was not traced (MEDIUM probability this is the only mapping).

---

## 13. Rust Implementation Comparison Matrix

| # | Item | Binary Evidence | Rust (`src/session/control_handshake.rs`) | Verdict |
|---|---|---|---|---|
| 1 | $N$ modulus | `0x100ac280`, 192 B BE, pinned at `0x100699e0` | `RADMIN_SRP1536_PRIME_HEX` (192 B) | **CONFIRMED_MATCH** |
| 2 | $g$ | `0x100ac279 = 0x05` | `RADMIN_SRP_GENERATOR = 5`, $H(g) = \text{SHA-1}([5])$ | **CONFIRMED_MATCH** |
| 3 | $k$ multiplier | SRP-6a class: $H(N \parallel \text{PAD}(g))$ at `0x10060810`/`0x10060ec0`; legacy `k = 3` at `0x100607d0`; dispatch unresolved | `RADMIN_SRP_K = 3` (Phase 10.5 remediation changed to dynamic `srp_k()` per reconciliation) | **UNVERIFIED** — high risk; if SRP-6a class used, `CONFIRMED_MISMATCH` |
| 4 | SHA-1 | Standard SHA-1, 20-byte BE digest; `0x10028810`/`0x100285f0`/`0x100286d0` | `sha1()` | **CONFIRMED_MATCH** |
| 5 | TLV framing | BE u32 `(tag & 0xF8000000)\|(len & 0x07FFFFFF)`, tags `0x10`–`0x70`, cap `0x2800` | `encode_item`/`decode_items` identical mask and BE header | **CONFIRMED_MATCH** |
| 6 | Version | `0x1006b1d0 → 3`; `0x1006ab80` `== 3`; wire endianness unverified | `SHELPER_PROTOCOL_VERSION = 3`, written `to_le_bytes()` | **PARTIAL_MATCH** (value matches; wire endianness unverified) |
| 7 | Step endianness | **Big-endian** `00 00 00 01` (CONFIRMED, refutes old LE claim) | `1u32.to_le_bytes()` | **CONFIRMED_MISMATCH** — fatal; server rejects step 1 |
| 8 | $x$ computation | $H(\text{salt} \parallel H(I \parallel ":" \parallel P))$; salt-first order matches; identity hashed UTF-16LE from `obj+0x8` | `username.as_bytes()` + `password.as_bytes()` = UTF-8 | **CONFIRMED_MISMATCH** (identity); password **UNKNOWN** |
| 9 | KDF | $H(S \parallel \text{BE32}(i))$, 40 B | `0u32.to_be_bytes()` / `1u32.to_be_bytes()`, 40 B | **CONFIRMED_MATCH** |
| 10 | $M_1$ formula | $H(H(N)\oplus H(g) \parallel H(I) \parallel \text{salt} \parallel A \parallel B \parallel K)$; $A$/$B$ hashed RAW minimal | Ordering identical; $H(I)$ was UTF-8 (fixed to UTF-16LE in 10.17); $A$/$B$ padding at call sites unverified | **PARTIAL_MATCH** |
| 11 | $M_2$ formula | Canonical $H(A \parallel M_1 \parallel K)$; server also accepts legacy $H(A \parallel K)$; BIGNUM step PARTIALLY_CONFIRMED | `sha1(a_bytes \parallel m1 \parallel k_full)` | **PARTIAL_MATCH** |
| 12 | Session key | First 32 B of 40-B K; install requires ≥32; both directions same 32 bytes | `k_full[..32]` both directions | **CONFIRMED_MATCH** |
| 13 | Identity wire | UTF-16BE per code unit (byte-swap `0x100667b0`) | `encode_identity()` = UTF-16BE | **CONFIRMED_MATCH** |
| 14 | Identity hash ($x$, $M_1$) | UTF-16LE raw `obj+0x8` | Was UTF-8; corrected to UTF-16LE via `encode_identity_le()` (10.14 / 10.17) | Was **CONFIRMED_MISMATCH**; now corrected |
| 15 | Validation | Group pinned `0x100699e0`; ephemeral `len ≤ 192`, `val < N`, `val != 0`; base > 1, base+1 != N | Strict `len == 192`; `!= 0`; `< N`; no group pinning | **PARTIAL_MATCH** (strict-192 can reject valid shorter peer values) |
| 16 | Key install | `0x1003dd40` → `0x100df250`; 32-byte enc/dec keys | 32-byte key to transport | **CONFIRMED_MATCH** |
| 17 | $u$ | $H(A \parallel B)$ symmetric (client `0x10060510`, server `0x10060fa0`); width from runtime object field | `SHA-1(PAD192(A) \parallel PAD192(B))` | **PARTIAL_MATCH** (width/order unresolved officially) |
| 18 | Exponent generation | `RAND_bytes(192)` + `BN_add_word(1536)`; no rejection sampling | CSPRNG, rejection sampling $1 < x < N-1$ | Behavioral divergence only (not interop-fatal) |
| 19 | $M_1$ compare | Non-constant-time, word-wise early exit | Not modeled | Documentation gap |
| 20 | Double $M_1$ accept | Server accepts canonical + legacy $M_1$ forms | Rust models canonical only | Documentation gap |

### Fatal defects (pre-remediation)

1. **Step endianness (CONFIRMED_MISMATCH):** Rust emits little-endian steps; binary emits big-endian. Immediate handshake failure.
2. **Identity/password encoding (CONFIRMED_MISMATCH for identity):** Rust hashes UTF-8; binary hashes UTF-16LE. $x$, $v$, $A$, $S$, $K$, $M_1$, $M_2$ all differ.
3. **$k$ value (UNVERIFIED):** If the deployed class is SRP-6a ($k = H(N \parallel \text{PAD}(g))$), Rust's $k = 3$ is a `CONFIRMED_MISMATCH`; if legacy, $k = 3$ matches. Class instantiation must be determined from `RvROLClient.dll`.

### Latent risk

- **Exact-192 length check (PARTIAL_MATCH):** Rust requires `len == 192` strictly; binary accepts `len ≤ 192` (padded). A valid official peer whose minimal form is shorter than 192 bytes (probability ≈ 1/256 per public value with a leading zero byte) would be rejected by Rust.

---

## 14. Dynamic-Analysis Blockers

Static analysis has been exhausted for the P0/P1 blockers; dynamic analysis is required:

| # | Blocker | Status | Static evidence | Required dynamic evidence |
|---|---|---|---|---|
| 1 | Password encoding | **UNKNOWN** (P0) | `shelper.dll` hashes caller bytes raw at `0x10060340`/`0x10060c80`; caller outside DLL not traced | Breakpoint on `0x10060340`/`0x10060c80`; capture `EDX` (ptr) / `EDI` (len); test ASCII, non-ASCII, non-BMP passwords |
| 2 | $M_2$ exact byte ordering / BIGNUM step | **PARTIALLY_CONFIRMED** | `0x100609a0` sequence reconstructed; primary-context contents before `SHA1_Final` not fully traced | Capture accumulator contents at `0x100609e9` / `0x100609fe` |
| 3 | $k$ class dispatch (which descriptor instantiated) | **UNKNOWN** | Method table bytes + descriptor pointers confirmed; consumer chain not recovered | Trace caller that loads the client/server table and selects the slot |
| 4 | RSA key source / call sites | **UNKNOWN** | Constructors `0x1006b3e0`/`0x1006b4e0` caller-provided; IAT slot `0x10175158` (4705 calls) shared | Capture `n`/`e` pointers/contents at `0x1006b4e0`; isolate RSA constructor call site in `RvROLClient.dll` |
| 5 | Identity UTF-16LE confirmation | **STRONGLY_SUPPORTED** (not CONFIRMED) | Swap direction + `obj+0x8` direct read | One breakpoint on `0x10060340`/`0x10060361` upgrades to CONFIRMED |
| 6 | AES same-pointer in `RvControlSvc.exe` | Untraced consumer | `RvROLClient.dll` paths both pass same pointer | Breakpoint on `0x1006a630` (SetKeyPair) in control-svc process |
| 7 | `obj+0x30$ auxiliary block in $M_1$ | **UNKNOWN** | Appended when `len > 0`; writer unknown | Observe whether block is ever non-empty in a live handshake |
| 8 | Server canonical-$M_2$ output slot | **UNRESOLVED** | `ctx+0x6a` (decompiler) vs `ctx+0x1A8` (read by `0x10061450`) | Re-disassemble / capture `0x10061000–0x100612F0` |

Environment note: the Windows VM (`win10`, KVM/virt-manager) and debuggers (x64dbg / WinDbg) are not available in this environment; `pcaps/radmin_vm2.pcap` (196 KB) is root-owned and not readable. PCAPs cannot reveal password encoding directly (SRP transmits derived values, not the password).

---

## 15. Sources

All 14 sources mapped to `CONTROL_HANDSHAKE_SPEC` in `analysis_workspace/compaction/mapping.tsv` were read and are consumed by this document:

1. `docs/CONTROL_HANDSHAKE_SPEC.md` — pre-existing baseline spec (overview, N/g/k, framing, state machines, key installation; contains the superseded little-endian step and `k=3 CONFIRMED` claims corrected in §4–§5).
2. `docs/CRYPTO_PHASE_10_13_P0_BLOCKER_RESOLUTION.md` — AES split mapping (`SAME_32_BYTE_MATERIAL_BOTH_DIRECTIONS`), password encoding `REQUIRES_DYNAMIC_ANALYSIS`, identity hash = UTF-16LE / wire = UTF-16BE, byte-level call paths `0x10096f21` / `0x1003de50` → `0x100df250`.
3. `docs/CRYPTO_PHASE_10_14_IDENTITY_REMEDIATION_AND_PASSWORD_INVESTIGATION.md` — `encode_identity_le()` added; `compute_srp_x()` uses UTF-16LE hash input; wire unchanged UTF-16BE; password runtime investigation not executed; byte vectors for "A"/"José"/emoji.
4. `docs/CRYPTO_PHASE_10_15_STATIC_PASSWORD_ENCODING_RECONSTRUCTION.md` — static caller-side reconstruction; password remains `UNKNOWN`; `MultiByteToWideChar`/`WideCharToMultiByte` imports present but untraced to SRP path; instruction-level trace of `0x10060340`.
5. `docs/CRYPTO_PHASE_10_16_RSA_AND_SRP_PROOF_RECONSTRUCTION.md` — RSA exports `0x1006b3e0`/`0x1006b4e0` (caller-provided components, no embedded blobs); M1/M2 formulas; SHA-1 accumulator layout (`+0x60` M1, `+0xc0` K, `+0x120` M2); M1 identity encoding `CONFIRMED_MISMATCH` (Rust UTF-8 vs binary UTF-16LE).
6. `docs/CRYPTO_PHASE_10_17_M1_REMEDIATION_AND_RSA_CALLER_TRACE.md` — `compute_srp_m1()` fixed to `encode_identity_le()`; RSA caller graph partially reconstructed; `GetProcAddress`/IAT dispatch; password still `UNKNOWN`.
7. `docs/CRYPTO_PHASE_10_18_M2_BYTE_LEVEL_AND_RSA_DATA_FLOW.md` — M2 byte-level closure `PARTIALLY_CONFIRMED`; M2 function `0x100609a0` exact sequence; RSA data-flow `PARTIALLY_RESOLVED`; IAT `0x10175158`.
8. `docs/CRYPTO_PHASE_10_19_M2_BIGNUM_AND_RSA_IAT_AUDIT.md` — `0x1005f620` BIGNUM resize (not conversion; no leading-zero stripping); M2 BIGNUM closure `CONFIRMED` for raw 20-byte digest, `PARTIALLY_CONFIRMED` for overall byte equivalence; static-analysis decision gate (dynamic required).
9. `docs/CRYPTO_SRP_ANALYSIS.md` — group parameters; k-class conflict (`0x10060810` SRP-6a vs `0x100607d0` legacy); step endianness big-endian CONFIRMED (LE refuted); full state machines; math ($x$, $k$, $u$, $S$, KDF, $M_1$, $M_2$); Rust comparison matrix with 20 rows; three documentation corrections required.
10. `docs/CRYPTO_SRP_DISPATCH_AND_DATA_FLOW_AUDIT.md` — dispatch contradiction only partially resolved; method-table reconstruction (`.data` at `0xad740`, slots `0x100602f0`…`0x100609a0`, name ptrs `0x100a3df0`/`0x100a3e18`); `FUN_100607d0` literal-3 confirmed, runtime selection UNKNOWN; `FUN_10060810` two-BIGNUM digest confirmed, assignment to $k$ UNKNOWN; $k$ classified UNKNOWN, not `CONFIRMED_MISMATCH`.
11. `docs/CRYPTO_SRP_EFFECTIVE_IMPLEMENTATION.md` — SRP-6a confirmed as effective implementation; client descriptor `0x100ad75c` → `FUN_10060810`; server descriptor `0x100ad7b4` → `FUN_10060fa0`; legacy `k=3` dead code; server $k$ externally provided at `obj+0x20`; asymmetric $u$ claim retracted (symmetric $H(A \parallel B)$); Rust incompatibilities ($k$, integer serialization, identity encoding).
12. `docs/CRYPTO_SRP_INTEGER_SERIALIZATION_AUDIT.md` — integer serialization matrix; Rust SRP integers big-endian (retracts little-endian SRP-integer claim); official slot `0x100607d0` uses literal 3 (CONFIRMED), SHA-1 digest form arithmetically verified but use UNKNOWN; `k = 3` consistent with examined slot; no implementation authorized.
13. `docs/CRYPTO_SRP_PASSWORD_ENCODING.md` — exact $x$ derivation $H(\text{salt} \parallel H(I \parallel \text{":"} \parallel P))$; separator `:` at `0x10094218`; identity UTF-16LE hash / UTF-16BE wire; password encoding UNKNOWN; server independently reconstructs $x$; 20-row evidence/confidence matrix.
14. `docs/CRYPTO_SRP_SCRAMBLING_VERIFICATION.md` — SRP-6a with $k = \text{SHA-1}(N \parallel \text{PAD}_{192}(g))$ dynamic; legacy $k=3$ dead code; $u$ symmetric ($H(A \parallel B)$ both sides); client `FUN_10060140`/`FUN_10060810`/`FUN_10060510`; server `FUN_10060a80`/`FUN_10060ec0`/`FUN_10060fa0`; exact pseudo-code; Rust compatibility matrix.

Cross-reference (not a `CONTROL_HANDSHAKE_SPEC` source, cited for the reconciliation pointer):
- `docs/CRYPTO_PHASE_10_10_RECONCILIATION.md` — cross-phase reconciliation of `k`, step endianness, identity encoding, AES split.

---

## 16. Provenance Note

This document was produced by consolidating exactly the 14 `CONTROL_HANDSHAKE_SPEC`-mapped sources listed in §15, plus the pre-existing `docs/CONTROL_HANDSHAKE_SPEC.md` (source 1). No new technical facts were invented; every address, constant, formula, and classification is transcribed from the sources. Where sources conflict (notably step endianness and the $k$ multiplier class), both claims are preserved with their addresses and the open question is flagged rather than resolved, with a pointer to `docs/CRYPTO_PHASE_10_10_RECONCILIATION.md`.

The password encoding remains `UNKNOWN` in this document, consistent with all 14 sources: `shelper.dll` transforms no password bytes internally, and the caller outside the DLL was never traced. No Rust source code, binary, PCAP, or Ghidra artifact was read-modify-write in producing this document; this is a documentation-only consolidation. All evidence is from static disassembly of local binaries (`shelper.dll` sha256 `d89daf6b…`, `RvROLClient.dll` sha256 `6ba7dfec…`, `RvControlSvc.exe` sha256 `546efad9…`); no dynamic execution, Windows VM, Wine, or third-party VPN was used.

End of document.
---

## Evidence appendix (exact tokens from consolidated sources)

Exact addresses, hashes and identifiers from the consolidated sources that are not repeated in the prose above. They are preserved here so that no evidence anchor is lost during compaction; the full narrative for each source remains available in git history.

- `docs/CONTROL_HANDSHAKE_SPEC.md`: `0x00000000`
- `docs/CRYPTO_PHASE_10_13_P0_BLOCKER_RESOLUTION.md`: `0x1003de1a`, `0x1003de21`, `0x1003de24`, `0x1003de29`, `0x1003de2e`, `0x1003de30`, `0x1003de3b`, `0x1003de3c`, `0x1003de3d`, `0x1003de3e`, `0x1003de49`, `0x1003de4f`, `0x10060369`, `0x1006036a`, `0x10096e07`, `0x10096e0a`, `0x10096e0f`, `0x10096e14`, `0x10096e19`, `0x10096e1a`, `0x10096f03`, `0x10096f08`, `0x10096f0d`, `0x10096f0e`, `0x10096f11`, `0x10096f14`, `0x10096f19`, `0x10096f1a`, `0x10096f1f`, `0x100a9960`, `0x100a9cd0`, `0x100dce84`, `0x100dce8a`, `0x100dce8d`, `0x100df27e`, `0x100df28b`, `0x100df2c5`, `0x100df2c7`, `0x100df2c8`, `0x100df2ca`, `0x100df2d5`, `95e304e0855a6faf4eece932484cb00e36620a6e`
- `docs/CRYPTO_PHASE_10_14_IDENTITY_REMEDIATION_AND_PASSWORD_INVESTIGATION.md`: `0x10060355`, `95e304e0855a6faf4eece932484cb00e36620a6e`
- `docs/CRYPTO_PHASE_10_15_STATIC_PASSWORD_ENCODING_RECONSTRUCTION.md`: `0x10060341`, `0x10060343`, `0x10060351`, `0x10060355`, `0x10060358`, `0x1006035c`, `0x10060374`, `0x10060379`, `0x1006037f`, `0x1006ac80`, `0x1006bbe0`, `0x100a5b63`, `0x100a5b9f`, `0x100a5daa`, `0x100a5dd8`, `0x100a625c`, `0x100a62df`, `0x100dc223`, `0x100dc270`, `0x100e25da`, `0x100e2617`, `0x100ff5ed`, `0x100ff6a5`, `0x10111104`, `0x10111108`, `0x101171d8`, `0x1011722c`, `5fc07f57d1d1a46bf080dd833511d5166235ffc2c00812faf46d99f008384d21`, `95e304e0855a6faf4eece932484cb00e36620a6e`
- `docs/CRYPTO_PHASE_10_16_RSA_AND_SRP_PROOF_RECONSTRUCTION.md`: `0x100609d4`, `0x10060a20`, `0x10060b3f`, `0x10060b50`, `0x10060b60`, `0x10060b6c`, `0x10060b7d`, `0x10060b8d`, `0x10060ba0`, `0x10060bd3`, `0x10060be2`, `0x10060c26`, `0x10060c3d`, `0x10065d00`, `0x10065f50`, `0x10066170`, `0x1006b3e3`, `0x1006b441`, `0x1006b6d0`, `95e304e0855a6faf4eece932484cb00e36620a6e`
- `docs/CRYPTO_PHASE_10_17_M1_REMEDIATION_AND_RSA_CALLER_TRACE.md`: `0x10060bf3`, `0x10060bf6`, `0x10060bf9`, `0x10060bfb`, `0x10060bfc`, `0x10060bfd`, `0x10060c00`, `0x10060c02`, `0x10060c26`, `0x10065d00`, `0x10065f50`, `0x10066170`, `95e304e0855a6faf4eece932484cb00e36620a6e`
- `docs/CRYPTO_PHASE_10_18_M2_BYTE_LEVEL_AND_RSA_DATA_FLOW.md`: `0x1005f4b0`, `0x10060742`, `0x1006075c`, `0x100609d4`, `0x100609f1`, `0x100609f7`, `0x100609f9`, `0x100609fd`, `95e304e0855a6faf4eece932484cb00e36620a6e`
- `docs/CRYPTO_PHASE_10_19_M2_BIGNUM_AND_RSA_IAT_AUDIT.md`: `0x1005f550`, `0x1006075c`, `0x100609c0`, `0x100609c2`, `0x100609c3`, `0x100609cb`, `0x100609ce`, `0x100609d0`, `0x100609d2`, `0x100609d3`, `0x100609d4`, `0x100609db`, `0x100609de`, `0x100609e0`, `0x100609e5`, `0x100609e8`, `0x100609f1`, `0x100609f7`, `0x100609f9`, `0x100609fa`, `0x100609fd`, `95e304e0855a6faf4eece932484cb00e36620a6e`
- `docs/CRYPTO_SRP_ANALYSIS.md`: `0x100161a0`, `0x10016770`, `0x10025d30`, `0x100263b0`, `0x1005f810`, `0x1005f860`, `0x1005f880`, `0x1005f8c0`, `0x1005f900`, `0x1005f940`, `0x1005ff40`
- `docs/CRYPTO_SRP_DISPATCH_AND_DATA_FLOW_AUDIT.md`: `0x1005f4b0`, `95e304e0855a6faf4eece932484cb00e36620a6e`, `e16711e2e3e59f6603f51f437197215b1914a3d8316e1f633260178b959921f7`
- `docs/CRYPTO_SRP_EFFECTIVE_IMPLEMENTATION.md`: `fun_10008a40`, `fun_100285f0`, `fun_100286d0`, `fun_10028810`, `fun_10061790`, `fun_10065f70`, `fun_10066170`
- `docs/CRYPTO_SRP_INTEGER_SERIALIZATION_AUDIT.md`: `048c79478a559e6dbf030489b906424b30fc17b1`, `0c95b5b39ccb66e4461a116269ed055d882b70df`, `0x1005f4b0`, `0x1006037f`, `0x5a827999`, `c07e990a8dbb4caa3d67d6558522e2b65d210727`
- `docs/CRYPTO_SRP_PASSWORD_ENCODING.md`: `0x1005f940`, `0x10060355`, `0x100603a8`, `0x100603ae`, `0x100603c8`, `0x100603d2`, `0x100603f3`, `0x10060d32`, `0x10066741`, `0x1011121c`, `0x10115d6c`, `0x10187030`, `fun_1003fbd0`
- `docs/CRYPTO_SRP_SCRAMBLING_VERIFICATION.md`: `0x00000000`, `fun_100285f0`, `fun_100286d0`, `fun_10028810`, `fun_1005f4b0`, `fun_1005f710`, `fun_1005f760`, `fun_1005f7e0`, `fun_1005fad0`, `fun_10060410`, `fun_10060d80`
