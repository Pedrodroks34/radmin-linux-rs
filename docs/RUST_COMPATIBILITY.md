# RUST_COMPATIBILITY — Consolidated Rust Compatibility Analysis

**Scope:** Cross-validation of the `radmin-vpn` Rust crate against the reverse-engineered official Windows client `Radmin_VPN_2.1.4951.1.exe`.

**Consolidated from:** the 12 sources mapped to `RUST_COMPATIBILITY` in `analysis_workspace/compaction/mapping.tsv`. Every source below is consumed exactly once; gap/remediation/validation reports are deduplicated while every technical fact is preserved.

**Language:** English. Nothing is invented. All Rust file paths, line numbers, verdicts (`CONFIRMED_MISMATCH` / `PARTIAL_MATCH` / `NOT_IMPLEMENTED` / `READY`), binary addresses used as evidence, breakpoint addresses (`shelper.10060340`, `100609a0`, `1006b4e0`, `1006b3e0`), and test-credential byte sequences are preserved verbatim from the sources. Where sources contradict, both verdicts are listed with source attribution.

This document is a consolidation only. No Rust source files, binaries, PCAPs, or other repository artifacts were read for modification or were modified. All technical claims trace to the 12 sources listed in `## Sources`. Where two sources assign different confidence to the same finding (e.g., SRP multiplier `k`, identity hash encoding, SRP integer endianness), both ratings are retained with the originating document named, so no information is lost by deduplication. No packet fields, ports, algorithms, key sizes, server addresses, or IP ranges were invented; anything not confirmed by static or dynamic analysis is marked unknown.

---

## 1. Readiness Matrix

Combined from `docs/PCAP_IMPLEMENTATION_READINESS.md` (PCAP-based, 12 items) and `docs/reverse-engineering/round-02/IMPLEMENTATION_READINESS.md` (Round 02, subsystem-based). These matrices use different axes (PCAP evidence vs. implementation feasibility) and are both retained.

### 1.1 PCAP-based readiness (docs/PCAP_IMPLEMENTATION_READINESS.md)

Commit-base: `9eecbfe`. Basis: 6 PCAP/PCAPNG captures in `claude-handoff/pcaps/`.

| # | Item | Readiness | Evidence needed to advance |
|---|------|-----------|----------------------------|
| 1 | Control framing | READY | — |
| 2 | Initial handshake | NOT READY | Capture handshake before any TCP connection |
| 3 | Authentication | NOT READY | Key material + authentication traffic |
| 4 | Cryptography | NOT READY | AES keys + algorithm + operation mode |
| 5 | STUN | PARTIALLY CHARACTERIZED | Ports and message format confirmed, but non-standard variant |
| 6 | NAT traversal | HYPOTHESIS | NAT type + successful hole punching |
| 7 | Peer discovery | PARTIALLY CHARACTERIZED | Discovery mechanism + complete TLV |
| 8 | UDP/9993 | PARTIALLY CHARACTERIZED | Complete structure + encrypted region |
| 9 | UDP/47836 | INCONCLUSIVE | Format confirmed but layout ambiguous |
| 10 | Relay | NOT READY | Relay server confirmation |
| 11 | Virtual interface | PARTIALLY CHARACTERIZED | ARP + IP 26.x.x.x confirmed, but encapsulation unknown |
| 12 | Packet encapsulation | NOT READY | Internal VPN packet format |

**PCAP evidence highlights (verbatim from source):**
- TCP/17301: `[4-byte big-endian length][payload]` validated in 8 frames (frames 77, 80, 81, 82, 87, 88, 93, 94 of `radmin-connect.pcapng`). TCP/17351: same framing in frames 5487, 5493, 5494, 5501 of `radmin_vm.pcap`. Length field excludes the 4-byte header itself.
- Handshake `00 00 00 04 03 00 00 00` does NOT appear at the start of any captured TCP connection; TCP/17301 captures begin with PSH+ACK data, not the 8-byte handshake.
- All TCP/17301 and TCP/17351 traffic is encrypted; no identifiable credentials, tokens, or authentication material in plaintext; no evidence of SRP in captured traffic.
- 48-byte encrypted region (0x2e–0x5d) in UDP/9993 Family A messages; all TCP payload appears encrypted (high entropy); no nonce, IV, or key visible in any packet.
- STUN: Binding Request (20 bytes) and Binding Response (56 bytes) on 9 ports (17309, 17310, 17341, 17342, 17347, 17348, 17349, 17357, 17358). Non-standard variant: no magic cookie `0x2112A442`, 16-byte transaction ID (not 12 as in RFC 5389). Automatic retry after ~100ms.
- Hole punching attempt: same UDP/9993 message sent from ports 9993, 48318, 48870. No confirmation of successful hole punching.
- TLV 0x0004 contains peer IP + port (big-endian). 10-byte session identifier: `e5 d4 c1 c5 bc 21 59 16 c8 0f`.
- UDP/9993: 5 message families by size (28, 33, 99, 137, 247–641 bytes); Family A (137 bytes) partially mapped; 17 undocumented bytes at offset 0x78–0x8a of Family A.
- UDP/47836: 4-byte payload `XX YY 00 00` (sequential counter, increments +1 per message, ~1 second interval, one direction only: 26.228.88.155 → 26.239.229.134). Layout ambiguous: `uint16 LE counter + 2 zero bytes` vs `uint32 LE counter` — indistinguishable because upper 16 bits are always zero.
- Virtual interface `radminvpn0` with IP `26.239.229.134/8`; ARP for virtual address resolution; locally administered MACs (prefix `02:`).
- High-volume flow (3.1 MB) between 192.168.15.15:43139 and [IP_PUBLICO_MASCARADO]:58358 (UDP) — no evidence this is a Radmin relay server.

**Implementation priority recommendations (PCAP):**
1. Capture initial handshake (blocker — without handshake, no control connection).
2. Obtain encryption keys (blocker — without keys, no secure communication).
3. Understand encapsulation (blocker — without encapsulation, virtual interface cannot work).
4. Fully specify UDP/9993 (including undocumented 17 bytes and encrypted region).
5. Identify peer discovery mechanism.
6. Determine NAT type.
7. Implement UDP/47836 keepalive (simple, format confirmed).
8. Implement STUN client (format confirmed, ports known).
9. Implement virtual interface TUN/TAP (IP format known).

**Recommended next experiments (PCAP):** start network capture before launching Radmin client; UI-synchronized capture; STUN decoding; simultaneous virtual/physical interface packet correlation; real interoperability test with official Windows client (observation only).

### 1.2 Round 02 implementation readiness (docs/reverse-engineering/round-02/IMPLEMENTATION_READINESS.md)

| Module / Subsystem | Readiness Status | External Dependency / Blockers | Target Rust Files |
|---|---|---|---|
| TCP Framing & Magic (0x03000000) | READY | None | `src/transport/framing.rs` |
| RSA-2048 / AES-256 Handshake (`HandshakeNegotiator`) | READY | Server public key | `src/session/handshake.rs` |
| Symmetric Cipher & Proprietary Trailer (`CryptoChannel`) | READY | `aes`, `cbc` crates | `src/crypto/famatech.rs` |
| Famatech TLV Serialization and Parser | READY | None | `src/protocol/tlv.rs` |
| Network Authentication and SHA-1 Hashing | READY | `sha1` crate | `src/session/auth.rs` |
| Linux TAP Layer (`/dev/net/tun`) & Packet Pump | READY | `CAP_NET_ADMIN` privilege | `src/adapter/tap.rs` |
| STUN RFC 3489 Client (NAT Discovery) | READY | Asynchronous UDP sockets | `src/p2p/stun.rs` |
| TcpRelay Forwarding Client (Port 17351) | READY | None | `src/transport/relay.rs` |
| IPC Layer (UNIX Domain Socket) | READY | None | `src/ipc/server.rs` |
| Teredo Tunneling (RFC 4380) | OPTIONAL (NEEDS RESEARCH) | Local IPv6 support | `src/p2p/teredo.rs` |

**Implementation specifications ready for Rust (verbatim):**

Trailer encoding rules (`src/crypto/famatech.rs`):
```rust
// Mandatory trailer encoding rules:
// 1. total_len = ((payload_len + 24) / 16) * 16;
// 2. pad_len = total_len - payload_len; // 9 <= pad_len <= 24
// 3. buffer[payload_len .. total_len - 9].fill(0xCC);
// 4. checksum = sum_64bit_additive_little_endian(&buffer[0 .. total_len - 9]);
// 5. buffer[total_len - 9 .. total_len - 1].copy_from_slice(&checksum.to_le_bytes());
// 6. buffer[total_len - 1] = pad_len as u8;
// 7. aes_256_cbc_encrypt(key, &mut iv, buffer); // IV is persistent and updated in place
```

Handshake state machine (`src/session/handshake.rs`):
```rust
pub enum HandshakeState {
    /// 1. Sends magic framing [00 00 00 04] + [03 00 00 00], waits for an identical reply
    WaitingMagicEcho,
    /// 2. Generates 64 random bytes, builds the 76-byte block, encrypts it with RSA-2048 PKCS#1 v1.5,
    ///    sends 256 bytes and waits for the 4 bytes from the server
    WaitingServerHello {
        client_key_material: [u8; 64],
    },
    /// 3. Receives the 4-byte token, derives the AES-256 key from the first 32 bytes of
    ///    `client_key_material`, initializes the IV with zeros and activates the symmetric channel
    SessionActive {
        session_token: u32,
        crypto: CryptoChannel,
    },
    Failed(HandshakeError),
}
```

Local network device interface (`src/adapter/tap.rs`): open `/dev/net/tun` with `O_RDWR | O_NONBLOCK`; `ioctl(fd, TUNSETIFF, &ifr)` with `IFF_TAP | IFF_NO_PI`; set MTU 1500 with `SIOCSIFMTU`; set virtual MAC with `SIOCSIFHWADDR`; attach to `tokio::io::unix::AsyncFd` for non-blocking async read/write of 1514-byte Ethernet frames.

**Automated test plan with extracted vectors:** (1) 64-bit checksum test — vector extracted directly from `shelper.dll` validating little-endian sum of 8-byte words and excess-byte handling; (2) padding/unpadding test — payloads 1–1500 bytes always result in strict multiples of 16 bytes, `pad_len` between 9 and 24 with `0xCC` padding; (3) IV chaining test — two consecutive CBC-encrypted blocks use last 16 bytes of previous block as subsequent IV; (4) TLV deserialization test — Login, JoinNetwork, error-response blocks using tags catalogued in `03-tlv-catalog.md`; (5) STUN Binding test — simulation of STUN response with attributes `0x0001`, `0x0004`, `0x0005`, as captured in packet #839 of `radmin_vm2.pcap`.

---

## 2. Gap Analysis

Primary source: `docs/CRYPTO_RUST_GAP_ANALYSIS.md` (38-row discrepancy matrix), cross-validated by `docs/CRYPTO_PHASE_10_5_COMPATIBILITY_AUDIT.md` (17-field table + contradiction resolution). Deduplicated: the audit's table overlaps the gap matrix; both verdicts are kept where they diverge, with attribution.

### 2.1 Discrepancy status values (verbatim)

- `CONFIRMED_MATCH` — Rust matches binary behavior, verified by direct evidence.
- `CONFIRMED_MISMATCH` — Rust differs from binary, verified by direct evidence.
- `PARTIAL_MATCH` — Rust matches partially but has a documented deviation.
- `UNVERIFIED` — Binary behavior not fully confirmed; Rust behavior may or may not match.
- `NOT_IMPLEMENTED` — Component exists in binary but not in Rust.
- `NOT_APPLICABLE` — Component not present in one or both implementations.

No component is marked `CONFIRMED_MATCH` without direct evidence. Tests that validate only internal consistency (round-trip within Rust) are explicitly noted as not providing interoperability evidence.

### 2.2 Discrepancy matrix (all 38 audit areas)

| # | Component | Original Behavior | Rust Behavior | Evidence | Status | Blocks Interop? |
|---|-----------|-------------------|---------------|----------|--------|-----------------|
| 1 | Control framing | `[4-byte BE length][payload]`, length excludes header | `FramedPacket::to_bytes()` / `FrameParser` with BE u32 length | Binary frames 77, 80, 81, 82, 87, 88, 93, 94 in `radmin-connect.pcapng`; Rust `src/protocol/framing.rs` | CONFIRMED_MATCH | — |
| 2 | TLV tag format | `(tag & 0xF8000000) \| (len & 0x07FFFFFF)`, BE header | `encode_item(tag, payload)`: `(tag & 0xF800_0000) \| (payload.len() as u32 & 0x07FF_FFFF)`, `to_be_bytes()` | Binary builder `0x100626e0`, parser `0x10062900`; Rust `src/protocol/tlv.rs` | CONFIRMED_MATCH | — |
| 3 | TLV tags | `0x10` step, `0x20` identity, `0x30` salt, `0x40` N, `0x50` g, `0x60` ephemeral, `0x70` proof | `TAG_STEP=0x10000000`, `TAG_IDENTITY=0x20000000`, `TAG_SALT=0x30000000`, `TAG_MODULUS=0x40000000`, `TAG_GENERATOR=0x50000000`, `TAG_PUBLIC_EPHEMERAL=0x60000000`, `TAG_PROOF=0x70000000` | Binary `0x10066680`/`0x100670d0`; Rust `src/session/control_handshake.rs` L24-36 | CONFIRMED_MATCH | — |
| 4 | Step value on wire | 4-byte **big-endian** (`00 00 00 01` for step 1) | `1u32.to_le_bytes()` → `01 00 00 00` | Binary builder `0x100626e0` emits BE; Rust `control_handshake.rs` L670, 780, 910, 1267, 1399, 1456 | **CONFIRMED_MISMATCH** | YES — complete handshake failure |
| 5 | Version value | `3` | `SHELPER_PROTOCOL_VERSION = 3` | Binary `0x1006b1d0` returns `0x3`; Rust `control_handshake.rs` L10 | CONFIRMED_MATCH | — |
| 6 | Version on-wire endianness | Unknown (binary only proves value = 3) | `to_le_bytes()` → `03 00 00 00` | Rust `control_handshake.rs` L588; binary `0x1006b1d0` only confirms value | PARTIAL_MATCH | MAY fail version exchange |
| 7 | SRP group N | `0x100ac280`, 192 bytes BE | `RADMIN_SRP1536_PRIME_HEX` (192 chars hex) | Binary pinned at `0x100ac280`; Rust `control_handshake.rs` L38-44 | CONFIRMED_MATCH | — |
| 8 | SRP group g | `0x100ac279 = 0x05` | `RADMIN_SRP_GENERATOR = 5` | Binary `0x100ac279`; Rust `control_handshake.rs` L14 | CONFIRMED_MATCH | — |
| 9 | SRP multiplier k | SRP-6a class: `k = SHA1(N_bytes ‖ PAD(g,192))`; legacy class: `k = 3` | `RADMIN_SRP_K = 3` | Binary `0x10060810` (SRP-6a), `0x100607d0` (legacy); Rust `control_handshake.rs` L16 | **UNVERIFIED** — which class instantiated unknown | — |
| 10 | Hash function | SHA-1, 20-byte BE output | `openssl::sha::sha1()` | Binary `0x10028810`/`0x285f0`/`0x286d0`; Rust `control_handshake.rs` uses `openssl::sha::sha1` | CONFIRMED_MATCH | — |
| 11 | x computation | `H(salt ‖ H(I ‖ ":" ‖ P))`, identity from UTF-16LE wide chars | `H(username.as_bytes() ‖ ":" ‖ password.as_bytes())` = UTF-8 bytes | Binary `0x10060340`/`0x10060c80`; Rust `compute_srp_x` L269-286 | **CONFIRMED_MISMATCH** (byte encoding differs) | YES |
| 12 | v computation | `v = g^x mod N` | `v.mod_exp(&g_bn, &x_secret, &prime_n, &mut ctx)` | Binary `0x100602f0`/`0x10060c80`; Rust `control_handshake.rs` L255-256 | CONFIRMED_MATCH | — |
| 13 | Ephemeral a | `RAND_bytes(192)`, `1 < a < N-1` no rejection sampling | `rand_bytes(192)`, rejection sampling `1 < a < N-1` up to 128 tries | Binary `0x10060410`; Rust `random_srp_exponent` L298-324 | PARTIAL_MATCH (sampling differs, output distribution same) | — |
| 14 | A = g^a mod N | `BN_mod_exp` | `a_public.mod_exp(&g_bn, &a_secret, &expected_n, &mut ctx)` | Binary `0x10060410`; Rust `control_handshake.rs` L773 | CONFIRMED_MATCH | — |
| 15 | u = H(PAD(A) ‖ PAD(B)) | `PAD(x)` = 192-byte left-zero-padded BE; `obj+0x04 & 2` selects padded | `pad_bignum_bytes(a_bytes, 192)`, `pad_bignum_bytes(b_bytes, 192)` | Binary `0x10060510`/`0x10060fa0`; Rust `compute_srp_u` L367-382 | CONFIRMED_MATCH | — |
| 16 | S = (B − k·v)^(a + u·x) mod N | `BN_sub`/`BN_mul`/`BN_add`/`BN_mod`/`BN_mod_exp` | `base.mod_sub(...)`, `ux.checked_mul(...)`, `exp.checked_add(...)`, `s.mod_exp(...)` | Binary `0x10060510`; Rust `control_handshake.rs` L864-892 | CONFIRMED_MATCH | — |
| 17 | KDF | `SHA1(S ‖ BE32(0)) ‖ SHA1(S ‖ BE32(1))` = 40 bytes | `SHA1(S_bytes ‖ 0u32.to_be_bytes()) ‖ SHA1(S_bytes ‖ 1u32.to_be_bytes())` = 40 bytes | Binary `0x10061790`; Rust `compute_srp_kdf` L384-400 | CONFIRMED_MATCH | — |
| 18 | M1 | `H(H(N) ⊕ H(g) ‖ H(I) ‖ salt ‖ A ‖ B ‖ K)`; A/B hashed in RAW minimal form | `sha1(h_xor ‖ h_i ‖ salt ‖ a_bytes ‖ b_bytes ‖ k_full)`; `h_i = sha1(username.as_bytes())` | Binary `0x100601b0`/`0x10060410`/`0x10060510`/`0x100609a0`; Rust `compute_srp_m1` L402-430 | PARTIAL_MATCH (identity encoding differs; A/B padding at call sites needs verification) | — |
| 19 | M2 | `H(A ‖ M1 ‖ K)` | `sha1(a_bytes ‖ m1 ‖ k_full)` | Binary `0x100609a0`; Rust `compute_srp_m2` L432-442 | CONFIRMED_MATCH | — |
| 20 | Session key | First 32 bytes of 40-byte K | `k_full[..CONTROL_SESSION_KEY_SIZE]` (32 bytes) | Binary `RvROLClient 0x1003dd40` → `0x100df250`; Rust `control_handshake.rs` L981-982 | CONFIRMED_MATCH | — |
| 21 | Key install | `SetKeyEnc`/`SetKeyDec` accept exactly 32 bytes | `FamatechCipherState::from_rsession_key(key_material)` takes `[0..32]` | Binary `0x1006ab00`/`0x1006aac0` reject ≠0x20; Rust `from_rsession_key` L181-186 | CONFIRMED_MATCH | — |
| 22 | Identity encoding on wire | UTF-16LE wide chars, byte-swapped to UTF-16BE per code unit | `encode_identity()`: `username.encode_utf16()`, writes big-endian per code unit | Binary `0x100667b0` (client), `0x100677d0` (server); Rust `encode_identity` L146-153 | CONFIRMED_MATCH (wire format matches) | — |
| 23 | Identity encoding in hash | UTF-16LE wide chars | `username.as_bytes()` = UTF-8 | Binary `0x10060340`/`0x10060c80` hashes wide-char bytes; Rust `compute_srp_x` L274-277 | **CONFIRMED_MISMATCH** | YES |
| 24 | Password encoding in x hash | UTF-16LE wide chars (inferred from identity source) | `password.as_bytes()` = UTF-8 | Binary `0x10060c80` (server) — caller not traced; Rust `compute_srp_x` L276 | **CONFIRMED_MISMATCH** (inferred; password caller not traced in binary) | YES |
| 25 | Public value validation | `len ≤ 192`, `val < N`, `val != 0`; base `> 1`, `base+1 != N` | `len == 192` (strict), `!= 0`, `< N`, `val mod N != 0`; no group pinning | Binary `0x100699e0` (pinning), `0x10060510` (validation); Rust `validate_srp_public_value` L326-365 | PARTIAL_MATCH (Rust exact-192 may reject valid short BN_bn2bin output; no group pinning in Rust) | Edge case (~1/256) |
| 26 | Password hash in control messages | `SHA1(password)` (SHA-1 over UTF-8 bytes?) | `hash_network_password(password)` = `sha1(password.as_bytes())` = SHA-1 over UTF-8 | Binary not traced for password hash in control messages; Rust `protocol/control.rs` L21-23 | UNVERIFIED | — |
| 27 | RSA public key size | 2048 bits (256 bytes) | `RSESSION_RSA_BLOCK_SIZE = 256`, `rsa.size() == 256` required | Binary `FUN_10066170` imports `(n, e)`; Rust `set_server_public_key_components` L148-166 | CONFIRMED_MATCH | — |
| 28 | RSA padding | PKCS#1 v1.5 (padding mode 1) | `Padding::PKCS1` | Binary `0x10065ec0` `PUSH 0x1`; Rust `handshake.rs` L262, 471 | CONFIRMED_MATCH | — |
| 29 | RSA operation | Client encrypts 76-byte plaintext with server public key; server decrypts with private key | `pub_key.public_encrypt(&plaintext, &mut encrypted, Padding::PKCS1)`; `self.private_key.private_decrypt(buf, &mut *decrypted, Padding::PKCS1)` | Binary `FUN_10065ec0`/`FUN_10065db0`; Rust `handshake.rs` L262, 471 | CONFIRMED_MATCH | — |
| 30 | Plaintext structure | 12-byte header (3×u32 LE client_params) + 64-byte key material = 76 bytes | `plaintext[0..4] = client_params[0].to_le_bytes()` ... `plaintext[12..76] = key_material` | Binary `FUN_1006a690` (client init); Rust `get_next_buffer` State 0 L253-258 | CONFIRMED_MATCH | — |
| 31 | Server token | 4 bytes, LE u32 | `server_token.to_le_bytes().to_vec()`; `u32::from_le_bytes(buf[0..4])` | Binary server emits 4-byte blob from `+0x04`; Rust `RSessionServer::create_server` L502, `get_next_buffer` State 2 L317 | CONFIRMED_MATCH | — |
| 32 | Key split | Hypothesis: `key_enc = secret[0..32]`, `key_dec = secret[32..64]` | `derive_aes256_key_ref()` returns `key_material[..32]` | Binary split not observed (UNVERIFIED); Rust takes first 32 bytes for both enc and dec | UNVERIFIED | — |
| 33 | Symmetric cipher | AES-256-CBC | `Cipher::aes_256_cbc()` | Binary `0x10062fb0`/`0x10062f30`; Rust `famatech.rs` L254-256 | CONFIRMED_MATCH | — |
| 34 | IV handling | Persistent 16-byte IV, updated from last ciphertext block, initial IV = zero | `enc_iv.copy_from_slice(&ciphertext[last_block_start..])`; initial `[0u8; 16]` | Binary AESCryptor object `+0x1ec`/`+0x1fc`; Rust `famatech.rs` L280, L312 | CONFIRMED_MATCH | — |
| 35 | Trailer | 0xCC fill + 64-bit additive checksum + MD5 → 8-byte fold + 1-byte pad length (9 bytes total) | `famitech_pad_and_sign` / `famitech_verify_and_unpad` | Binary `0x10069c20`/`0x10069f90`; Rust `famatech.rs` L64-125 | CONFIRMED_MATCH | — |
| 36 | Zeroization | `clear()` zeroizes keys and IVs; `Drop` calls `clear()` | `clear()` zeroizes; `Drop` impl calls `clear()` | Binary `SHelper_RSession_Delete` `0x1006b9e0`; Rust `Drop for FamatechCipherState` L318-322, `Drop for ControlClientNegotiator` L557-561, `Drop for RSessionServer` L536-540 | CONFIRMED_MATCH | — |
| 37 | Error handling | Fail-closed on validation failures | `fail_and_clear()` sets state to `Failed`, returns `Err` | Binary state machines transition to failed state; Rust `fail_and_clear()` L350-354, `fail_session` L578-584 | CONFIRMED_MATCH | — |
| 38 | Test evidence | N/A (binary tests not available) | Round-trip tests within Rust only; SRP test emulator with generated RSA key | Rust tests use `Rsa::generate(2048)` — NOT the original binary's key; no cross-implementation test | UNVERIFIED (Rust tests validate internal consistency only) | — |

### 2.3 Detailed analysis of critical mismatches

**3.1 Step Value Endianness (CONFIRMED_MISMATCH).** Binary: SRP-6a step field emitted as 4-byte big-endian (`00 00 00 01` for step 1), confirmed by TLV builder `0x100626e0` and PCAP traffic. Rust: `control_handshake.rs` uses `1u32.to_le_bytes()` → `01 00 00 00` at lines 670, 780, 910, 1267, 1399, 1456. Impact: server rejects step 1 because `0x01000000` (little-endian 1) does not equal expected `1` read as big-endian. Complete handshake failure. Fix required: change all `to_le_bytes()` calls for step values to `to_be_bytes()` in `control_handshake.rs`.

**3.2 Identity/Password Encoding (CONFIRMED_MISMATCH).** Binary: identity stored internally as UTF-16LE wide chars but byte-swapped to UTF-16BE per code unit on the wire (`0x100667b0` client, `0x100677d0` server). Password hashed as part of `x = H(salt ‖ H(I ‖ ":" ‖ P))` where `I` is identity; password byte encoding inferred UTF-16LE (same source as identity), not directly traced. Rust: `encode_identity()` correctly writes UTF-16BE on the wire (L146-153). However, `compute_srp_x()` hashes `username.as_bytes()` and `password.as_bytes()`, which are UTF-8 byte sequences (L274-277). Impact: `SHA1(UTF-8(username) ‖ ":" ‖ UTF-8(password)) ≠ SHA1(UTF-16LE(username) ‖ ":" ‖ UTF-16LE(password))`; cascades to `v`, `A`, `S`, `K`, `M1`, `M2` — entire handshake fails. Fix required: change `compute_srp_x` to hash UTF-16LE byte sequences for both username and password.

**3.3 Multiplier k (UNVERIFIED in gap analysis; UNKNOWN after audit reconciliation).** Binary: two classes — SRP-6a class `k = SHA1(N_bytes ‖ PAD(g,192))` (canonical SRP-6a per RFC 5054); legacy class `k = 3` (hardcoded). String pointers `"SRP-6a client (tjw)"` at `0x100a3df0` and `"SRP-6a server (tjw)"` at `0x100a3e18` point to vtables `0x100ad760`/`0x100ad7b4`, but instantiation path not traced. Rust: `RADMIN_SRP_K = 3` (hardcoded). Impact: if deployed class is SRP-6a, Rust's `k=3` is wrong → shared secret `S` differs → handshake fails. If legacy class, `k=3` matches. Fix required: determine which class is instantiated in `RvROLClient.dll` session constructor.

**3.4 Exact-192 Length Check (PARTIAL_MATCH).** Binary: `validate_srp_public_value` accepts `len ≤ 192` with `val < N` and `val != 0`; `BN_bn2bin` output shorter than 192 bytes (leading zero byte) accepted. Rust: requires `bytes.len() == RADMIN_SRP1536_MODULUS_LEN` (exactly 192) at L330-337. Impact: valid official peer whose public value has a leading zero byte (~1/256 probability) rejected by Rust. Interop edge case, not complete failure. Fix required: accept `len ≤ 192` and left-pad to 192 bytes.

**3.5 Version Endianness (PARTIAL_MATCH).** Binary: version constant `3` confirmed, on-wire byte order not directly observed (PCAP captures start after version exchange). Rust: `create_version_packet()` writes `SHELPER_PROTOCOL_VERSION.to_le_bytes()` → `03 00 00 00` at L587-589. Impact: if binary expects big-endian (`00 00 00 03`), version exchange fails. Fix required: determine on-wire version endianness from a capture including version exchange, or test against live server.

**3.6 Public Value Padding in M1 (PARTIAL_MATCH).** Binary: `M1` hashes `A` and `B` in raw minimal form (`BN_bn2bin` output without padding), while `u` uses padded 192-byte forms. Rust: `compute_srp_m1(...)` hashes `a_bytes` and `b_bytes` as passed by caller; caller must ensure correct padding. Impact: if caller passes unpadded `a_bytes`/`b_bytes` (minimal `BN_bn2bin` output), M1 matches; if padded, M1 differs. Fix required: verify call sites pass minimal-form (unpadded) public values.

### 2.4 Contradiction resolution (from CRYPTO_PHASE_10_5_COMPATIBILITY_AUDIT)

The audit cross-validated seven investigation reports against the Rust source. Headline: reports are internally contradictory on the three highest-impact questions (SRP multiplier `k`, SRP scrambling `u` symmetry, integer endianness). Several findings marked CONFIRMED in Tasks 4.1/4.2/4.3/5.1/5.2/5.3 are downgraded to UNKNOWN or INFERRED by Phase 10.7/10.8 reconciliation reports because the dispatcher selecting SRP code paths was never traced.

**Three blockers CONFIRMED_MISMATCH directly from Rust source + binary evidence (audit):**
1. SRP multiplier `k`: Rust hardcodes `RADMIN_SRP_K = 3` (control_handshake.rs:16), used in `kv = k*v mod N` at lines 861-863 (client) and 1283-1285 (server). Binary computes `k = SHA-1(N||PAD(g))` via FUN_10060810/FUN_10060ec0. Different `k` → different `kv = k*v mod N` → different `base = B - k*v` (client) / `avu = A*v^u` (server) → different `S` → different session keys. Handshake will fail. **Note:** the audit later downgrades `k` to UNKNOWN because the SRP-6a dispatch is not proven; the literal-3 routine `0x100607d0` is confirmed but its reachability is unknown. No code change to `RADMIN_SRP_K` authorized on current evidence per the audit's reviewer determination.
2. Identity hash encoding: Rust `compute_srp_x` hashes `username.as_bytes()` = UTF-8 at control_handshake.rs:275. Binary hashes identity as raw UTF-16LE bytes from `obj+0x8` (shelper.dll `0x10060340` client / `0x10060c80` server), confirmed via wire byte-swap at `0x100667b0`/`0x100677d0`. Different identity hash → different `x` → different `v` → different `A`, `S`, `K`, `M1`, `M2` → complete handshake failure. **Note:** audit downgrades to UNKNOWN because wire-side byte-swap confirms internal storage, not that `0x10060340` hashes those bytes without re-encoding.
3. RSession 64→32+32 AES key split: Rust `from_rsession_key` (famatech.rs:181-186) and `derive_aes256_key_ref` (handshake.rs:202-207) use `key_material[..32]` for BOTH enc and dec; bytes [32..64] unused. Binary requires two separate exactly-32-byte keys via `SetKeyEnc` (vtable +0x18) and `SetKeyDec` (vtable +0x1c), both enforcing `len == 0x20` (`shelper.dll` `0x1006ab00`/`0x1006aac0`). `GetKey` (`0x1006ba80`) returns all 64 bytes verbatim with no split. One key for both directions → one direction will fail decryption. Split mapping UNKNOWN — do not guess.

**Three blockers DISPROVEN / FALSE POSITIVE:**
| Claim | Original Verdict | Corrected Verdict | Reason |
|-------|-----------------|-------------------|--------|
| Asymmetric `u` computation | CONFIRMED (Task 4.1) | **DISPROVEN** | Binary functions `0x10060510`/`0x10060fa0` decompiled by Task 5.2: both compute `SHA-1(A||B)`; apparent asymmetry was variable misidentification (context+0x20 = own ephemeral, wire parameter = peer ephemeral). |
| Integer serialization mismatch | INCOMPATIBLE (Task 4.1) | **NOT CONFIRMED** | Rust `pad_bignum_bytes` (control_handshake.rs:288-296) produces big-endian wire output matching binary. `to_le_bytes()` uses are 32-bit protocol step/version fields, not SRP BIGNUMs. |
| task 4.1/5.2/5.3 all-conformant claims | Various | Various | Multiple claims downgraded to UNKNOWN per Phase 10.7/10.8 reconciliation |

**Confirmed compatibilities (audit C1-C10):** SRP modulus N `0x100ac280` = `RADMIN_SRP1536_PRIME_HEX` (control_handshake.rs:38-44); generator g `0x05` at `0x100ac279` = `RADMIN_SRP_GENERATOR = 5` (L14); KDF `SHA-1(S‖BE32(0))‖SHA-1(S‖BE32(1))` = 40 bytes = `compute_srp_kdf` L384-400; session key first 32 bytes of KDF output (control_handshake.rs L981-982, 1463-1464); RSA-2048 PKCS#1 v1.5 76-byte plaintext (12-byte LE header ‖ 64-byte key), 256-byte ciphertext = `handshake.rs` L10-16, 262; RSA transport direction client encrypts with public key / server decrypts with private key; AES-256-CBC persistent IVs 0xCC padding 9-byte trailer = `famatech.rs` L64-125; control-handshake vs RSession key separation (`RSession_GetKey` `0x1006ba80` vs control `GetKey` `0x1006b010`); decrypt-before-validation (`FUN_10069d70` decrypts before `FUN_10069f90` validates); no KDF/hash on RSession path (callee set of `FUN_1006a2b0`: memset, RAND, malloc, memcpy, RSA_pub_enc, RSA_priv_dec; no hash).

**Inferred findings (audit I1-I5):** SRP-6a client/server class names exist (`"SRP-6a client (tjw)"` at `0x100a3df0`, `"SRP-6a server (tjw)"` at `0x100a3e18`) INFERRED; server-side `k` externally provided at object `+0x20` INFERRED; password encoding likely UTF-16LE INFERRED; 64→32+32 AES key split INFERRED (SetKeyEnc/SetKeyDec each require len==0x20); step values on wire big-endian (`00 00 00 01` for step 1) INFERRED.

**Unknown findings (audit U1-U15):** include whether deployed SRP class is SRP-6a or legacy (UNKNOWN); whether `FUN_10060810` computes `k`/`u`/other (UNKNOWN); whether `FUN_100607d0` (literal `3`) executes in official handshake (UNKNOWN); whether server `k` equals client `k` (UNKNOWN); official identity hash encoding (UNKNOWN); official password encoding (UNKNOWN); official runtime widths for `A`, `B`, `u` inputs and `S` before KDF (UNKNOWN); whether `obj+0x30` auxiliary buffer appended to M1 (UNKNOWN); `GetKey` consumer location (UNKNOWN); which half of 64-byte secret → enc vs dec (UNKNOWN, duplicated U10/U11); client/server RSA key provenance (UNKNOWN); version on-wire endianness (UNKNOWN); `TwoFishV2` vftable `0x100832c4` dead code or instantiated (UNKNOWN); public value exact-192 vs `len ≤ 192` acceptance PARTIAL (binary accepts `len ≤ 192`; Rust requires exactly 192).

**False-positive / overconfident claims requiring correction (audit FP1-FP8):** includes SRP multiplier `k = SHA-1(N||PAD(g))` CONFIRMED → UNKNOWN; asymmetric `u` CONFIRMED INCOMPATIBILITY → DISPROVEN; integer serialization CONFIRMED_MISMATCH → NOT CONFIRMED for SRP BIGNUMs; identity hash UTF-16LE CONFIRMED_MISMATCH → UNKNOWN; Rust `key_material[..32]` for both enc/dec CONFIRMED_MISMATCH but split mapping UNKNOWN; session key first 32 bytes CONFIRMED → INFERRED/LIKELY → CONFIRMED only via gap analysis citation; referenced docs `CRYPTO_PHASE_10_4_GAP_ANALYSIS.md`/`CRYPTO_PHASE_10_4_UNRESOLVED.md` DO NOT EXIST; password hash encoding CONFIRMED_MISMATCH → UNKNOWN/INFERRED.

**Remaining blockers to interoperability (audit B1-B8):** SRP multiplier `k` CRITICAL; identity hash encoding CRITICAL; RSession AES key split CRITICAL; SRP integer padding MEDIUM; server `k` provenance MEDIUM; public value exact-192 vs `len ≤ 192` MEDIUM; public value endianness MEDIUM; client/server RSA key provenance MEDIUM.

**Prioritized next investigations (audit 1-11):** step value endianness; complete disp8 sweep for `GetKey` consumer (`disp8 ∈ {0xb0, 0xc0, 0xc4}`); determine 64→32+32 AES key split (`lea reg,[key+0x20]` split fingerprint); trace SRP dispatcher consumer (`shelper.dll` method table `.data` `0xad740`/`0xad760`; descriptor `0x100ad75c`/`0x100ad7b4`); confirm identity hash encoding at `0x10060340`; confirm password encoding; trace `u` width fields and `S` width before KDF (`shelper.dll` `0x1005fad0` width fields `[esi+0xc]`, `[esi+0x10]`; KDF caller `0x10061790`); determine `A`/`B` order in `u` and `M1`; version on-wire endianness; public value exact-192 vs `len ≤ 192` check relaxation (control_handshake.rs L330-337); interop test with original RSA key.

### 2.5 Components not implemented in Rust (gap analysis §4)

| Component | Binary Behavior | Rust Status | Notes |
|-----------|-----------------|-------------|-------|
| Control channel messages (Login, LoginResponse, JoinNetwork, etc.) | TLV-structured control messages after SRP-6a handshake | NOT_IMPLEMENTED | `src/protocol/control.rs` defines message types but no integration with encrypted control channel |
| RSession server (`RSessionServer`) | Server-side RSA decryption, token emission | PARTIAL | `src/session/handshake.rs` has `RSessionServer` but integration with transport layer not verified |
| Control channel state machine (6 steps) | Full SRP-6a handshake on TCP/17301 | NOT_IMPLEMENTED | `ControlClientNegotiator` exists but no integration with `TcpChannel` for control port |
| Key rotation | None observed | NOT_IMPLEMENTED | No key rotation in either binary or Rust |

### 2.6 Components not in binary but present in Rust (gap analysis §5)

| Component | Rust Behavior | Notes |
|-----------|---------------|-------|
| TLV message type system (U32, U64, I32, Bool, Float, Double, Buffer, StringUtf8, etc.) | Full TLV encoding/decoding with validation | Binary uses only U32 and Buffer types; Rust has a more general TLV system |
| Bool value/raw mismatch validation | Rust rejects `value != decoded(raw)` | Binary does not appear to validate this |
| Message size limits (65535 bytes max) | `MAX_TLV_MESSAGE_SIZE = 65535` | Binary limits unknown |
| Record count limits (1024 max) | `MAX_TLV_RECORDS_PER_MESSAGE = 1024` | Binary limits unknown |

### 2.7 Test coverage assessment (gap analysis §6)

Rust test suite (`#[cfg(test)]` modules) provides **internal consistency verification only**: `test_session_full_handshake_and_encrypted_data_exchange` — client-server handshake with a **generated** RSA-2048 key (`Rsa::generate(2048)`), not the original binary's key; `test_rsession_full_handshake_and_cchannel_key_installation` — same with generated key; all framing/TLV tests use synthetic data, not captured PCAP traffic. No test validates interoperability with the original binary's key material or protocol behavior. A test against `RvROLClient.dll`'s actual RSA public key, or against captured PCAP traffic, would be required for interoperability evidence.

### 2.8 Recommended fixes (priority order, gap analysis §7)

| Priority | Issue | Fix | Binary Evidence |
|---|-------|-----|-----------------|
| 1 (Critical) | Step value endianness | Change `to_le_bytes()` to `to_be_bytes()` for all step values in `control_handshake.rs` | PCAP frames + binary builder `0x100626e0` |
| 2 (Critical) | Identity/password encoding in `x` | Hash UTF-16LE byte sequences for username and password in `compute_srp_x` | Binary `0x10060340`/`0x10060c80` hashes wide-char bytes |
| 3 (High) | Multiplier k | Determine which class is instantiated; if SRP-6a, compute `k = SHA1(N_bytes ‖ PAD(g,192))` at runtime | Binary vtable `0x100ad760`/`0x100ad7b4` |
| 4 (Medium) | Public value length check | Accept `len ≤ 192` and left-pad to 192 bytes | Binary `0x100699e0` accepts `len ≤ 192` |
| 5 (Medium) | Version endianness | Determine on-wire byte order; adjust `to_le_bytes()`/`to_be_bytes()` accordingly | PCAP capture with version exchange needed |
| 6 (Low) | Public value padding in M1 | Verify call sites pass minimal-form (unpadded) public values | Binary `BN_bn2bin` output |

---

## 3. Remediation History

Source: `docs/CRYPTO_PHASE_10_5_REMEDIATION.md` (Portuguese-language remediation report; technical facts preserved verbatim). Repository: `https://github.com/Pedrodroks34/radmin-vpn-linux-rs`, branch `main`, HEAD commit `a6ae3fbbdffec872732a4f2c4104042027d3b428`.

### 3.1 Executive summary

Reverse-engineering analysis of official binaries (`shelper.dll`, `RvROLClient.dll`, `RvControlSvc.exe`) revealed three critical incompatibilities between original Rust code and official Windows client behavior. This document records the engineering changes applied to the Rust `radmin-vpn` client to eliminate those incompatibilities, based strictly on reverse-engineering evidence. No packet fields, algorithms, or parameters were invented.

### 3.2 Changes applied

**Change 1 — Replace `RADMIN_SRP_K = 3` with `k = SHA-1(N||PAD(g))`.** File: `src/session/control_handshake.rs`. Problem: Rust used `RADMIN_SRP_K = 3` (constant integer) as SRP multiplier; official `shelper.dll` computes `k = SHA-1(N || PAD192(g))` dynamically via `FUN_10060810` (client) and `FUN_10060ec0` (server). Legacy `k=3` path (`FUN_100607d0`) is dead code (not referenced by SRP-6a descriptors).

Change applied:
- Replaced static constant `RADMIN_SRP_K: u32 = 3` with function `srp_k()` computing `SHA-1(N || PAD192(g))` dynamically.
- `N` (1536-bit prime) and `g = 0x05` read from same offsets as official binary (`0x100ac280` and `0x100ac279`).
- `k` computed as `SHA-1(N_bytes || PAD192(g_bytes))` where `PAD192(g)` is `g` left-zero-padded to 192 bytes.
- Result `k` is a `BigNum` of 192 bytes used in `k*v mod N` and `k*v^u mod N`.

Lines altered in `src/session/control_handshake.rs`:
- Line 16: replaced `pub const RADMIN_SRP_K: u32 = 3;` with `pub static RADMIN_SRP_K: OnceLock<BigNum> = OnceLock::new();`
- Lines 19-30: added function `srp_k()` computing `SHA-1(N||PAD(g))` as `BigNum`
- Line 275: `username.as_bytes()` → `encode_identity(username)` (identity must be used as UTF-16LE raw bytes from internal object, not UTF-8)
- Lines 861-863: replaced `BigNum::from_u32(RADMIN_SRP_K)` with `srp_k()?`
- Lines 1283-1285: replaced `BigNum::from_u32(RADMIN_SRP_K).map_err(|e| ...)` with `srp_k()?`
- Line 1580 (test): `let k_from_rust = RADMIN_SRP_K.get().unwrap().to_vec();` → `let k_from_rust = srp_k().unwrap();`

Evidence: reverse engineering of `shelper.dll` functions `FUN_10060810` and `FUN_10060ec0` showed both compute `SHA-1(N || PAD(g))` where `N` comes from field `+0x0C` and `g` from field `+0x10` of session object. Legacy `k=3` (`FUN_100607d0`) not referenced by any SRP-6a descriptor.

**Change 2 — Identity hash encoding.** File: `src/session/control_handshake.rs`, line 275: `username.as_bytes()` → `encode_identity(username)`. Rationale: identity must be UTF-16LE raw bytes per binary `obj+0x8`.

### 3.3 Changes NOT applied (AES key split)

Task 5.1 revealed the binary uses **two separate AES-256 keys** (one for enc, one for dec) derived from the 64-byte RSession secret, but the **mapping of which half goes to which direction is unknown** (consumer call site in `RvROLClient.dll`/`RvControlSvc.exe` could not be traced due to indirect `disp8` calls). Therefore:
- Not altered: `src/crypto/famatech.rs` or `src/session/handshake.rs` regarding key split.
- Rust continues using `key_material[..32]` for both directions.
- This is a known unresolved incompatibility blocking full interoperability until the split is determined by further reverse engineering of consumer binaries.

### 3.4 Supporting evidence

Binaries analyzed:
| Binary | SHA-256 | Location |
|--------|---------|----------|
| `shelper.dll` | `d89daf6bcd5cafa3c7f6173f835ccf045baf8e7134f868819db6fd7615959ac4` | `/tmp/rea-ghidra-KCSGad/target-d89daf6bcd5c.dll` |
| `RvROLClient.dll` | `6ba7dfecd38183d4bff0fc53f1c8c05d25e636077fe753b1220912aa58938177` | `claude-handoff/binaries/radmin_ext/` |
| `RvControlSvc.exe` | `546efad9ab3ff85c2a50d61524d754bec94a3f3e30d6ae8addef481a1e8daa1e` | `claude-handoff/binaries/radmin_ext/` |

Relevant function addresses in `shelper.dll`:
| Function | Address | Purpose |
|----------|---------|---------|
| `ROLClient_InitDll` | `0x10041010` | Initializes CChannel and `shelper.dll` resolution |
| `ROLClient_Send` | `0x10041e70` | Packet sending |
| `ROLClient_Receive` | `0x100418b0` | Packet reception |
| `SetKeyEnc` | `0x10041c00` | Installs encryption key |
| `SetKeyDec` | `0x10041c40` | Installs decryption key |
| `EncryptBuffer` | `0x10041c80` | Encrypts buffer |
| `DecryptBuffer` | `0x10041cc0` | Decrypts buffer |

### 3.5 Compliance status

| Item | Binary | Rust | Status |
|------|--------|------|--------|
| SRP-6a `k` | `SHA-1(N||PAD(g))` | Before: `k=3`; After: `SHA-1(N||PAD(g))` | **CORRIGIDO (fixed)** |
| Identity hash | UTF-16LE (obj+0x8) | Before: UTF-8; After: UTF-16LE raw bytes | **CORRIGIDO (fixed)** |
| 64→32+32 AES key | Two separate 32B keys | One 32B key for both directions | **NÃO CORRIGIDO (not fixed)** — split mapping unknown |
| AES-256-CBC | Confirmed | Confirmed | OK |
| 0xCC padding | Confirmed | Confirmed | OK |
| 9-byte trailer (folded MD5) | Confirmed | Confirmed | OK |
| RSA-2048 PKCS#1 v1.5 | Confirmed | Confirmed | OK |

### 3.6 Pending (unresolved)

| Item | Description | Status |
|------|-------------|--------|
| AES key split | 64 bytes → 32+32, which half is enc/dec? | Unknown — requires consumer call site tracing in `RvROLClient.dll`/`RvControlSvc.exe` |
| Handshake step endianness | Wire uses big-endian; Rust uses `to_le_bytes()` | Not addressed in this phase (out of scope) |
| RSA key model | Origin of public/private keys unknown | Not investigated in this phase |

### 3.7 Files modified

| File | Change | Reason |
|------|--------|--------|
| `src/session/control_handshake.rs` | Line 16: `RADMIN_SRP_K` → `srp_k()`; Line 275: `username.as_bytes()` → `encode_identity(username)` | Fix SRP-6a k multiplier and identity hash encoding |
| `src/session/mod.rs` | Added `srp_k` to public exports | Export `srp_k` for use in other modules |

### 3.8 Additional dependencies

No new external dependency added. Crate `openssl` already present; provides SHA-1 via existing `openssl::sha::sha1`.

---

## 4. Validation

Source: `docs/CRYPTO_PHASE_10_5_VALIDATION.md`. Repository: `https://github.com/Pedrodroks34/radmin-vpn-linux-rs`, branch `main`, HEAD commit `a6ae3fbbdffec872732a4f2c4104042027d3b428`.

### 4.1 Executive summary

Validation of cryptographic fixes applied in Task 5.5 of Phase 10.5. Fixes address three confirmed incompatibilities between Rust client and official Windows Radmin VPN client: (1) SRP multiplier `k=3` hardcoded → `k=SHA-1(N||PAD(g))` dynamic; (2) identity hash encoding UTF-8 → UTF-16LE (raw `obj+0x8` bytes); (3) AES key split 32 bytes for both directions → two separate 32-byte keys (pending mapping).

### 4.2 Build results

| Command | Result | Output |
|---------|--------|--------|
| `cargo build` | ✅ SUCCESS | Compiles without errors |
| `cargo test --locked --all-targets` | ✅ SUCCESS | 147 unit tests + 5 integration tests passed |
| `cargo fmt --check` | ✅ SUCCESS | Code formatted per rustfmt |
| `cargo clippy` | Not executed | Not run (not mandatory for validation) |

Build output:
```
   Compiling radmin-vpn v0.1.0 (/home/pedrodroks/Downloads/radmin)
    Finished dev [unoptimized + debuginfo] target(s) in 1.91s
```

All tests passed:
```
test result: ok. 147 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

Integration tests (5): `test_pcap_radmin_17301_control_frames_validation` ✅; `test_e2e_real_captured_packet_686_validation` ✅; `test_e2e_crypto_tampering_resilience` ✅; `test_e2e_ethernet_pipeline` ... ok; `test session::tests::test_tcp_channel_disconnect_with_partial_frame` ... ok; (all passed).

### 4.3 Fix verification

**4.3.1 SRP multiplier fix (`k = SHA-1(N||PAD(g))`).**

Before:
```rust
pub const RADMIN_SRP_K: u32 = 3;
```

After:
```rust
pub static RADMIN_SRP_K: OnceLock<BigNum> = OnceLock::new();

pub fn srp_k() -> Result<BigNum, ControlHandshakeError> {
    RADMIN_SRP_K.get_or_init(|| {
        let n_bytes = BigNum::from_hex_str(RADMIN_SRP1536_PRIME_HEX)
            .map_err(|e| ControlHandshakeError::CryptoError(format!("falha ao carregar N: {e}")))?;
        let g_bytes = [RADMIN_SRP_GENERATOR];
        let mut pad_g = vec![0u8; RADMIN_SRP1536_MODULUS_LEN - g_bytes.len()];
        pad_g.extend_from_slice(&g_bytes);
        let mut input = Vec::with_capacity(n_bytes.to_vec().len() + pad_g.len());
        input.extend_from_slice(&n_bytes.to_vec());
        input.extend_from_slice(&pad_g);
        let k_hash = sha1(&input);
        BigNum::from_slice(&k_hash)
            .map_err(|e| ControlHandshakeError::CryptoError(format!("falha ao criar k: {e}")))
    })?;
    Ok(RADMIN_SRP_K.get().unwrap().clone())
}
```

Validation test: `test_srp_group_parameters` calculates `k = SHA-1(N || PAD192(g))` independently and compares with `RADMIN_SRP_K.get().unwrap().to_vec()`. Test passes, confirming Rust now uses same `k` value as official binary.

**4.3.2 Identity encoding fix.**

Before:
```rust
let mut cred_buf = Zeroizing::new(Vec::with_capacity(username.len() + 1 + password.len()));
cred_buf.extend_from_slice(username.as_bytes());  // UTF-8 (INCORRETO)
cred_buf.push(b':');
cred_buf.extend_from_slice(password.as_bytes());
```

After:
```rust
let mut cred_buf = Zeroizing::new(Vec::with_capacity(username.len() + 1 + password.len()));
cred_buf.extend_from_slice(&encode_identity(username));  // UTF-16LE (correto)
cred_buf.push(b':');
cred_buf.extend_from_slice(password.as_bytes());
```

Test: existing test `test_identity_utf16_byte_swapping` verifies `encode_identity` produces correct UTF-16LE, and `decode_identity` decodes it back.

**4.3.3 AES key (split not resolved).** Status: NOT FIXED. Rust still uses `key_material[..32]` for both directions (enc and dec), while official binary requires two separate 32-byte keys. Mapping of which half goes to which direction not determined via reverse engineering of available binaries (consumer call site in `RvROLClient.dll`/`RvControlSvc.exe` not located due to indirect `disp8` calls not statically detectable). Recommendation: when split is determined, modify `from_rsession_key` in `src/crypto/famatech.rs` to use `key_material[..32]` for enc and `key_material[32..]` for dec (or vice-versa, depending on discovered mapping).

### 4.4 Test results

**Unit tests (147) — all passed:**
- `session::control_handshake::tests::test_srp_group_parameters` ... ok
- `session::control_handshake::tests::test_full_srp_handshake_success` ... ok
- `session::control_handshake::tests::test_srp_kdf_40_bytes` ... ok
- `crypto::famatech::tests::test_rsession_64_byte_key_installation_and_channel` ... ok
- `session::tests::test_srp_handshake_wrong_password_fails` ... ok
- `session::control_handshake::tests::test_srp_handshake_tampered_m1_fails_closed` ... ok

**Integration tests (5) — all passed:**
- `pcap_radmin_17301_control_frames_validation` ... ok
- `e2e_real_captured_packet_686_validation` ... ok
- `e2e_crypto_tampering_resilience` ... ok
- `e2e_ethernet_pipeline` ... ok
- `session::tests::test_handshake_rejects_invalid_server_token_size_and_closes_channel` ... ok

### 4.5 Remaining differences (not fixed)

| Item | Status | Reason |
|------|--------|--------|
| RSession AES key split (2×32 bytes) | Not fixed | Split mapping unknown; requires consumer call site tracing |
| Step endianness (little-endian vs big-endian) | Not fixed | Out of scope of Task 5.5; requires PCAP analysis |
| Identity hash UTF-8 vs UTF-16LE | Fixed | Uses `encode_identity()` producing UTF-16LE bytes |
| Multiplier k=3 vs SHA-1(N||PAD(g)) | Fixed | Now uses dynamic `SHA-1(N||PAD(g))` |

### 4.6 Limitations and next steps

Limitations: (1) AES key split unresolved — consumer of `GetKey` deciding which half of 64 bytes goes to enc vs dec not located in available binaries; until discovered, Rust uses same 32-byte key for both directions, resulting in decryption failure in one direction; (2) handshake step endianness — Rust uses `to_le_bytes()` for steps 1-10, PCAP traffic shows big-endian, preventing handshake from working correctly; (3) RSA key origin — could not determine where client gets server public key or where server gets private key.

Next steps: (1) trace `GetKey` consumer in `RvROLClient.dll`/`RvControlSvc.exe` to determine key split (dispatcher sweep with `call [reg+0xb0/c0/c4]`); (2) investigate step endianness in PCAP to determine if Rust should use `to_be_bytes()` for handshake steps; (3) trace RSA key origin in client/server binaries; (4) validate full interoperability against official Windows client once items above resolved.

No binaries, PCAPs, or Ghidra databases modified. No commit, push, branch, or PR created.

---

## 5. Implementation Recommendations

Sources: `docs/CRYPTO_RUST_GAP_ANALYSIS.md` §7, `docs/PHASE_2_3/12_RUST_COMPATIBILITY_ASSESSMENT.md`, `docs/PHASE_2_3/23_EXTENDED_RUST_COMPATIBILITY.md`, `docs/PHASE_2_4/13_RUST_COMPATIBILITY_REASSESSMENT.md`, `docs/PHASE_2_5/13_RUST_COMPATIBILITY_REASSESSMENT.md`.

### 5.1 Priority fixes for cryptographic interoperability (from gap analysis §7)

1. (Critical) Step value endianness: change `to_le_bytes()` to `to_be_bytes()` for all step values in `control_handshake.rs`.
2. (Critical) Identity/password encoding in `x`: hash UTF-16LE byte sequences for username and password in `compute_srp_x`.
3. (High) Multiplier `k`: determine which SRP class is instantiated; if SRP-6a, compute `k = SHA1(N_bytes ‖ PAD(g,192))` at runtime.
4. (Medium) Public value length check: accept `len ≤ 192` and left-pad to 192 bytes.
5. (Medium) Version endianness: determine on-wire byte order; adjust `to_le_bytes()`/`to_be_bytes()` accordingly.
6. (Low) Public value padding in M1: verify call sites pass minimal-form (unpadded) public values.

### 5.2 Windows object-lifecycle patterns — do NOT implement in Rust

Per AGENTS.md constraints and verified findings (Phase 2.3 Stage 12/23, Phase 2.4 Stage 13, Phase 2.5 Stage 13):

| Windows Pattern | Reason Not to Implement |
|-----------------|-------------------------|
| C++ vtable layouts | Rust trait objects use different layout; not portable |
| Adjustment thunks (`SUB ECX, offset`) | Rust has no `this` pointer adjustment |
| Multi-phase vptr transitions | Rust constructors do not overwrite vtables |
| `field_0x28/0x2C/0x30` as u32 fields | Rust should use enum state machine, not numeric comparisons |
| Manual `HeapAlloc`/`HeapFree` | Rust ownership model handles allocation/deallocation |
| `LOCK()`/`UNLOCK()` critical sections | Rust `Arc<T>` / `AtomicBool` / `Mutex<T>` are safer |
| `RegCloseKey` / `EventUnregister` | Windows-specific APIs; no Linux equivalent |
| `GetLastError`/`SetLastError` | Rust uses `Result<T, E>` for error handling |
| Destroy-on-read-nonzero (`FUN_004731E0` → `FUN_00473210`) | Rust `Arc<T>` handles destruction automatically at count 0 |
| Set refcount to 0 (not decrement) | Rust ownership model handles deallocation; explicit zeroing not idiomatic |
| Atomic exchange of obj+0x24 flag | Use `AtomicBool`/`AtomicU32` only if flag semantics understood |
| `DeleteCriticalSection` explicitly | Rust `Mutex<T>`/`RwLock<T>` drop automatically |

### 5.3 Windows → Rust viable mappings

| Windows Behavior (Confirmed) | Rust Equivalent | Viability | Notes |
|------------------------------|-----------------|-----------|-------|
| Refcount at obj+0x20 with LOCK/UNLOCK | `Arc<T>` / `AtomicUsize` | VIABLE | `Arc::clone()` = AddRef, `drop` = Release |
| Release via `FUN_004731E0` | `impl Drop for T` | VIABLE | Automatic when `Arc` count reaches 0 |
| AddRef (not found in Windows) | `Arc::clone()` | VIABLE | Standard Rust pattern |
| List cleanup (5 functions, `FUN_004e6cd7` per node) | `Vec<Arc<T>>` / `LinkedList<Arc<T>>` | VIABLE | Automatic drop, no manual unlinking |
| Destruction chain → `CALL [0x500ca6]` | Custom `Drop::drop()` | VIABLE | If special deallocation needed |
| `field_0x28` compared to 5 | `enum` state machine | VIABLE | Enum instead of u32 comparison |
| `field_0x2C` compared to 0 | `bool` or `Option<T>` | VIABLE | Rust type system instead of sentinel |
| `field_0x30` incremented counter | `AtomicU64` or `u64` | VIABLE | If thread-safe needed |
| `obj+0x24` exchanged atomically | `AtomicU32` or `AtomicBool` | PARTIAL | Could be destroyed flag or generation counter |
| Fields not initialized by constructor | `Option<T>` or `default()` | VIABLE | Rust `Default::default()` zero-initializes; matches zero-init heap hypothesis |

### 5.4 What Rust already has vs. Windows

| Concept | Windows (`RvControlSvc.exe`) | Rust (`radmin-vpn-linux-rs`) | Gap |
|---------|------------------------------|------------------------------|-----|
| Reference counting | Manual (obj+0x20, LOCK/UNLOCK) | `Arc<T>` (partial) | Partial — daemon uses `Arc` but not for object lifecycle |
| List of objects | 5 manual cleanup functions | `Vec<T>` / `LinkedList<T>` | Missing — no object list in Rust |
| State machine | u32 fields (0x28, 0x2C) | `enum SessionState` | Implemented in `session/mod.rs` |
| Object construction | Multi-phase vptr transitions | `fn new()` | Different pattern |
| Object destruction | `CALL [0x500ca6]` | `Drop` trait | Different pattern |
| IPC | Named pipe `\\.\pipe\RadminVpnGuiChannel` | Unix domain socket | Different mechanism |
| Control port | TCP 17301 | Not implemented | Missing |
| Real Radmin networking | YES | NO | Major gap — Rust daemon is mock/stub |

### 5.5 Could be implemented (future phase)

| Windows Pattern | Rust Implementation | Priority |
|-----------------|---------------------|----------|
| Reference-counted object | `Arc<T>` + `Drop` | Medium |
| List of objects with cleanup | `Vec<Arc<T>>` / `LinkedList<Arc<T>>` | Medium |
| Global flag with synchronization | `AtomicBool` / `AtomicU32` | Low |
| Object factory | `Arc::new()` / custom factory function | Low |
| Session state machine | `enum SessionState` + `SessionManager` | High (partially done) |

`session/` module already implements `SessionState` enum and `SessionManager` with proper state transitions. `daemon/` module implements `DaemonContext` with `Arc<DaemonContext>` for shared ownership. These are correct Rust equivalents; they do not need to mirror C++ implementation details.

---

## 6. Dynamic Analysis Plans

Sources: `docs/CRYPTO_PHASE_10_13_DYNAMIC_ANALYSIS_PLAN.md` (Phase 10.13), `docs/CRYPTO_PHASE_10_20_DYNAMIC_ANALYSIS_READINESS.md` (Phase 10.20), `docs/PHASE_2_5/13_RUST_COMPATIBILITY_REASSESSMENT.md` (Phase 2.5 Stage 12 context).

### 6.1 Phase 10.13 — Dynamic Analysis Plan — Unresolved P0 Blockers

**Experiment 1 — Password Encoding (OQ-2) — REQUIRES_DYNAMIC_ANALYSIS.** Objective: determine exact byte encoding of password supplied to SRP `x` hash.
- Module: `shelper.dll`; Function: `0x10060340` (client x computation); Breakpoint: function entry (`0x10060340`); Also check `0x10060c80` (server x computation).
- Calling convention: `__stdcall`-ish; args at `[ebp+8]` (this), `[ebp+12]` (password_len), `[ebp+16]` (password_ptr).
- VM: `win10` (historical: 192.168.122.77, KVM/virt-manager); Tool: x64dbg or WinDbg; install breakpoint `bp shelper.10060340`.
- Memory inspection at breakpoint: `EDX` at `0x10060384` = password data pointer; `EDI` at `0x10060355` = password length (bytes); `[EDI]` dereference = actual password bytes. Capture: dump `EDI` bytes starting at `EDX`.
- Test credentials: Username `"A"` (identity); Password `"p"` (single ASCII). Expected byte sequences: UTF-8: `70`; UTF-16LE: `70 00`; UTF-16BE: `00 70`; ANSI: `70`. A single ASCII character distinguishes all encodings by length (1 vs 2 bytes) and content.
- Expected observations: `70` (len=1) → UTF-8 or ANSI; `70 00` (len=2) → UTF-16LE; `00 70` (len=2) → UTF-16BE; `70 00 00 00` (len=4) → UTF-32LE (unlikely); longer buffer with null terminator → null-terminated string (unlikely given `0x10060384` uses explicit len).
- Success criteria: encoding confirmed if captured bytes match exactly one encoding. Non-ASCII test (e.g., `"é"`) further confirms via multi-byte UTF-8 `C3 A9` vs UTF-16LE `E9 00` vs UTF-16BE `00 E9`.
- Call stack: record full call stack to identify caller module and function, tracing password provenance chain back to application input.

**Experiment 2 — Identity Hash Encoding Confirmation (OQ-3) — RESOLVED_STRONGLY_SUPPORTED.** Based on: binary reads `obj+0x8` raw for hash (no swap at `0x10060361`); binary byte-swaps a copy for wire (`0x100667b0`); Windows native string format is UTF-16LE.
- Optional confirmation breakpoint: same as password (`0x10060340`). At `0x10060361`, read `obj+0x8`: `EAX` after `mov 0x8(%esi),%eax` = identity struct pointer; `[EAX]` = data pointer; `[EAX+4]` = length. Test identity: `"A"` → expected `41 00` (LE) or `00 41` (BE).
- Success criteria: if buffer contains `41 00`, identity hash = UTF-16LE CONFIRMED. If `00 41`, identity hash = UTF-16BE CONFIRMED (and STRONGLY_SUPPORTED conclusion wrong).

**Experiment 3 — AES Mapping Confirmation (OQ-1) — RESOLVED_STRONGLY_SUPPORTED.** Based on two independent call paths in `RvROLClient.dll` both passing same buffer pointer for enc and dec.
- Optional confirmation breakpoint: Module `RvROLClient.dll`; Function `0x100df250` (SetKeyPair wrapper); Breakpoint: function entry.
- Memory inspection: at breakpoint, read `0xc(%ebp)` and `0x14(%ebp)` (key1_ptr and key2_ptr). Compare pointers. If equal, same-key CONFIRMED. If differ by 0x20, halves are `buf[0..32]` and `buf[32..64]`.
- Success criteria: if both pointers identical, STRONGLY_SUPPORTED conclusion CONFIRMED. If differ, mapping is `FIRST_32_ENC_SECOND_32_DEC` and Rust is WRONG.
- `RvControlSvc.exe` gap: control service (`FUN_00442290`) resolves GetKey but its consumer not traced. Breakpoint on `shelper.dll!0x1006a630` in control service process would confirm same-pointer or different-halves usage.

**Execution context (all experiments):** Windows 10 VM with Radmin VPN installed; ability to initiate connection to test server; debugger attached to client process (`RvControlSvc.exe` or `RvROLClient.dll` host). SRP handshake typically runs on single worker thread; record thread ID at each breakpoint. SRP x computation occurs during initial authentication phase, before encrypted communication; AES key installation occurs after RSession handshake completes — separate sessions/phases.

**Summary of required dynamic experiments:**
| Experiment | Blocker | Breakpoint | Success = | Priority |
|------------|---------|------------|-----------|----------|
| EXP-1 | Password encoding | `shelper.dll!0x10060340` | Password bytes match one encoding | P0 |
| EXP-2 | Identity LE confirmation | `shelper.dll!0x10060340` + `0x10060361` | `41 00` vs `00 41` | P1 |
| EXP-3 | AES same-pointer | `RvROLClient.dll!0x100df250` | Both ptr args identical | P1 |
| EXP-4 | RvControlSvc.exe AES | `shelper.dll!0x1006a630` in control svc process | Pointer comparison | P1 |

Minimum dynamic session needed: a single debugger session with breakpoints on `0x10060340` (password + identity) resolves both P0 remaining items.

### 6.2 Phase 10.20 — Dynamic Analysis Readiness & Instrumentation Plan

**Executive summary:** No dynamic execution was performed. No Windows VM, QEMU, debugger, or live process was available. All breakpoints and procedures specified but not executed. Three workstreams planned: A — password encoding (breakpoint `shelper.dll!0x10060340` to capture password pointer and length); B — M2 accumulator (breakpoint `shelper.dll!0x100609a0` to capture SHA-1 context states and input bytes); C — RSA constructor (breakpoint `shelper.dll!0x1006b4e0` to capture key components). One instrumented session sufficient to resolve all three P0/P1 blockers.

**Repository state:** Branch `main`; HEAD `95e304e0855a6faf4eece932484cb00e36620a6e`; working tree 3 tracked modified + 71 untracked; no commit/push.

**Infrastructure limitations:** Windows VM: NO (no QEMU/KVM, no virt-manager). Windows debugger: NO (no x64dbg, no WinDbg). Live Radmin process: NO. Runtime instrumentation: NO. Linux GDB: YES (but no Windows target). No breakpoint installed or tested. No runtime data captured. Phase is strictly preparation; ready to execute when Windows environment available.

#### 6.2.1 Password Breakpoint Plan

Target: Module `shelper.dll`; Function `0x10060340` (client x computation); Also check `0x10060c80` (server x computation); Breakpoint: function entry.
Calling convention: standard x86 `__stdcall`. Arguments on stack:
| Offset | Argument | Register at entry |
|--------|----------|-------------------|
| `[ebp+8]` | `this` (SRP object) | `ESI` after prologue |
| `[ebp+12]` | `password_len` | `EDI` after prologue |
| `[ebp+16]` | `password_ptr` | `EDX` at `0x10060384` |

Data to capture: (1) Password pointer: `EDX` at `0x10060384` (`mov 0x10(%ebp),%edx`); (2) Password length: `EDI` at `0x10060355` (`mov 0xc(%ebp),%edi`); (3) Raw password bytes: dereference `EDX`, dump `EDI` bytes; (4) Identity buffer: `obj+0x8` from `ESI` — pointer and length; (5) Identity bytes: dereference identity pointer; (6) Call stack: full stack trace with module-relative addresses.

Test credentials:
| Test | Password | UTF-8 | UTF-16LE | UTF-16BE | ANSI |
|------|----------|-------|----------|----------|------|
| T1 | `p` | `70` (1B) | `70 00` (2B) | `00 70` (2B) | `70` (1B) |
| T2 | `päss` | `70 c3 a4 73 73` (5B) | `70 00 e4 00 73 00 73 00` (8B) | `00 70 00 e4 00 73 00 73` (8B) | `70 e4 73 73` (4B) |
| T3 | `😀` (U+1F600) | `f0 9f 98 80` (4B) | `3d d8 00 de` (4B) | `d8 3d de 00` (4B) | N/A |

Observation mapping:
| Observation | Length | Encoding | Confidence |
|-------------|--------|----------|------------|
| `70` | 1 | UTF-8 or ANSI | PARTIAL (T2 distinguishes) |
| `70 00` | 2 | UTF-16LE | **CONFIRMED** (if T2 also UTF-16LE) |
| `00 70` | 2 | UTF-16BE | **CONFIRMED** (if T2 also UTF-16BE) |
| `70 c3 a4 73 73` | 5 | UTF-8 | **CONFIRMED** |
| `70 e4 73 73` | 4 | ANSI (Cp1252) | **CONFIRMED** |

Success criteria: encoding CONFIRMED if T1 and T2 both match same candidate encoding; length matches expected byte count; bytes match expected hexadecimal sequence.

#### 6.2.2 M2 Capture Plan

Target: Module `shelper.dll`; Function `0x100609a0` (M2 computation); Also check `0x100612f0` (M1 verification).
SHA-1 context states to capture at M2 function entry, dump all four contexts at `context+0x38`:
| Context | Offset | Purpose |
|---------|--------|---------|
| Primary | `+0x00` | Accumulates ... (TBD) |
| M1/M2 accumulator | `+0x60` | A, M1, K for M2 |
| K context | `+0xc0` | Session key material |
| M2 verification | `+0x120` | Verification context |

Each context is 0x60 bytes. Dump full 0x180 bytes.
SHA-1 input captures: set hardware breakpoints on SHA-1 update function `0x100285f0`: first update in M2 — pointer, length, raw bytes; second update (K) — pointer, length, 40 bytes.
BIGNUM buffer capture: at `0x100609c3` (`call 0x1005f620`): capture BIGNUM pointer, requested size (0x14 = 20), buffer capacity before and after. At `0x100609d4` (`SHA1_Final`): capture output buffer contents (20 bytes), BIGNUM length field (should be 20). At `0x100609e9` (`SHA1_Update`): capture data pointer, length (should be 20), raw bytes. Verify: are all 20 bytes present? Are leading zeros preserved?
Distinguishing representations:
| Observation | Interpretation |
|-------------|----------------|
| 20 bytes, no leading zeros | Raw digest (Rust-compatible) |
| <20 bytes (leading zeros stripped) | BIGNUM integer serialization |
| 20 bytes, leading zeros present | Raw digest (leading zeros preserved) |
| Variable length | BIGNUM with stripping |

Capture will definitively determine which representation is used.

#### 6.2.3 RSA Constructor Capture Plan

Target: Module `shelper.dll`; Function `0x1006b4e0` (CreateWithPublicKey); Also check `0x1006b3e0` (CreateWithPrivateKey).
Arguments to capture (public key):
| Stack offset | Argument | Capture |
|--------------|----------|---------|
| `[ebp+8]` | `n_ptr` | Dereference, dump bytes |
| `[ebp+12]` | `n_len` | Value (should be 256) |
| `[ebp+16]` | `e_ptr` | Dereference, dump bytes |
| `[ebp+20]` | `e_len` | Value (should be 3 for 0x010001) |

Arguments to capture (private key): all 16 arguments (8 ptr+len pairs). Record each pointer and dereference to dump bytes.
Caller information: capture full call stack. Record caller module and function, module-relative return address, thread ID.
Component source tracing: from captured pointers, determine if buffers are in `.rdata` (static/embedded), on heap (allocated at runtime), in file mapping (loaded from disk), or in network buffers (received). This identifies key provenance.

#### 6.2.4 RSA Call-Site Narrowing Strategy

Problem: 4705 calls to IAT slot `0x10175158` in `RvROLClient.dll`; RSA constructor call site hidden among them.
Narrowing strategy: (1) cross-reference search — find all code loading `SHelper_RSAHelper_CreateWithPublicKey` via `GetProcAddress`; string name at known address in `.rdata`; (2) function pointer storage — find where resolved pointer is stored (object field, global variable, or stack slot); (3) indirect call sites — find `call *reg` or `call *[mem]` instructions using stored pointer; (4) argument preparation — for each candidate call site, check if preceding code sets up 4 arguments (n_ptr, n_len, e_ptr, e_len); (5) runtime confirmation — if static narrowing fails, set breakpoint on function itself (`0x1006b4e0`) and capture the one that hits.
Runtime observation fallback: breakpoint on `shelper.dll!0x1006b4e0` entry. When it hits: capture call stack (return address → caller function); capture all 4 arguments. This definitively identifies caller.

#### 6.2.5 One-Session Execution Sequence

Preparation: (1) start Windows VM (`win10`); (2) install Radmin VPN client; (3) attach debugger (x64dbg/WinDbg) to `RvControlSvc.exe` or `RvROLClient.dll` host process; (4) set breakpoints: `bp shelper.10060340` (password), `bp shelper.100609a0` (M2), `bp shelper.1006b4e0` (RSA public key), `bp shelper.1006b3e0` (RSA private key).
SRP handshake (password + M2): (1) configure client with test credentials — Username `"A"` (identity), Password `"p"` (test password T1); (2) initiate connection to test server; (3) breakpoint hits at `0x10060340`: capture password ptr, len, bytes; capture identity ptr, len, bytes; capture call stack; (4) continue to M2 breakpoint at `0x100609a0`: dump all 4 SHA-1 contexts (0x180 bytes); capture BIGNUM buffer; capture each SHA-1 update input.
RSA handshake (RSession): (1) with SRP complete, RSession key exchange begins; (2) breakpoint hits at `0x1006b4e0`: capture n_ptr, n_len, e_ptr, e_len; dereference and dump key bytes; capture call stack; (3) breakpoint hits at `0x1006b3e0` (if server side): capture all 16 arguments; dump all component buffers.
Repeat with test credentials: repeat SRP handshake with Password `"päss"` (T2: non-ASCII) and Password `"😀"` (T3: non-BMP). Confirms encoding across multiple test cases.

#### 6.2.6 Capture Data Schema

Evidence organized as:
```
phase-10.20/
├── environment.md              # VM specs, binary hashes, debugger version
├── breakpoint-plan.md          # Breakpoint addresses and conditions
├── password-captures/
│   ├── PW-001.json            # T1: "p"
│   ├── PW-002.json            # T2: "päss"
│   └── PW-003.json            # T3: "😀"
├── m2-captures/
│   ├── M2-001.json            # SHA-1 context dumps
│   └── M2-002.json            # BIGNUM buffer capture
├── rsa-captures/
│   ├── RSA-001.json           # Public key components
│   └── RSA-002.json           # Private key components
├── call-stacks/
│   ├── CS-001.txt             # Password call stack
│   ├── CS-002.txt             # M2 call stack
│   └── CS-003.txt             # RSA call stack
├── raw-dumps/
│   └── (binary dumps)
└── capture-index.json          # Master index of all captures
```
See `docs/CRYPTO_PHASE_10_20_CAPTURE_SCHEMA.json` for the JSON schema.

#### 6.2.7 Expected Evidence

| Blocker | Evidence needed | Classification after capture |
|---------|-----------------|------------------------------|
| Password encoding | Password bytes + length at 0x10060340 | CONFIRMED (if matches one encoding) |
| M2 BIGNUM step | SHA-1 context + BIGNUM buffer | CONFIRMED (if bytes match one representation) |
| RSA key source | Component buffers + call stack | STRONGLY_SUPPORTED or CONFIRMED |

#### 6.2.8 Failure Conditions

| Failure | Cause | Mitigation |
|---------|-------|------------|
| Breakpoint not hit | Wrong function address (ASLR) | Use module-relative offset: `shelper.10060340` |
| VM cannot run Radmin | Missing dependencies | Use portable Radmin build or installer |
| Debugger cannot attach | Process protection | Use admin privileges or early attach |
| Password buffer zeroized | Function clears after use | Capture at entry, before `SHA1_Update` |
| BIGNUM buffer reallocated | Resize changes pointer | Capture after `0x1005f620` returns |

#### 6.2.9 Remaining Uncertainties

Even after dynamic analysis: whether password is cached or re-derived (lifecycle); whether RSA keys rotate (long-term behavior); whether M2 accumulator is reused across sessions. These are P2 and do not block interoperability.

#### 6.2.10 Exact Prerequisites for Phase 10.21

Infrastructure: Windows 10 VM (KVM/virt-manager or equivalent); Radmin VPN client installed and functional; test Radmin server (or loopback server); debugger attached (x64dbg or WinDbg); test accounts configured.
Breakpoints: `shelper.dll!0x10060340` (password); `shelper.dll!0x10060c80` (password server); `shelper.dll!0x100609a0` (M2); `shelper.dll!0x1006b4e0` (RSA public key); `shelper.dll!0x1006b3e0` (RSA private key).
Test data: Username: `"A"`, `"José"`, `"😀`; Passwords: `"p"`, `"päss"`, `"😀`; capture directory structure ready.
Authorization: user authorizes VM start; user authorizes debugger attachment; user authorizes live Radmin session.

#### 6.2.11 Integrity Confirmation (Phase 10.20)

- No Rust source code was modified during Phase 10.20.
- No historical documentation was overwritten.
- No binaries or PCAPs were modified.
- No commits, pushes, branches, or pull requests were created.
- HEAD remains at `95e304e0855a6faf4eece932484cb00e36620a6e`.
- No dynamic execution was performed.
- Deliverables created: `docs/CRYPTO_PHASE_10_20_DYNAMIC_ANALYSIS_READINESS.md` (this file); `docs/CRYPTO_PHASE_10_20_CAPTURE_SCHEMA.json`.

### 6.3 Phase 2.5 Stage 12 — Object Lifecycle vs Rust

Phase 2.5 Stage 13 (reassessment) corrected object lifecycle findings and mapped them to Rust equivalents (verbatim):

| Windows Behavior (Corrected) | Rust Equivalent | Viability | Rationale |
|------------------------------|-----------------|-----------|-----------|
| Refcount at obj+0x20; `FUN_004731E0` reads atomically; if != 0, calls `FUN_00473210` | `Arc<T>` + custom `Drop` | PARTIAL | `Arc::clone()` = increment (AddRef not found in Windows); `drop` = Release-like behavior |
| `FUN_00473210`: sets refcount to 0, exchanges obj+0x24, deletes critical section at obj+8 | `impl Drop` with cleanup | PARTIAL | Windows destroy is not standard decrement-to-zero; Rust `Drop` runs once when `Arc` count reaches 0 |
| AddRef not found | `Arc::clone()` | N/A | Windows AddRef absent; Rust `Arc::clone()` would add behavior not present in Windows |
| obj+0x24 exchanged atomically | `AtomicU32` or `AtomicBool` | PARTIAL | Could be a destroyed flag or generation counter |
| obj+8 critical section deleted in `FUN_00473210` | `Mutex<T>` drop | PARTIAL | Windows destroys critical section explicitly; Rust `Mutex` drops automatically |
| field_0x28 compared to 5; field_0x2C compared to 0 | `enum` state machine | VIABLE | Rust enum replaces numeric comparisons |
| field_0x30 call counter | `AtomicU64` or `u64` | VIABLE | Simple counter |
| field_0x20, 0x28, 0x2C NOT initialized by constructor | `Option<T>` or `default()` | VIABLE | Rust `Default::default()` zero-initializes; matches zero-init heap allocation hypothesis |

What Windows does that Rust should NOT replicate: destroy-on-read-nonzero (`FUN_004731E0` → `FUN_00473210`); set refcount to 0 (not decrement); atomic exchange of obj+0x24 flag; `DeleteCriticalSection` explicitly; manual vptr transitions (3× during construction); adjustment thunks (`SUB ECX, offset`).

Rust Rust already has (object-lifecycle relevance): `session` — `src/session/mod.rs` (`SessionState` enum 8 states, `SessionManager` with connect/handshake/disconnect/close); `src/session/control.rs` (`ControlConnectionState` enum, `ControlConnection` with SRP-6a handshake); `src/session/control_handshake.rs` (SRP-6a negotiator with state machine); `src/session/handshake.rs` (RSA handshake negotiator); `daemon` — `src/daemon/mod.rs` (`DaemonContext` with `Arc<DaemonContext>`, `Daemon` with start/stop); `src/daemon/ipc.rs` (Unix domain socket IPC server); `protocol` — `src/protocol/tlv.rs` (TLV message serialization with validation).

Gaps between Windows and Rust: reference counting manual (obj+0x20, atomic) vs `Arc<T>` (partial — daemon uses Arc) — partial, Rust `Arc` not yet used for object lifecycle; object destruction `FUN_00473210` (destroy/reset) vs `Drop` trait — different semantics (Windows is destroy-on-read-nonzero); object construction multi-phase, unreachable vs `fn new()` — different pattern; state machine u32 fields (0x28, 0x2C) vs `enum SessionState` — implemented in `session/mod.rs`; object fields not initialized by constructor vs `Default::default()` — Rust zero-initializes; matches heap hypothesis; IPC named pipe (Windows) vs Unix domain socket (Linux) — different mechanism; real Radmin networking YES vs NO — major gap, Rust daemon is mock/stub.

Phase 2.5 conclusion: Rust should NOT mirror Windows object lifecycle details (no C++ vtable transitions, no adjustment thunks, no manual heap management, no Windows-specific synchronization, no destroy-on-read-nonzero pattern). Instead use `Arc<T>` for shared ownership, `Drop` for cleanup, `enum` for state machines, `AtomicBool`/`AtomicU32` for synchronized flags, `Default::default()` for zero-initialization. No Rust source files modified.

---

## Sources

All 12 sources mapped to `RUST_COMPATIBILITY` in `analysis_workspace/compaction/mapping.tsv`, read in full:

1. `docs/CRYPTO_PHASE_10_13_DYNAMIC_ANALYSIS_PLAN.md` — Phase 10.13 dynamic analysis plan (password encoding OQ-2, identity hash OQ-3, AES mapping OQ-1; breakpoints `shelper.10060340`, `0x10060361`, `RvROLClient.dll 0x100df250`, `shelper.1006a630`; test credentials `70`/`70 00`/`00 70`/`70 00 00 00`/`41 00`/`00 41`).
2. `docs/CRYPTO_PHASE_10_20_DYNAMIC_ANALYSIS_READINESS.md` — Phase 10.20 readiness & instrumentation plan (workstreams A/B/C; breakpoints `10060340`, `100609a0`, `1006b4e0`, `1006b3e0`; SHA-1 contexts; RSA constructor args; one-session execution sequence; capture schema; failure conditions; Phase 10.21 prerequisites; HEAD `95e304e0855a6faf4eece932484cb00e36620a6e`).
3. `docs/CRYPTO_PHASE_10_5_COMPATIBILITY_AUDIT.md` — Task 5.4 adversarial cross-validation (17-field mismatch table; contradictions on `k`, `u`, endianness; CONFIRMED_MISMATCH on `k`/identity/AES split; DISPROVEN asymmetric `u`; inferred/unknown findings U1-U15; false positives FP1-FP8; blockers B1-B8; prioritized investigations 1-11; binary SHA-256 hashes; Rust files reviewed).
4. `docs/CRYPTO_PHASE_10_5_REMEDIATION.md` — Phase 10.5 remediation report (replace `RADMIN_SRP_K=3` with `srp_k()`; identity encoding via `encode_identity()`; AES key split NOT applied; lines 16/19-30/275/861-863/1283-1285/1580 in `control_handshake.rs`; binary SHA-256; shelper.dll function addresses `0x10041010`/`0x10041e70`/`0x100418b0`/`0x10041c00`/`0x10041c40`/`0x10041c80`/`0x10041cc0`; compliance status; files modified).
5. `docs/CRYPTO_PHASE_10_5_VALIDATION.md` — Phase 10.5 validation report (`cargo build`/`cargo test` 147+5 passing/`cargo fmt --check`; fix verification code before/after; remaining differences; limitations and next steps).
6. `docs/CRYPTO_RUST_GAP_ANALYSIS.md` — Rust implementation gap analysis (38-row discrepancy matrix with verdicts; detailed critical mismatch analysis §3.1-3.6; components not implemented / not in binary; test coverage; recommended fixes priority 1-6; evidence sources).
7. `docs/PCAP_IMPLEMENTATION_READINESS.md` — PCAP implementation readiness (12-item readiness matrix; per-item PCAP evidence; priority recommendations; next experiments).
8. `docs/PHASE_2_3/12_RUST_COMPATIBILITY_ASSESSMENT.md` — Phase 2.3 Stage 12 Rust compatibility assessment (ABI separation P2.2-*; mapping table; do-not-implement list; architectural difference table; AGENTS.md compliance).
9. `docs/PHASE_2_3/23_EXTENDED_RUST_COMPATIBILITY.md` — Phase 2.3 Stage 23 extended Rust compatibility mapping (Windows→Rust mapping table; object lifecycle mapping reference counting/list cleanup/destruction chain/registry/ETW/critical section; FAM RT class hierarchy mapping; do-not-implement and could-implement tables).
10. `docs/PHASE_2_4/13_RUST_COMPATIBILITY_REASSESSMENT.md` — Phase 2.4 Stage 13 Rust compatibility reassessment (source inspection of `src/daemon/mod.rs`, `src/daemon/ipc.rs`, `src/session/mod.rs`, `src/session/control.rs`/`control_handshake.rs`/`handshake.rs`, `src/protocol/tlv.rs`; Windows→Rust viability table; do-not-implement list; could-implement table).
11. `docs/PHASE_2_5/13_RUST_COMPATIBILITY_REASSESSMENT.md` — Phase 2.5 Stage 13 Rust compatibility reassessment (corrected object lifecycle vs Rust mappings; what Rust should not replicate; what Rust already has; gaps table; conclusion).
12. `docs/reverse-engineering/round-02/IMPLEMENTATION_READINESS.md` — Round 02 readiness matrix (TCP framing/RSA/AES/TLV/SHA-1/TAP/STUN/relay/IPC/Teredo; trailer encoding rules; handshake state machine; TAP layer steps; automated test plan with extracted vectors).

---

## Provenance note

This consolidated document was produced by reading all 12 `RUST_COMPATIBILITY`-mapped sources exactly once and merging them into a single evidence-preserving file. Gap, remediation, and validation reports were deduplicated (the Phase 10.5 compliance/audit tables overlap the gap-analysis matrix; both are represented with attribution where verdicts diverge). Every Rust file path and line number, every mismatch verdict (`CONFIRMED_MISMATCH`, `PARTIAL_MATCH`, `NOT_IMPLEMENTED`, `READY`, `UNVERIFIED`, `UNKNOWN`), every binary address used as evidence, every breakpoint address (`shelper.10060340`, `100609a0`, `1006b4e0`, `1006b3e0`, and related addresses such as `0x10060c80`, `0x10060361`, `0x100609c3`, `0x100609d4`, `0x100609e9`, `0x1006b4e0`, `0x1006b3e0`), and every test-credential byte sequence (`70`, `70 00`, `00 70`, `70 00 00 00`, `41 00`, `00 41`, T1/T2/T3 sequences for `p`/`päss`/`😀`) is preserved verbatim. Nothing was invented; where sources contradict, both ratings are retained with the originating document named. No Rust source, binary, PCAP, or other repository artifact was modified, and no other file was created or written as part of this task.

---

## Evidence appendix (exact tokens from consolidated sources)

Exact addresses, hashes and identifiers from the consolidated sources that are not repeated in the prose above. They are preserved here so that no evidence anchor is lost during compaction; the full narrative for each source remains available in git history.

- `docs/CRYPTO_PHASE_10_5_COMPATIBILITY_AUDIT.md`: `0x10063530`, `0x10094218`, `7b12a483fe77c3ed56e5a4dd8e7acc4fe7ec1233`, `fun_1005fad0`, `fun_10060510`, `fun_10060fa0`, `fun_10069c20`
- `docs/PHASE_2_3/23_EXTENDED_RUST_COMPATIBILITY.md`: `fun_00403700`, `fun_004038a0`, `fun_0043a9a0`, `fun_0043b420`, `fun_0043b470`, `fun_0043b4c0`, `fun_00440670`, `fun_00451900`, `fun_0046ae70`, `fun_0046b9f0`, `fun_00475870`, `fun_00475c00`, `fun_004802f0`, `fun_004ec736`
