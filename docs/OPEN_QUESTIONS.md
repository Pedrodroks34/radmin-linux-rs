# Open Questions — Consolidated (OPEN_QUESTIONS)

Consolidation of every blocker/question ID from the 10 sources mapped to
`OPEN_QUESTIONS` in `analysis_workspace/compaction/mapping.tsv`. Every ID,
exact binary address, Rust location, status, and "why it matters" entry is
preserved. Repeated blocker lists across phases are deduplicated (see
Provenance note).

---

## Provenance note

This document was produced by consolidating the 10 sources whose first column
in `analysis_workspace/compaction/mapping.tsv` is `OPEN_QUESTIONS`. No facts
were invented; every item below quotes or paraphrases its source file. Where
two or more sources document the same underlying gap (for example, Phase 2.4
B1–B4 and Phase 2.5 B1–B4 both cover object allocation, vptr state, and
indirect-call targets), the later phase's entry is treated as authoritative
and the earlier duplicate is cross-referenced rather than repeated verbatim.
Statuses (`UNKNOWN`, `UNRESOLVED`, `BLOCKED`, `CONFIRMED_MISMATCH`, etc.)
are preserved exactly as written in the source. Password encoding and RSA key
provenance are deliberately kept `UNKNOWN` throughout, per task requirement.

## 1. Crypto / Protocol Blockers

Source materials: `docs/CRYPTO_UNRESOLVED_QUESTIONS.md` (Investigations A–G,
with consolidated priority list),
`docs/CRYPTO_PHASE_10_3_10_5_OPEN_QUESTIONS.md` (OQ-1..OQ-8),
`docs/CRYPTO_PHASE_10_12_BLOCKER_RESOLUTION.md` (Workstreams A–F, remaining
unknowns, dynamic experiments),
`docs/reverse-engineering/round-02/UNRESOLVED_QUESTIONS.md` (Questions 1–3).

### 1.1 Investigation A — MD5 Implementation and Digest Folding

| ID | Question | Why it matters | Where to investigate (addresses) | Status |
|----|----------|----------------|----------------------------------|--------|
| A-1 | Does the recovered MD5 implementation produce byte-identical output to RFC 1321 / OpenSSL test vectors on arbitrary inputs (empty input, 55/56/64-byte boundaries, multi-block)? | All MD5-related conclusions rest on structural/constant identity (IV `0x67452301`, 92-byte context, `0x80` padding, LE assembly, LE output, RFC round constants). No execution means no 100% proof of correctness for edge cases. | `shelper.dll` `0x100638f0` (MD5 wrapper), `0x10004780` (compression), `0x10004e50` (update), `0x10004f30` (final). Method: emulate/instrument `shelper.dll` with controlled inputs and compare against a known-good MD5. | UNKNOWN (blocked — dynamic execution not possible) |
| A-2 | Which function(s) in `RvROLClient.dll` call `SHelper_CChannel_EncryptBuffer` (`0x1006aa10`) and `SHelper_CChannel_DecryptBuffer` (`0x1006a930`)? | The trailer (folded MD5 + `0xCC` padding) is applied inside `shelper.dll`, but the call sites determine which protocol layer uses it (control channel vs RSession vs data channel) and whether any post-trailer transformation occurs. | `RvROLClient.dll` API table at `api+0xc8` / `api+0xcc` (set via `GetProcAddress` at `0x1003fd5c–0x1003fd86`); indirect calls `call [reg+0xc8]` / `call [reg+0xcc]`. | UNKNOWN (indirect calls through cached table; `+0xc8/+0xcc` collide with unrelated struct fields) |
| A-3 | Does `FUN_10062d60` (AES-CBC decrypt, `vtable+8`) reject, truncate, or over-read when input length is not a multiple of 16? | `FUN_10069d70` calls the decrypt slot **before** `0x10069f90` validates `len % block == 0`. If the decrypt routine does not reject non-block-aligned input, a malformed packet could cause an out-of-bounds read or silent decryption of garbage. | `shelper.dll` `0x10069d70` → `0x10062d60`; `0x10069f90` validation gate at `0x10069fe5–0x1006a010`. | UNKNOWN (worth follow-up — possible robustness/DoS surface) |
| A-4 | Is the folded MD5 trailer intended as (a) corruption/format detection for a legacy transport, (b) a weak anti-tamper measure, or (c) something else? | Classification affects how the Rust implementation should be evaluated. If it is merely format detection, the lack of a keyed MAC is not a "bug" relative to the original — it is intentional design. | No strings, logs, or caller-level evidence found in `shelper.dll` or `RvROLClient.dll`. May require analysis of `RvControlSvc.exe` or original documentation. | HYPOTHESIS ("corruption/format detection" inferred from construction; no direct evidence) |
| A-5 | Why two MD5 implementations exist — which product paths use `md5_block_asm_data_order` at `0x10009580` vs the C build at `0x10004780`? | The trailer path uses `0x10004780` exclusively. If another code path uses `0x10009580` with different behavior (different padding or output), any component sharing that path would produce different digests. | `shelper.dll` `0x10005050` / `0x10005130` (wrapper pair reaching `0x10009580`); xrefs from those functions. | UNKNOWN (not required for Investigation A) |

#### A — SRP Control Key Derivation (key-lifecycle sub-items from Investigation A)

| ID | Question | Impact | Where | Status |
|----|----------|--------|-------|--------|
| A-i | Exact operands of `0x10060810`: is `[obj+0xc]` N and `[obj+0x10]` the padded-g buffer, or vice versa? | Blocks byte-exact `k` formula statement. | `shelper.dll` `0x10060810` full disassembly. | UNVERIFIED |
| A-ii | Slot `+0x1c` role: combined S method (k computed inline) or standalone `k` accessor? | Affects understanding of key derivation architecture. | Review `0x10060810` caller chain. | UNVERIFIED |
| A-iii | `0x10060510` (S/u core): does it implement `S = (B − k·g^x)^(a + u·x) mod N`? Where is S stored? | Shared secret computation unverified. | `objdump -d --start-address=0x10060510 --stop-address=0x100606a0 shelper.dll`. | NOT DISASSEMBLED (budget expired) |
| A-iv | `0x10061790` (KDF): KDF = `H(S ‖ BE32(i))`, 40 bytes? Domain/order of A‖B in u? | KDF correctness unverified. | `objdump -d --start-address=0x10061790 --stop-address=0x10061860 shelper.dll`. | NOT DISASSEMBLED |
| A-v | `0x100609a0` (M2 generation) and server `0x10060fa0`/`0x100612f0`/`0x10061450`: server M1 verify/M2 generation paths not traced. | Server-side proof verification unverified. | `objdump -d` ranges at those addresses. | NOT DISASSEMBLED |

### 1.2 Investigation B — SRP-6a Control Authentication

| ID | Question | Why it matters | Where to investigate (addresses) | Status |
|----|----------|----------------|----------------------------------|--------|
| B-1 | Which SRP class is instantiated (`k = H(N‖PAD(g))` vs `k = 3`)? | Rust hardcodes `RADMIN_SRP_K = 3`. If the binary uses the SRP-6a class, this is a **CONFIRMED_MISMATCH** and the shared secret `S` will differ — complete handshake failure. | Cross-reference `"SRP-6a client (tjw)"` string at `0x100a3df0` (ptr `0x100ad75c → vtable 0x100ad760`) and `"SRP-6a server (tjw)"` at `0x100a3e18` (ptr `0x100ad7b4 → vtable 0x100ad7b8`) from the session constructor in `RvROLClient.dll`. | UNVERIFIED — highest-priority blocker for SRP interoperability |
| B-2 | Does `obj+0x30` ever contain non-empty data, and if so, what is it? `FUN_10060510`/`FUN_10060fa0` append this buffer to the M1 hash when `len > 0`. | If non-empty, Rust's M1 computation (`compute_srp_m1` L402-430) which does not include this block will produce a different M1 — handshake failure. | `shelper.dll` `0x10060510` (client), `0x10060fa0` (server); writer of `obj+0x30`. | UNKNOWN |
| B-3 | Does the binary hash `A` and `B` in raw minimal `BN_bn2bin` form or padded 192-byte form inside M1? `u` uses padded forms (CONFIRMED), but M1 hashes A/B as caller-supplied bytes. | Rust's `compute_srp_m1` hashes `a_bytes`/`b_bytes` as passed. A leading-zero byte in A or B would change M1 if padding differs. | Call sites of M1 computation in `shelper.dll` (`0x10060410` appends A, `0x10060510` appends B); Rust call sites in `control_handshake.rs` (`compute_srp_m1` callers at L1267, 1399, 1456). | PARTIAL — binary hashes minimal form; Rust call-site padding unverified |
| B-4 | Is the password hashed as UTF-16LE wide characters (inferred from the identity source) or UTF-8? `x = H(salt ‖ H(I ‖ ":" ‖ P))`. | Rust's `compute_srp_x` hashes `password.as_bytes()` = UTF-8 (L276). If the binary uses UTF-16LE, `x` differs — cascading to `v`, `A`, `S`, `K`, `M1`, `M2` — complete handshake failure. | `shelper.dll` `0x10060c80` (server x computation); caller-supplied password byte string. | CONFIRMED_MISMATCH if password is UTF-16LE (inferred, not directly traced) |
| B-5 | Is the version value `3` sent as big-endian (`00 00 00 03`) or little-endian (`03 00 00 00`)? Rust writes `to_le_bytes()` at L588. | PCAP captures start after version exchange, so the wire encoding was never observed. If wrong, the version exchange fails before SRP begins. | PCAP capture including the 8-byte version frame `00 00 00 04 03 00 00 00`, or live server testing. | PARTIAL_MATCH — value matches, endianness unverified |
| B-6 | Does `FUN_100612f0` finalize canonical M2 into `ctx+0x6a` or `ctx+0x1A8`? The decompiler output shows `ctx+0x6a` on the canonical path, while `0x10061450` reads `ctx+0x1A8`. | If the slot is wrong, the server's M2 comparison reads the wrong digest — either false accept or false reject. | `shelper.dll` `0x10061000–0x100612F0` (server M2 finalization), `0x10061450` (comparison read). | UNRESOLVED (re-disassemble required) |
| B-7 | What is the exact entry point and jump-table layout of the client state dispatcher? Earlier trace identified `0x10066fdc` but Ghidra resolves `0x100665b0–0x100667a7` to logging helper and `0x10066680` is not a function entry. | State numbers (`{0,2,4,6}` for client) and transitions depend on the correct dispatcher entry. | `shelper.dll` `0x10066fdc` region; client vtable `0x100ad760`. | UNKNOWN (earlier trace unreliable) |
| B-8 | Does the lack of rejection sampling in the binary (`rand192 + 1536`, no range check) cause any interoperability difference? | Rust rejects exponents outside `(1, N−1)` for up to 128 tries. Only `A = g^a mod N` is transmitted, so an out-of-range `a` still produces a valid `A`. No interoperability impact expected, but not proven. | `shelper.dll` `0x10060410` / `0x10060d80` vs Rust `random_srp_exponent` L298-324. | UNVERIFIED (behavioral divergence, no interop impact expected) |

### 1.3 Investigation C — RSession Key Establishment

| ID | Question | Why it matters | Where to investigate (addresses) | Status |
|----|----------|----------------|----------------------------------|--------|
| C-1 | Does the consumer split the 64-byte RSession secret as `key_enc = secret[0..32]`, `key_dec = secret[32..64]`, or does it derive two keys via a hash/KDF? | Rust's `derive_aes256_key_ref` takes `key_material[..32]` for both enc and dec (same key for both directions). If the binary uses different keys for enc/dec, traffic encrypted with one direction's key cannot be decrypted with the other — complete failure in one direction. | `RvControlSvc.exe` `GetProcAddress` resolver + call sites of `RSession_GetKey` (`0x1006ba80`), `SetKeyEnc` (`0x1006ab00`), `SetKeyDec` (`0x1006aac0`). No indirect call sites found in `RvROLClient.dll`. | HYPOTHESIS / UNVERIFIED — highest-priority blocker for RSession interoperability |
| C-2 | What does the client's 4-byte ACK value mean? The server stores `+0x14 = LE32(blob)` but never interprets it beyond length validation. | If the ACK is a server-chosen cookie that the client must echo correctly, Rust must generate it properly. If it is an echo of `+0x04`, the client must track and return the server's value. | `shelper.dll` client state-2 branch (`0x1006a5eb` → state 2 → 3), server state-2 branch. | UNKNOWN |
| C-3 | Which component supplies the 8 component buffers (`n`, `e`, `d`, `p`, `q`, `dmp1`, `dmq1`, `iqmp`) to `RSession_CreateServer`? Are they embedded in `RvROLClient.dll` or loaded at runtime? | Without the server's actual RSA private key, Rust cannot implement the server side of RSession key establishment. | `RvROLClient.dll` / `RvControlSvc.exe` callers of `SHelper_RSession_CreateServer` (`0x1006b8f0`); embedded key data in `.rdata`. | UNKNOWN |
| C-4 | What do the 12-byte header fields and decrypted header fields (`+0x04..+0x0c`, `+0x14..+0x1c`) represent semantically? They are treated as opaque dwords in `shelper.dll`. | If these fields encode protocol version, flags, or session identifiers, Rust must set them correctly. | `shelper.dll` `FUN_1006a690` (client init copies 12-byte header), `FUN_1006a2b0` server store path. | UNKNOWN |
| C-5 | Is the TwoFishV2-shaped vftable at `0x100832c4` dead code, or is it instantiated somewhere not yet found? | If instantiated, the cipher might be TwoFish, not AES-256, in some code path — contradicting the AES-256-CBC conclusion. | `shelper.dll` `.rdata` `0x100832c4`; xrefs to this vftable. | UNKNOWN (likely dead code, no instantiation found) |
| C-6 | Does the peer ever rekey or reset IVs per frame? No key rotation observed within a session. | If IVs are truly persistent and never reset, long sessions accumulate more ciphertext under the same IV chain. Dropped/reordered frames break decryption until rekeying — no recovery mechanism observed. | `shelper.dll` AESCryptor object lifecycle; `RvROLClient.dll`/`RvControlSvc.exe` session teardown/rekey logic. | UNKNOWN |

### 1.4 Investigation D — RSA Operations

| ID | Question | Why it matters | Where to investigate (addresses) | Status |
|----|----------|----------------|----------------------------------|--------|
| D-1 | Server RSA key provenance (duplicate of C-3). | See C-3. Same question, same impact, same location. | `RvROLClient.dll` / `RvControlSvc.exe` callers of `SHelper_RSession_CreateServer` (`0x1006b8f0`); embedded key data in `.rdata`. | UNKNOWN |
| D-2 | Does the server ever rotate its RSA key pair during operation? | If keys rotate, Rust must handle key rollover and backward compatibility with old ciphertexts. | `RvROLClient.dll` / `RvControlSvc.exe` key reload logic after `SHelper_RSession_CreateServer`. | UNKNOWN |
| D-3 | Does OpenSSL 1.0.1f's `RSA_free` in this build zeroize key material before freeing? | Affects memory-forensics security assessment, not interoperability. Do not claim secure wiping in the spec without verification. | OpenSSL 1.0.1f source / binary `RSA_free` behavior. | STRONG INDICATION (upstream behavior), unverified in this binary |
| D-4 | What is the 5th stack argument of `DecryptBuffer_Private` (`ret $0x14`)? The core takes 3 args; extra out/flag parameter meaning not recovered. | Do not reimplement that export from its name alone — incorrect assumptions could introduce behavioral divergence. | `shelper.dll` `DecryptBuffer_Private` disassembly. | UNKNOWN |

### 1.5 Investigation E — Symmetric Encryption

| ID | Question | Why it matters | Where to investigate (addresses) | Status |
|----|----------|----------------|----------------------------------|--------|
| E-1 | Is the IV ever reset between frames, or is it truly persistent for the entire session? | Rust implements persistent IVs matching the binary. If the binary resets IVs periodically (e.g., after N frames), Rust would diverge. | `shelper.dll` AESCryptor object `+0x1ec`/`+0x1fc` lifecycle; any `memset` or re-init of IV buffers. | CONFIRMED persistent (no reset observed), but not exhaustively traced across session boundaries |
| E-2 | Key rotation (see C-6 / D-2). No key rotation observed. | N/A | `shelper.dll` AESCryptor object lifecycle; session teardown/rekey logic. | UNKNOWN (not observed → assume none) |
| E-3 | Is the all-zero initial IV an intentional design choice or an oversight? | Makes the first block equivalent to ECB encryption. Minor weakness but not an interop blocker — Rust matches this behavior. | `shelper.dll` AESCryptor constructor (`FUN_10062b60`); initial IV initialization. | CONFIRMED (zero IV at init), intent UNKNOWN |

### 1.6 Investigation G — Rust Implementation Gap Analysis

| ID | Question / Finding | Rust location | Binary address(es) | Status | Why it matters / impact |
|----|-------------------|---------------|--------------------|--------|-------------------------|
| G-1 | Step value endianness: Rust `1u32.to_le_bytes()` → `01 00 00 00`; binary uses 4-byte big-endian `00 00 00 01`. | `control_handshake.rs` L670, 780, 910, 1267, 1399, 1456 | `0x100626e0` | CONFIRMED_MISMATCH — fix required | Complete handshake failure — server rejects step 1 immediately. Fix: change all step `to_le_bytes()` to `to_be_bytes()`. |
| G-2 | Identity/password encoding in `x`: Rust `username.as_bytes()`/`password.as_bytes()` = UTF-8 at `compute_srp_x` L274-277; binary uses UTF-16LE wide chars. | `control_handshake.rs` L269-286 | `0x10060340`, `0x10060c80` | CONFIRMED_MISMATCH — fix required | `x` differs → `v`, `A`, `S`, `K`, `M1`, `M2` all differ → complete handshake failure even with step endianness fixed. Fix: hash UTF-16LE byte sequences. |
| G-3 | Multiplier `k`: Rust `RADMIN_SRP_K = 3`; binary SRP-6a class uses `k = SHA1(N_bytes ‖ PAD(g, 192))`; legacy class uses `k = 3`. | `control_handshake.rs` L16 | `0x10060810`, `0x100ad760`, `0x100ad7b8` | UNVERIFIED — potential CONFIRMED_MISMATCH | If SRP-6a class is deployed, `S` differs → complete handshake failure. Fix: determine deployed class (B-1); if SRP-6a, compute `k` at runtime. |
| G-4 | Exact-192 length check: Rust `bytes.len() == 192` strict; binary `len ≤ 192` with `val < N`, `val != 0`. | `control_handshake.rs` L330-337 | `0x100699e0` | PARTIAL_MATCH | Valid official peer with leading-zero-byte public value (~1/256 probability) rejected by Rust. Fix: accept `len ≤ 192`, left-pad to 192 bytes. |
| G-5 | Version endianness: Rust `to_le_bytes()` → `03 00 00 00` at L588; binary value `3` confirmed, wire endianness unknown. | `control_handshake.rs` L588 | `0x1006b1d0` | PARTIAL_MATCH | Version exchange failure if wrong endianness. Fix: determine wire encoding from PCAP with version exchange or live test. |
| G-6 | Public value padding in M1: Rust hashes `a_bytes`/`b_bytes` as passed by caller; binary hashes raw minimal `BN_bn2bin` form. | `control_handshake.rs` `compute_srp_m1` callers | `0x10060410`, `0x10060510` | PARTIAL_MATCH | If Rust caller passes padded values, M1 differs. Fix: verify call sites pass minimal-form (unpadded) public values. |
| G-7 | No control-channel message integration: binary has TLV-structured control messages (Login, LoginResponse, JoinNetwork, etc.) after SRP-6a handshake; Rust `src/protocol/control.rs` defines message types but no integration with encrypted control channel. | `src/protocol/control.rs` | N/A | NOT_IMPLEMENTED | Control channel cannot carry application messages. Fix: implement control message send/receive over the AES-256-CBC channel. |
| G-8 | No RSession-transport integration: binary has `RSessionServer` server-side RSA decryption + token emission; Rust `RSessionServer` exists in `src/session/handshake.rs` but integration with transport layer not verified. | `src/session/handshake.rs` `RSessionServer` | `0x1006b8f0`, `0x1006b860` | PARTIAL | RSession key establishment not wired to actual network transport. Fix: wire `RSessionServer`/`ControlClientNegotiator` to `TcpChannel`. |
| G-9 | Tests validate internal consistency only (UNVERIFIED for interop): Rust tests use `Rsa::generate(2048)` — generated key, not the original binary's key. No test against captured PCAP traffic or `RvROLClient.dll`'s actual RSA public key. | `src/session/*` test modules | `RvROLClient.dll` RSA public key | UNVERIFIED | No evidence of interoperability with the original implementation. Fix: add test using the original binary's RSA public key and/or replay captured PCAP traffic. |

### 1.7 Phase 10.x Open Questions (OQ-1..OQ-8)

Source: `docs/CRYPTO_PHASE_10_3_10_5_OPEN_QUESTIONS.md` (consolidated OQ list) and
`docs/CRYPTO_PHASE_10_12_BLOCKER_RESOLUTION.md` (Workstreams A–F, remaining
unknowns, dynamic experiments).

| ID | Question | Priority | Why it matters | Existing evidence | Missing evidence / next step | Status |
|----|----------|----------|----------------|-------------------|------------------------------|--------|
| OQ-1 | AES split mapping: which half of the 64-byte RSession secret (`[0..32]` vs `[32..64]`) feeds AES encryption and which feeds decryption? | P0 | Rust `from_rsession_key()` uses `key_material[..32]` for both directions (`famatech.rs:181-186`). If the official consumer passes two different halves, one direction fails decryption. | `GetKey` (0x1006ba80) returns 64 bytes verbatim; `SetKeyPair` (0x1006a630) receives two pointers and validates both lengths == 0x20. | Consumer call site deriving the two pointers not located statically (disp8 indirect dispatch). Dynamic breakpoint on `0x1006a630`; compare pointer args with the GetKey buffer. | UNKNOWN |
| OQ-2 | Password encoding in `x`: is the password hashed as UTF-8, UTF-16LE, UTF-16BE, or ANSI? | P0 | `x`, `v`, `A`, `S`, `K`, `M1`, `M2` all depend on it. Rust uses UTF-8 (`password.as_bytes()`). | `shelper.dll` takes the password as caller-supplied raw `(ptr, len)` at `0x10060340`/`0x10060c80` with no transformation inside. | The caller conversion not traced; `RvROLClient.dll`/`RvControlSvc.exe` call sites not traced. Dynamic breakpoint on `0x10060340`; inspect password buffer for a known test string. | UNKNOWN |
| OQ-3 | Identity hash bytes LE vs BE: does the `x` hash consume the internal UTF-16LE buffer at `obj+0x8`, or the wire UTF-16BE form? | P0 | Rust `encode_identity()` emits UTF-16BE and feeds it to `compute_srp_x()`. If the binary hashes UTF-16LE, `x` differs even though the wire identity matches. | Wire byte-swap at `0x100667b0`; hash reads `obj+0x8` raw at `0x10060361`. LE-inference is MEDIUM confidence. | Byte-exact capture of the hashed identity buffer. Dynamic breakpoint on `0x10060340`; inspect identity buffer bytes for "A" (`41 00` = LE, `00 41` = BE). | UNKNOWN |
| OQ-4 | `context+0x20` runtime proof: is `context+0x20` definitively `A` on the client and `B` on the server at runtime? | P1 | The symmetric `u = SHA-1(A‖B)` conclusion rests on this. | `FUN_10060410`/`FUN_10060d80` write `context+0x20` after `mod_exp` (`0x1005f940`) calls — STRONGLY_SUPPORTED. | Runtime confirmation. Breakpoint after the `mod_exp` call; compare with `g^a` / `g^b`. | STRONGLY_SUPPORTED (static), runtime proof pending |
| OQ-5 | M1/M2 exact construction: what is the exact input order and component list for M1 and M2? | P1 | Rust uses single-shot hashes; the binary accumulates incrementally. | M1 accumulator at `context+0x38+0x60`; documented formulas `M1 = SHA-1(H(N)⊕H(g)‖H(I)‖salt‖A‖B‖K)`, `M2 = SHA-1(A‖M1‖K)`. | Full disassembly of `0x100612f0`/`0x100609a0` and their callers not performed. Disassemble the M1/M2 regions; intercept hash inputs dynamically. | PARTIALLY_CONFIRMED |
| OQ-6 | RSA key provenance: where do the server's RSA public key and private key come from? | P1 | RSession cannot be implemented without the official key material. | RSA-2048 PKCS#1 v1.5, exponent 65537, 76-byte plaintext. | Embedded blob (`.rdata` search negative so far), file load, network delivery, or runtime generation not found. Search resources and imports for key-loading APIs; trace `CreateClient`/`CreateServer` callers. | UNKNOWN |
| OQ-7 | SRP step-value endianness: are SRP step values (and other protocol integers) little- or big-endian on the wire? | P2 | Rust uses `to_le_bytes()` for step values; the version field is confirmed little-endian, but SRP step values have not been captured. | PCAP captures `03 00 00 00` version; no SRP exchange captured. | A PCAP containing the full SRP handshake. Capture an SRP handshake (requires a Windows session). | UNKNOWN |
| OQ-8 | Residual fields and dispatcher: what are `context+0x24`, `+0x2c`, `+0x30`, `+0x34`, and the `FUN_100092e0` jump table? | P2 | Low direct impact, but they may affect the M1/S computation paths. | Field map through `+0x28` (u); M1 accumulator `+0x38`. | Writes/reads to the remaining offsets not traced. Full object-field read/write sweep with Ghidra. | UNKNOWN |

#### Phase 10.12 remaining unknowns (from `docs/CRYPTO_PHASE_10_12_BLOCKER_RESOLUTION.md`)

| # | Unknown | Impact | Evidence needed |
|---|---------|--------|-----------------|
| 1 | AES split: which half → enc vs dec | **Critical** — one direction fails | Dynamic execution or call-site tracing |
| 2 | Password encoding (UTF-8 vs UTF-16LE) | **Critical** — `x`, `v`, `A`, `S`, `K` all differ | Caller tracing in consumer binary |
| 3 | Identity hash encoding (UTF-16LE vs UTF-16BE) | **Critical** — `x` differs | Compare known identity hash input |
| 4 | GetKey consumer call site | **High** — needed for #1 | Disp8 indirect call sweep or dynamic tracing |
| 5 | RSA key blobs (public/private) | **High** — RSession cannot be implemented | Search `.rdata` for key material |
| 6 | M1/M2 exact formulas | **Medium** — proof verification | Disassemble `0x100612f0`/`0x100609a0` |
| 7 | SRP step endianness | **Medium** — step validation | PCAP with full SRP handshake |
| 8 | `context+0x24/0x2c/0x30/0x34` semantics | **Low** — intermediate values | Full object field tracing |

### 1.8 Round-02 Open Questions

Source: `docs/reverse-engineering/round-02/UNRESOLVED_QUESTIONS.md`.

| ID | Priority | Question | Current situation / technical gap | Validation strategy |
|----|----------|----------|-----------------------------------|---------------------|
| Round-02 Q1 | HIGH | Provisioning and anchoring of the server's RSA public key | In the client handshake (`shelper.dll!0x1006a540`), the server's RSA public key is passed as a parameter through the pointer `[esi + 0x18]`. Does the official client load the coordination RSA key directly from a trusted key table embedded in the `.rdata` section of the executable, or does it accept dynamic keys negotiated previously? | Locate the certificate/public-key table in `.rdata` of `RvROLClient.dll` and check whether strict digital signature verification (certificate pinning) is enforced, or whether any standard RSA-2048 key is accepted on private servers. |
| Round-02 Q2 | MEDIUM | Rekeying frequency and keepalive | In the `radmin_17301.pcap` flow, the control session stays open for minutes exchanging small telemetry packets without renewing the AES key negotiated initially. Does the protocol require periodic rekeying by time or by bytes transmitted? Or is the session purely persistent until the socket is disconnected? | Run a long session with high-volume traffic to observe whether the server sends a TLV message requesting a new handshake. |
| Round-02 Q3 | LOW | Complete bitmask of the attributes in `0x010001e3` | `0x010001e3` is a confirmed 32-bit network attribute used for routing control and permissions. What exactly are all the flag bits mapped in the 32 bits? | Compare network configuration captures with different administrative settings enabled in the official GUI. |

## 2. Object-Lifecycle Blockers

Source materials: `docs/PHASE_2_3/16_UNRESOLVED_QUESTIONS.md` (Q1–Q8),
`docs/PHASE_2_4/16_UNRESOLVED_QUESTIONS_AND_BLOCKERS.md` (B1–B10),
`docs/PHASE_2_5/16_UNRESOLVED_QUESTIONS_AND_BLOCKERS.md` (B1–B12,
resolved R1–R8).

Note on dedup: Phase 2.4 B1–B4 (object allocation call site, allocation
size, runtime vptr state, indirect-call targets) are duplicates of Phase 2.5
B1–B4. Phase 2.5 entries are authoritative; Phase 2.4 cross-references are
not repeated verbatim.

### 2.1 Phase 2.3 Unresolved Questions (Q1–Q8)

| ID | Question | Why it matters | Evidence examined | Static analysis operation needed | Blocks Rust? | Addresses |
|----|----------|----------------|-------------------|----------------------------------|--------------|-----------|
| Q1 | Runtime vptr state when `FUN_0044F3F0` executes. The constructor overwrites `[EDI+0x00]` three times: `0x51FFB4` → `0x51E570` → `0x51E4F0`. Cannot determine which vptr is active when `FUN_0044F3F0` reads `[EDI]` and makes indirect calls. | Indirect call targets `[EAX+0x34]` and `[EAX+0x58]` depend entirely on which vptr is active. | Constructor disassembly (853 bytes, all 3 vptr writes verified); `FUN_0044F3F0` disassembly (EAX = [EDI] at all 4 call sites); REA procedure_callers at 0x44F3F0 (empty — no direct callers). | Search for all writes to object offset 0x00 across the entire binary to find the final vptr value before `FUN_0044F3F0` is called. Search for calls to `FUN_0044F3F0` via vtable slot 0 to find invocation context. | No — Rust doesn't use C++ vtable semantics. | `FUN_0044F3F0` (0x44F3F0); constructor writes at 0x43E1B1, 0x43E4C8, 0x43E4E8 |
| Q2 | Object allocation site and factory. No `operator new`/`malloc`/allocator call found in the constructor. Who allocates the object and calls `FUN_0043ECF0` (or the adjustment thunks)? | Without the constructor caller, object lifetime and initialization order cannot be established. | REA procedure_callers at 0x43ECF0 (5 thunks only); REA procedure_callers at 0x44F3F0 (empty); constructor disassembly (no allocator call). | Search for CALL instructions targeting the adjustment thunk addresses (0x43e85e–0x43e881) or direct calls to `FUN_0043ECF0`. Search PE import directory for allocator APIs (malloc, operator new, CoTaskMemAlloc, etc.). | No. | Thunks at 0x43e85e–0x43e881; `FUN_0043ECF0` (0x43ecf0); PE import directory |
| Q3 | `FUN_00451090` body. | N/A | — | — | No. | — |
| Q4 | `field_0x28`/`0x2C`/`0x30` writers: `field_0x28` is compared to 5, `field_0x2C` is compared to 0, `field_0x30` is incremented. Writers for `field_0x28` found in 15+ functions. `field_0x2C` writers found in 7 functions. `field_0x30` writer found in `FUN_00410E80` and `FUN_00410F60` (in addition to `FUN_0044F3F0`). | These fields control whether indirect calls execute in `FUN_0044F3F0`. Without knowing their initial values, we cannot determine if the guard condition is ever satisfied. | `FUN_0044F3F0` disassembly (all read accesses at 0x44F4EE/0x44F4F4/0x44F4FE/0x44F597/0x44F59D/0x44F5A7); constructor disassembly (no writes to these offsets); byte search for `C7 47 28` and `C7 47 2C` found many writers. | The writers for `field_0x28` and `field_0x2C` have been found (many functions). The writer for `field_0x30` has also been found (`FUN_00410E80` and `FUN_00410F60` initialize it to 0). All writers have been identified. | No — field semantics are hypotheses; Rust enum state machine doesn't need them. | `FUN_0044F3F0` reads at 0x44F4EE/0x44F4F4/0x44F4FE/0x44F597/0x44F59D/0x44F5A7; `FUN_00410E80` at 0x410ebd; `FUN_00410F60` at 0x410f9d |
| Q5 | `field_0x214` writer not found: `MOV [EDI+0x214], 0` (`C7 47 214`) was NOT found anywhere in the binary. The previous report claimed a write at 0x42173B. | The field doesn't appear to exist in this object. | Raw byte search for `C7 47 214` returned no results across all code sections. Alternative encodings were also searched. | None — all reasonable byte patterns have been searched. | No — `field_0x214` doesn't appear to exist in this object. | None — `field_0x214` has no accesses |
| Q5 (Priority 2) | `FUN_004E7EC0` body not analyzed. `FUN_004E6CD7` wraps `FUN_004E7EC0`. | This is the conditional cleanup path in `FUN_0043ECF0`. | `FUN_004E6CD7` disassembly (14 bytes: `PUSH [EBP+0x8]; CALL 0x004e7ec0`). | REA procedure_info/procedure_assembly at 0x4e7ec0. | No. | `FUN_004E7EC0` (0x4e7ec0) |
| Q6 | Non-.text table slots (8 entries in Table A; 3 in intermediate/final tables): Table A slots 1, 25, 28, 33, 38 contain non-.text values (0x00539xxx range). Tables B and C have 3 non-.text slots each. Purpose unknown. | Affects vtable classification (pure vs. mixed code/data table). | Full 40-slot table extraction; intermediate/final table extraction. | REA read_bytes at 0x00539A4C, 0x00539BDC, 0x00539BF0, 0x00539C04, 0x00539C18; search for references to these addresses. | No. | Table A slots 1, 25, 28, 33, 38 at VA 0x51FFB0, 0x520010, 0x52001C, 0x520030, 0x520048 |
| Q7 | Constructor sub-initializer bodies not analyzed: constructor calls 12 sub-initializer functions whose bodies were not analyzed: `FUN_0047A8A0`, `FUN_0043E500`, `FUN_00403540`, `FUN_004728E0`, `FUN_00483750`, `FUN_0043E680`, `FUN_0047BB20`, `FUN_00475B70`, `FUN_00479240`, `FUN_004E70a5`, `FUN_0043a9a0`, `FUN_004E7EC0`. | These initialize subobject fields that may affect object behavior. | Constructor disassembly shows call sites but not function bodies. | REA procedure_info/procedure_assembly on each sub-initializer. | No. | All 12 sub-initializer addresses |
| Q8 | Object size unknown: constructor initializes fields up to offset 0x5C40. Zeroing loop covers 0x0C–0x4C4. Actual object size not confirmed (no allocator call found). | Affects understanding of object memory layout. | Constructor disassembly (`LEA ECX,[EDI+0x5C40]`); `FUN_0043E100` zeroing loop. | Search PE import directory for allocator APIs; search for allocation patterns near object-sized regions. | No. | Constructor entry 0x43E1A0; PE import directory |

### 2.2 Phase 2.4 Blockers (B1–B10)

Source: `docs/PHASE_2_4/16_UNRESOLVED_QUESTIONS_AND_BLOCKERS.md`.

| ID | Question | Classification | Blocks Rust? | Required evidence | Blocker type |
|----|----------|----------------|--------------|-------------------|--------------|
| P2.4-BLOCK-1 | Object allocation call site | BLOCKED | No | `HeapAlloc`/`RolClient_AllocMemory` call with `this` pointer | No Windows debugger |
| P2.4-BLOCK-2 | Object actual allocation size | BLOCKED | No | Allocation size argument observed | No Windows debugger |
| P2.4-BLOCK-3 | Runtime vptr state at `FUN_0044F3F0` | BLOCKED | No | `[EDI]` value at breakpoint | No Windows debugger |
| P2.4-BLOCK-4 | Actual indirect-call targets at runtime | BLOCKED | No | CALL target at 0x44F501/0x44F50D/0x44F5AA/0x44F5B6 | No Windows debugger |
| P2.4-BLOCK-5 | `FUN_00473210` body | UNKNOWN | No | REA procedure_info/procedure_pseudo_code at 0x473210 | Not yet analyzed |
| P2.4-BLOCK-6 | AddRef function | UNKNOWN | No | Search for increment at obj+0x20 | Not yet found |
| P2.4-BLOCK-7 | `[0x00500ca6]` IAT slot target | UNKNOWN | No | Read memory at 0x500ca6; identify resolved function | Not yet resolved |
| P2.4-BLOCK-8 | Allocation/deallocation symmetry | UNKNOWN | No | Pair allocation with deallocation | Both ends unresolved |
| P2.4-BLOCK-9 | Multiple reference counters | UNKNOWN | No | Verify 0x1E28–0x1E50 are refcounts | Not yet verified |
| P2.4-BLOCK-10 | `field_0x28`/`0x2C` initial values | UNKNOWN | No | Find initialization writes | Not found in constructor |

#### P2.4-BLOCK detailed descriptions

- **P2.4-BLOCK-1 — Object Allocation Call Site:** No function calls `HeapAlloc` or `RolClient_AllocMemory` with the object as the result. The constructor `FUN_0043E1A0` does not allocate memory. Blocked: no Windows debugger to capture runtime allocation. Static analysis found no allocation call in the constructor path. Required: breakpoint at `KERNEL32!HeapAlloc` or `RvROLClient!RolClient_AllocMemory`, capture return pointer, trace to constructor entry.
- **P2.4-BLOCK-2 — Object Actual Allocation Size:** No allocation size argument was observed. Constructor initializes fields up to 0x5C40, but this is not the allocation size. Depends on P2.4-BLOCK-1 — need to see the actual `HeapAlloc(size)` call.
- **P2.4-BLOCK-3 — Runtime Vptr State at `FUN_0044F3F0`:** Constructor writes 3 different vptrs. Cannot determine which is active when `FUN_0044F3F0` executes. Blocked: `FUN_0044F3F0` has no direct callers. No runtime execution trace. Required: breakpoint at 0x44F3F0, inspect `[EDI]` vptr value.
- **P2.4-BLOCK-4 — Actual Indirect-Call Targets at Runtime:** Slot 13 (+0x34) and slot 22 (+0x58) targets depend on active vptr. Table A: both return 0. Table B/C: slot 13 returns 16, slot 22 returns 0. Depends on P2.4-BLOCK-3 — need to know which vptr is active. Required: breakpoint at CALL instructions, capture actual target.
- **P2.4-BLOCK-5 — `FUN_00473210` Body:** Referenced by `FUN_004731E0` as decrement-and-destroy-if-zero, but body not decompiled. Not in the set of functions analyzed in Phase 2.3. Need REA procedure_info at 0x473210.
- **P2.4-BLOCK-6 — AddRef Function:** No function identified that increments refcount at obj+0x20. Static search did not find an increment pattern at obj+0x20. Required: search for `LOCK` + `ADD`/`XADD` at obj+0x20, or runtime breakpoint.
- **P2.4-BLOCK-7 — `[0x00500ca6]` IAT Slot Target:** The function pointer at `[0x00500ca6]` is not resolved. Likely `HeapFree` or `RolClient_FreeMemory`. Required: REA read_bytes at 0x500ca6, or breakpoint at `CALL [0x500ca6]`.
- **P2.4-BLOCK-8 — Allocation/Deallocation Symmetry:** Cannot confirm same allocator family used for both operations. Both allocation site (P2.4-BLOCK-1) and deallocation target (P2.4-BLOCK-7) unresolved.
- **P2.4-BLOCK-9 — Multiple Reference Counters:** obj+0x20 confirmed as refcount. Region 0x1E28–0x1E50 hypothesized but not verified. No instruction-level analysis of 0x1E28–0x1E50 region.
- **P2.4-BLOCK-10 — `field_0x28`/`0x2C` Initial Values:** No constructor writes to these offsets. Initial values before first write unknown. Constructor does not initialize these fields. Required: search for all writes to obj+0x28 and obj+0x2C to find initialization.

#### P2.4 Questions not blocking Rust implementation

All 10 blockers above do NOT block Rust implementation because: Rust does not use C++ vtable semantics (P2.4-BLOCK-3, P2.4-BLOCK-4 blocked); Rust does not use manual heap management (P2.4-BLOCK-1, P2.4-BLOCK-2, P2.4-BLOCK-8 blocked); Rust `Arc<T>` handles reference counting automatically (P2.4-BLOCK-5, P2.4-BLOCK-6, P2.4-BLOCK-9 blocked); Rust `Drop` handles deallocation (P2.4-BLOCK-7 blocked); Rust enum state machines replace u32 field comparisons (P2.4-BLOCK-10 blocked).

### 2.3 Phase 2.5 Blockers (B1–B12) and Resolved Items (R1–R8)

Source: `docs/PHASE_2_5/16_UNRESOLVED_QUESTIONS_AND_BLOCKERS.md`.

| ID | Question | Classification | Blocks Rust? | Required evidence |
|----|----------|----------------|--------------|-------------------|
| P2.5-BLOCK-1 | Object allocation call site | BLOCKED | No | `HeapAlloc`/`RolClient_AllocMemory` call with `this` pointer |
| P2.5-BLOCK-2 | Object actual allocation size | BLOCKED | No | Allocation size argument observed |
| P2.5-BLOCK-3 | Runtime vptr state at `FUN_0044F3F0` | BLOCKED | No | `[EDI]` value at breakpoint |
| P2.5-BLOCK-4 | Actual indirect-call targets at runtime | BLOCKED | No | CALL target at 0x44F501/0x44F50D/0x44F5AA/0x44F5B6 |
| P2.5-BLOCK-5 | `CALL [0x00500CA6]` actual target | BLOCKED | No | Memory at [0x500CA6] at CALL breakpoint |
| P2.5-BLOCK-6 | AddRef function | UNKNOWN | No | Search for increment at obj+0x20 |
| P2.5-BLOCK-7 | 9 sub-initializer bodies | UNKNOWN | No | REA procedure_info on each |
| P2.5-BLOCK-8 | obj+0x20/0x28/0x2C initial values | UNKNOWN | No | Find initialization writes |
| P2.5-BLOCK-9 | `FUN_00450FA0` body | UNKNOWN | No | REA procedure_pseudo_code at 0x450FA0 |
| P2.5-BLOCK-10 | `FUN_00450FC0` body | UNKNOWN | No | REA procedure_pseudo_code at 0x450FC0 |
| P2.5-BLOCK-11 | `FUN_004728E0` body | UNKNOWN | No | REA procedure_pseudo_code at 0x4728E0 |
| P2.5-BLOCK-12 | Constructor reachability | UNKNOWN | No | Search for factory or indirect caller |

Note: Phase 2.5 re-examined `[0x00500CA6]` and found it contains `0x8B55FF8B` (code bytes, not a valid pointer) — refuted as an IAT slot (see R4/R5 below).

#### P2.5-BLOCK detailed descriptions

- **P2.5-BLOCK-1 — Object Allocation Call Site:** No function calls `HeapAlloc` or `RolClient_AllocMemory` with the object as the result. No Windows debugger to capture runtime allocation.
- **P2.5-BLOCK-2 — Object Actual Allocation Size:** No allocation size argument was observed. Depends on P2.5-BLOCK-1.
- **P2.5-BLOCK-3 — Runtime Vptr State:** Constructor writes 3 different vptrs. Cannot determine which is active when `FUN_0044F3F0` executes. `FUN_0044F3F0` has no direct callers. No runtime execution trace.
- **P2.5-BLOCK-4 — Actual Indirect-Call Targets:** Slot 13 (+0x34) and slot 22 (+0x58) targets depend on active vptr. Corrected static targets known, but runtime selection unknown. Depends on P2.5-BLOCK-3.
- **P2.5-BLOCK-5 — CALL [0x00500CA6] Actual Target:** The DWORD at 0x500CA6 is `0x8B55FF8B` (code bytes, not a valid pointer). The CALL instruction reads this as a pointer — anomalous. Need to break at the CALL instruction and capture the actual resolved target at runtime.
- **P2.5-BLOCK-6 — AddRef Function:** No function identified that increments refcount at obj+0x20. Static search of all analyzed functions found no increment pattern. 9 sub-initializers not yet analyzed.
- **P2.5-BLOCK-7 — 9 Sub-Initializer Bodies:** Bodies of `FUN_0047A8A0`, `FUN_0043E500`, `FUN_00403540`, `FUN_004728E0`, `FUN_00483750`, `FUN_0043E680`, `FUN_0047BB20`, `FUN_00475B70`, `FUN_00479240` not analyzed. Not in Ghidra's analyzed function set or not decompiled.
- **P2.5-BLOCK-8 — obj+0x20/0x28/0x2C Initial Values:** Constructor doesn't write these fields. Initial values before first write unknown. No writer found in constructor. May be in unanalyzed sub-initializers.
- **P2.5-BLOCK-9/10/11 — Function Bodies Not Decompiled:** `FUN_00450FA0`, `FUN_00450FC0`, `FUN_004728E0` bodies not decompiled by Ghidra (`procedure_pseudo_code` returned null).
- **P2.5-BLOCK-12 — Constructor Reachability:** No external callers found for the constructor chain. Could be reached via indirect call, factory function, or unanalyzed code.

#### Phase 2.5 resolved items (no longer blockers)

| ID | Previous classification | New classification | Resolution |
|----|------------------------|-------------------|------------|
| R1 | `FUN_00473210` body — UNKNOWN | CONFIRMED | Analyzed: destroy/reset, sets obj+0x20 to 0, exchanges obj+0x24, deletes critical section at obj+8 |
| R2 | Table A indirect dispatch targets — UNKNOWN | CONFIRMED | Slot 13 → 0x4510A0 (returns 0); Slot 22 → 0x450FA0 (body not analyzed) |
| R3 | Table B/C indirect dispatch targets — UNKNOWN | CONFIRMED | Slot 13 → 0x4510B0 (returns 16); Slot 22 → 0x450FC0 (body not analyzed) |
| R4 | `0x500CA6` section — UNKNOWN | CONFIRMED | In `.text`; contains `free` function |
| R5 | `0x500CA6` is IAT slot — UNKNOWN | REFUTED | Contains code (function prologue), not a pointer |
| R6 | Subinitializer count discrepancy — UNKNOWN | CONFIRMED | 9 not 8 |
| R7 | Object lifecycle type — UNKNOWN | CONFIRMED | Destroy-on-read-nonzero, not standard AddRef/Release |
| R8 | `field_0x20`/`0x28`/`0x2C` initialization — UNKNOWN | CONFIRMED (negative) | Not initialized by constructor |

#### Phase 2.5 questions not blocking Rust

All 12 blockers above do NOT block Rust implementation because: Rust does not use C++ vtable semantics (P2.5-BLOCK-3, P2.5-BLOCK-4 blocked); Rust does not use manual heap management (P2.5-BLOCK-1, P2.5-BLOCK-2 blocked); Rust `Arc<T>` handles reference counting automatically (P2.5-BLOCK-6 blocked); Rust `Drop` handles deallocation (P2.5-BLOCK-5 blocked); Rust enum state machines replace u32 field comparisons (P2.5-BLOCK-8 blocked); Rust construction is `fn new()`, not multi-phase vptr transitions (P2.5-BLOCK-12 blocked).

## 3. Runtime / IPC Gaps

Source materials: `docs/PHASE_2_7/12_EVIDENCE_LIMITATIONS_AND_UNRESOLVED_QUESTIONS.md` (Q1–Q15),
`docs/PHASE_2_8/16_EVIDENCE_LIMITATIONS_AND_UNRESOLVED_QUESTIONS.md` (Q1–Q21).

### 3.1 Phase 2.7 Unresolved Questions (pre-connection)

#### Architecture questions

| ID | Question | Evidence needed | Priority |
|----|----------|-----------------|----------|
| P2.7-Q1 | What IPC mechanism does GUI use to talk to service? | Named pipe / RPC / LPC handle enumeration | High |
| P2.7-Q2 | Is `RvROLClient.dll` the sole protocol implementation in service? | Static analysis + runtime call tracing | High |
| P2.7-Q3 | What triggers `RvFwHelper.exe` spawn? | Post-connection process tree | High |
| P2.7-Q4 | Does `drvinst.exe` run on every connection or only first? | Multiple connection tests | Medium |
| P2.7-Q5 | What is the purpose of `WinLpcDl.dll` / `ChatLPCx.dll`? | Static analysis + runtime loading | High |

#### Network questions

| ID | Question | Evidence needed | Priority |
|----|----------|-----------------|----------|
| P2.7-Q6 | What protocol runs on UDP 56413? | PCAP + payload analysis | High |
| P2.7-Q7 | Does service establish TCP to relay servers pre-connection? | Continuous netstat / PCAP | Medium |
| P2.7-Q8 | How are peer addresses discovered? | Post-connection network diff | High |
| P2.7-Q9 | Is there a persistent control channel to Famatech servers? | Long-term network monitoring | Medium |

#### Crypto/key questions

| ID | Question | Evidence needed | Priority |
|----|----------|-----------------|----------|
| P2.7-Q10 | Where are session keys generated/stored? | Memory analysis (not in scope) | High |
| P2.7-Q11 | Does libcrypto-3/libssl-3 handle all TLS? | Call tracing + static analysis | High |
| P2.7-Q12 | What is `RvUESClient.dll`'s role in key exchange? | Static analysis + runtime | High |

#### Module/code questions

| ID | Question | Evidence needed | Priority |
|----|----------|-----------------|----------|
| P2.7-Q13 | Why does GUI not load `RvROLClient.dll` at baseline? | Static analysis of GUI imports | Medium |
| P2.7-Q14 | What Qt plugins are loaded dynamically post-connection? | Module diff | Low |
| P2.7-Q15 | Are there any delay-loaded DLLs in Radmin binaries? | Static analysis (delay import table) | Medium |

### 3.2 Phase 2.8 Unresolved Questions

#### Service behavior

| ID | Question | Priority | Evidence needed |
|----|----------|----------|-----------------|
| P2.8-Q1 | Why did service restart in Phase 2.7 but not Phase 2.8? | HIGH | Compare initial conditions (crash loop vs stable) |
| P2.8-Q2 | Why does service change local TCP port on Connect (62654→65157)? | HIGH | Service code trace / relay protocol |
| P2.8-Q3 | Why does service change local TCP port again after GUI restart (65157→65199)? | HIGH | Service code trace / GUI IPC |
| P2.8-Q4 | Is UDP port 49237 fixed or ephemeral? | MEDIUM | Multiple connections |
| P2.8-Q5 | What causes the 5 pre-baseline crashes? | MEDIUM | Crash dumps / Event Viewer |

#### GUI behavior

| ID | Question | Priority | Evidence needed |
|----|----------|----------|-----------------|
| P2.8-Q6 | What triggers GUI restart on Connect? | HIGH | GUI debugger trace / IPC trace |
| P2.8-Q7 | Why does GUI module count drop 125→101 on restart? | HIGH | Delay-load analysis / Qt plugin load logic |
| P2.8-Q8 | Does GUI restart reinitialize IPC channel? | HIGH | Pipe operation trace |
| P2.8-Q9 | Does GUI use QLocalSocket to `RadminVpnGuiChannel`? | HIGH | Qt5Network code trace |

#### IPC mechanism

| ID | Question | Priority | Evidence needed |
|----|----------|----------|-----------------|
| P2.8-Q10 | What is the exact IPC protocol on `RadminVpnGuiChannel`? | HIGH | Pipe message capture (Procmon) |
| P2.8-Q11 | Does service create the pipe or GUI? | MEDIUM | Pipe create trace |
| P2.8-Q12 | Are `WinLpcDl.dll` / `ChatLPCx.dll` ever loaded? | MEDIUM | Delay-load trace / feature trigger |
| P2.8-Q13 | Is RPC/ALPC used in addition to named pipes? | MEDIUM | ETW RPC/ALPC capture |

#### Network/protocol

| ID | Question | Priority | Evidence needed |
|----|----------|----------|-----------------|
| P2.8-Q14 | What protocol runs on TCP 17301 to relay? | HIGH | PCAP / service trace |
| P2.8-Q15 | What causes service port change 62654→65157? | HIGH | Service trace | (duplicate of P2.8-Q2)
| P2.8-Q16 | What causes service port change 65157→65199? | HIGH | Service trace | (duplicate of P2.8-Q3)
| P2.8-Q17 | Is UDP 49237 used for peer traffic or keepalive? | MEDIUM | PCAP / traffic analysis | (duplicate of P2.8-Q4)
| P2.8-Q18 | How are peer addresses discovered? | MEDIUM | PCAP / service trace | (duplicate of P2.8-Q8)

#### Crypto/key management

| ID | Question | Priority | Evidence needed |
|----|----------|----------|-----------------|
| P2.8-Q19 | Where are session keys generated/stored? | HIGH | Memory analysis (prohibited) |
| P2.8-Q20 | How does libcrypto/libssl integrate with `RvROLClient`? | HIGH | Static trace + dynamic |
| P2.8-Q21 | Does GUI restart affect session keys? | HIGH | Key comparison pre/post |

Note: P2.8-Q2/Q15, Q3/Q16, Q4/Q17, Q8/Q18 are duplicates across the phase 2.8 table and are preserved once here with both IDs noted.

## 4. PCAP Evidence Gaps

Source materials: `docs/PHASE_2_7/12_EVIDENCE_LIMITATIONS_AND_UNRESOLVED_QUESTIONS.md`,
`docs/PHASE_2_8/16_EVIDENCE_LIMITATIONS_AND_UNRESOLVED_QUESTIONS.md`,
`docs/reverse-engineering/round-02/UNRESOLVED_QUESTIONS.md`.

| Gap | Description | Severity | Source |
|-----|-------------|----------|--------|
| No PCAP capture | No packet capture available, so protocol content, encryption, and payloads cannot be analyzed. | High | Phase 2.7 §1.3 (Network Monitoring) |
| SRP handshake not captured | No PCAP containing the full SRP handshake exists; step-value endianness (OQ-7) and version wire encoding (B-5/G-5) cannot be confirmed from capture. | Medium | Phase 10.x OQ-7; Investigation B B-5; Investigation G G-5 |
| UDP 56413 protocol unknown | What protocol runs on UDP 56413 is unknown; requires PCAP + payload analysis. | High | Phase 2.7 Q6 |
| UDP 49237 purpose unknown | Is UDP 49237 used for peer traffic or keepalive? Fixed or ephemeral? | Medium | Phase 2.8 Q4/Q17 |
| TCP 17301 relay protocol unknown | What protocol runs on TCP 17301 to relay is unknown. | High | Phase 2.8 Q14 |
| Rekeying frequency | Hypothesis (50% confidence): rekeying after an inactivity timer or volume limit; no explicit trigger in the PCAP. Not confirmed whether periodic rekeying by time or bytes occurs. | Medium | Round-02 Q2 |
| `0x010001e3` bitmask | Complete bitmask of the 32-bit network attribute `0x010001e3` (routing control/permissions flag bits) unknown. | Low | Round-02 Q3 |

## 5. Consolidated Priority List

Source: `docs/CRYPTO_UNRESOLVED_QUESTIONS.md` §9 (Consolidated Priority List for Implementation). Priority is left to the implementer based on which gaps block interoperability.

| Priority | Issue | Investigation | Binary address(es) | Rust location |
|----------|-------|---------------|-------------------|---------------|
| 1 (Critical) | Step value endianness | A / G-1 | `0x100626e0` | `control_handshake.rs` L670, 780, 910, 1267, 1399, 1456 |
| 2 (Critical) | Identity/password encoding in `x` | A / G-2 | `0x10060340`, `0x10060c80` | `control_handshake.rs` L269-286 |
| 3 (Critical) | Multiplier `k` class | A / G-3 | `0x10060810`, `0x100ad760`, `0x100ad7b8` | `control_handshake.rs` L16 |
| 4 (High) | 64 → two 32-byte AES key split | B / C | `0x1006ba80`, `0x1006ab00`, `0x1006aac0` | `famatech.rs` `derive_aes256_key_ref` |
| 5 (High) | GetKey consumer location | B | disp8 sweep in ROLClient/ControlSvc | N/A (consumer not found) |
| 6 (High) | Client/server RSA key provenance | D | `0x1006b860`/`0x1006b8f0` callers | `handshake.rs` `create_client`/`create_server` |
| 7 (Medium) | Public value length check | A / G-4 | `0x100699e0` | `control_handshake.rs` L330-337 |
| 8 (Medium) | Version endianness | A / G-5 | `0x1006b1d0` | `control_handshake.rs` L588 |
| 9 (Medium) | Public value padding in M1 | A / G-6 | `0x10060410`, `0x10060510` | `control_handshake.rs` `compute_srp_m1` callers |
| 10 (Low) | Control message integration | G-7 | N/A | `src/protocol/control.rs` |
| 11 (Low) | RSession transport integration | G-8 | `0x1006b8f0`, `0x1006b860` | `src/session/handshake.rs` `RSessionServer` |
| 12 (Low) | Interop test with original key | G-9 | `RvROLClient.dll` RSA public key | `src/session/*` test modules |

## 6. Items Resolved by Later Phases vs Still UNKNOWN

### Resolved by later phases

| Item | Source phase | Resolution |
|------|-------------|------------|
| `FUN_00451090` body | Phase 2.3 Q3 → Phase 2.2 Stage 7 | RESOLVED — `XOR EAX, EAX; RET` (returns 0). |
| `field_0x28`/`0x2C` writers | Phase 2.3 Q4 → Phase 2.3 Stage 4 | PARTIALLY RESOLVED — writers found in many functions; `field_0x30` writer found (`FUN_00410E80`/`FUN_00410F60` initialize to 0). |
| 12 sub-initializer bodies | Phase 2.3 Q7 → Phase 2.3 Stage 1 | PARTIALLY RESOLVED — all 12 identified; some bodies analyzed, some not. |
| `FUN_00473210` body | Phase 2.4 P2.4-BLOCK-5 → Phase 2.5 R1 | CONFIRMED — destroy/reset, sets obj+0x20 to 0, exchanges obj+0x24, deletes critical section at obj+8. |
| Table A indirect dispatch targets | Phase 2.5 R2 | CONFIRMED — Slot 13 → 0x4510A0 (returns 0); Slot 22 → 0x450FA0 (body not analyzed). |
| Table B/C indirect dispatch targets | Phase 2.5 R3 | CONFIRMED — Slot 13 → 0x4510B0 (returns 16); Slot 22 → 0x450FC0 (body not analyzed). |
| `0x500CA6` section | Phase 2.5 R4 | CONFIRMED — in `.text`; contains `free` function. |
| `0x500CA6` is IAT slot | Phase 2.5 R5 | REFUTED — contains code (function prologue), not a pointer. |
| Subinitializer count discrepancy | Phase 2.5 R6 | CONFIRMED — 9 not 8. |
| Object lifecycle type | Phase 2.5 R7 | CONFIRMED — destroy-on-read-nonzero, not standard AddRef/Release. |
| `field_0x20`/`0x28`/`0x2C` initialization | Phase 2.5 R8 | CONFIRMED (negative) — not initialized by constructor. |

### Still UNKNOWN (carried forward)

**Crypto/protocol (P0/P1 blockers kept UNKNOWN):**
- Password encoding in `x` (B-4, G-2, OQ-2) — UNKNOWN / CONFIRMED_MISMATCH if UTF-16LE
- RSA key provenance (C-3/D-1/OQ-6/Round-02 Q1) — UNKNOWN
- AES key split mapping (C-1/OQ-1) — UNKNOWN / HYPOTHESIS
- Identity hash LE vs BE (OQ-3) — UNKNOWN
- M1/M2 exact construction (OQ-5) — PARTIALLY_CONFIRMED
- SRP step endianness (OQ-7/G-5) — UNKNOWN / PARTIAL_MATCH
- `context+0x20` runtime proof (OQ-4) — STRONGLY_SUPPORTED (static), runtime proof pending

**Object-lifecycle (kept UNKNOWN / BLOCKED):**
- Object allocation call site (P2.4-BLOCK-1 / P2.5-BLOCK-1) — BLOCKED
- Object actual allocation size (P2.4-BLOCK-2 / P2.5-BLOCK-2) — BLOCKED
- Runtime vptr state at `FUN_0044F3F0` (P2.4-BLOCK-3 / P2.5-BLOCK-3) — BLOCKED
- Actual indirect-call targets (P2.4-BLOCK-4 / P2.5-BLOCK-4) — BLOCKED
- AddRef function (P2.4-BLOCK-6 / P2.5-BLOCK-6) — UNKNOWN
- obj+0x20/0x28/0x2C initial values (P2.4-BLOCK-10 / P2.5-BLOCK-8) — UNKNOWN
- `FUN_00450FA0`/`FUN_00450FC0`/`FUN_004728E0` bodies (P2.5-BLOCK-9/10/11) — UNKNOWN
- Constructor reachability (P2.5-BLOCK-12) — UNKNOWN

**Runtime/IPC (kept UNKNOWN):**
- All Phase 2.7 Q1–Q15 and Phase 2.8 Q1–Q21 items (IPC mechanism, session key storage, relay protocol, port changes, etc.)

**PCAP evidence (kept UNKNOWN):**
- SRP handshake capture, rekeying frequency, `0x010001e3` bitmask, UDP 56413/49237 protocols, TCP 17301 protocol

## Sources

All sources consumed (first column `OPEN_QUESTIONS` in `analysis_workspace/compaction/mapping.tsv`):

1. `docs/CRYPTO_PHASE_10_12_BLOCKER_RESOLUTION.md` — Phase 10.12 cryptographic compatibility blocker resolution (Workstreams A–F, remaining unknowns, dynamic experiments, evidence index).
2. `docs/CRYPTO_PHASE_10_3_10_5_OPEN_QUESTIONS.md` — Open Questions, unified Phase 10.3–10.5 (OQ-1..OQ-8).
3. `docs/CRYPTO_UNRESOLVED_QUESTIONS.md` — Cryptographic analysis unresolved questions (Investigations A–G, key-lifecycle sub-items, consolidated priority list).
4. `docs/PHASE_2_3/16_UNRESOLVED_QUESTIONS.md` — Phase 2.3 Stage 16 unresolved questions and evidence gaps (Q1–Q8).
5. `docs/PHASE_2_4/16_UNRESOLVED_QUESTIONS_AND_BLOCKERS.md` — Phase 2.4 Stage 16 unresolved questions and blockers (B1–B10).
6. `docs/PHASE_2_5/16_UNRESOLVED_QUESTIONS_AND_BLOCKERS.md` — Phase 2.5 Stage 16 unresolved questions and blockers (B1–B12, resolved R1–R8).
7. `docs/PHASE_2_7/12_EVIDENCE_LIMITATIONS_AND_UNRESOLVED_QUESTIONS.md` — Phase 2.7 evidence limitations and unresolved questions (Q1–Q15).
8. `docs/PHASE_2_8/16_EVIDENCE_LIMITATIONS_AND_UNRESOLVED_QUESTIONS.md` — Phase 2.8 evidence limitations and unresolved questions (Q1–Q21).
9. `docs/analysis_workspace/unresolved_references.md` — Unresolved references (runtime pointer values, indirect call targets, thunk targets, missing functions, unknown-convention functions).
10. `docs/reverse-engineering/round-02/UNRESOLVED_QUESTIONS.md` — Open questions and certainty classification (Round 02, Questions 1–3).

---

## Evidence appendix (exact tokens from consolidated sources)

Exact addresses, hashes and identifiers from the consolidated sources that are not repeated in the prose above. They are preserved here so that no evidence anchor is lost during compaction; the full narrative for each source remains available in git history.

- `docs/CRYPTO_PHASE_10_12_BLOCKER_RESOLUTION.md`: `0x10000000`, `0x1005f6e0`, `0x10061760`, `0x10062b10`, `0x10069f50`, `0x1006a270`, `0x10094218`, `546efad9ab3ff85c2a50d61524d754bec94a3f3e30d6ae8addef481a1e8daa1e`, `5fc07f57d1d1a46bf080dd833511d5166235ffc2c00812faf46d99f008384d21`, `6ba7dfecd38183d4bff0fc53f1c8c05d25e636077fe753b1220912aa58938177`, `7b12a483fe77c3ed56e5a4dd8e7acc4fe7ec1233`, `95e304e0855a6faf4eece932484cb00e36620a6e`, `d89daf6bcd5cafa3c7f6173f835ccf045baf8e7134f868819db6fd7615959ac4`, `fun_00442290`, `fun_1003fbd0`, `fun_1005f710`, `fun_1005fad0`, `fun_100607d0`, `fun_10060810`, `fun_10060ec0`
- `docs/PHASE_2_4/16_UNRESOLVED_QUESTIONS_AND_BLOCKERS.md`: `fun_004ec736`
- `docs/analysis_workspace/unresolved_references.md`: `0x0055bf80`, `0x0055bf84`, `fun_00415f80`, `fun_00416650`, `fun_0041e220`, `fun_0041e280`
- `docs/reverse-engineering/round-02/UNRESOLVED_QUESTIONS.md`: `0x00498fe0`, `0x090001cd`, `0x1004ef1c`, `0x10052310`, `0x10062ca9`, `0x10065790`, `0x1006a4cc`, `0x1006a512`, `0x224018`, `0x224020`, `0x228014`, `0x22801c`, `0x22c004`, `0x40f052`, `0x41537e`, `0x4e8eb0`, `0xffffffff`, `fun_10069c20`, `fun_10069f90`, `fun_1006a0c0`
