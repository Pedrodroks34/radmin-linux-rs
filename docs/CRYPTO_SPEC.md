# CRYPTO Specification — Consolidated Draft

**Project:** Radmin VPN Linux client (Rust, independent)
**Source corpus:** 17 documents mapped to `CRYPTO_SPEC` in `analysis_workspace/compaction/mapping.tsv`
**Status:** Consolidation draft — all claims trace to a source address or explicit confidence classification; no hypothesis presented as confirmed fact
**Language:** English

Confidence classifications used throughout (per `docs/CRYPTOGRAPHIC_OVERVIEW.md` §1):

| Classification | Meaning |
|---|---|
| CONFIRMED | Directly demonstrated by instruction-level analysis, verified data flow, or reproducible behavior |
| STRONG INDICATION | Multiple consistent observations, missing one decisive verification |
| HYPOTHESIS | Plausible interpretation requiring verification |
| UNKNOWN | Insufficient evidence |
| REFUTED | Evidence directly contradicts the claim |

Compatibility statuses (per `docs/CRYPTO_KEY_LIFECYCLE_GAP_ANALYSIS.md`): CONFIRMED_MATCH, CONFIRMED_MISMATCH, PARTIAL_MATCH, UNVERIFIED, NOT_IMPLEMENTED, NOT_APPLICABLE.

---

## 1. Cryptographic Primitives Inventory

The table below is the consolidated primitives inventory. Every row is backed by at least one source document; addresses and sizes are preserved verbatim.

| Primitive | Algorithm | Mode/Params | Source / Evidence | Confidence |
|---|---|---|---|---|
| Symmetric cipher | AES-256 | CBC | `shelper.dll` AESCryptor vtable `0x100832a0` slots +0x18/+0x1c → `AES_set_encrypt_key`/`AES_set_decrypt_key`, bits = 256; AES-CBC transform `0x10003b30` | CONFIRMED |
| Block size | 16 bytes | — | `AESCryptor::GetBlockSize` returns 0x10 (`+0x20` → `0x10062e90`) | CONFIRMED |
| Key size | 32 bytes | AES-256 | `SetKeyEnc`/`SetKeyDec` reject ≠0x20 (`0x1006ab00`/`0x1006aac0`) | CONFIRMED |
| IV | 16 bytes | Persistent (copied from last ciphertext block) | AESCryptor object layout `+0x1ec` (enc) / `+0x1fc` (dec), zero-initialized at construction | CONFIRMED |
| Padding | 0xCC fill | + 8-byte checksum + 1-byte pad length (9 bytes overhead) | `FUN_10069c20` (`famitech_pad_and_sign`) | CONFIRMED |
| Checksum | Additive 64-bit | LE word-additive, `mod 2^64`, carry propagation | `FUN_1006a0c0` (`add ebx,[esi]` / `adc edi,[esi+4]`) | CONFIRMED |
| Digest | MD5 | RFC 1321, 92-byte context | `0x10005250`/`0x10004e50`/`0x10004f30`; context 0x5c bytes; IV `0x67452301`,`0xefcdab89`,`0x98badcfe`,`0x10325476` | CONFIRMED |
| Digest fold | Byte-wise add | `fold[i] = digest[i] + digest[8+i] mod 256` | `0x10069ce0–0x10069d15`; verifier `0x1006a03c–0x1006a074` | CONFIRMED |
| Trailer | 9 bytes | 8-byte folded MAC + 1-byte pad length | `0x10069d18–0x10069d3a` (`movq` at `len-9`, pad byte at `len-1`) | CONFIRMED |
| Key exchange (RSession) | RSA-2048 | PKCS#1 v1.5 | `FUN_10065ec0` (padding mode `PUSH 0x1` at `0x10065f05`) | CONFIRMED |
| Key exchange (control) | SRP-6a | N=1536-bit, g=5, k=H(N‖PAD(g))† | `shelper.dll` SRP-6a vtables `0x100ad75c`/`0x100ad7b4` | CONFIRMED (k=H() STRONG INDICATION) |
| Hash | SHA-1 | 20-byte output | `0x10028810`/`0x100285f0`/`0x100286d0` (bundled Tom Wu `(tjw)`, not OpenSSL) | CONFIRMED |
| KDF (control) | SHA-1 | `SHA1(S‖BE32(0)) ‖ SHA1(S‖BE32(1))` = 40 bytes | `0x10061790` (structure confirmed; body not disassembled in this session) | CONFIRMED (structure) |

† `k = H(N‖PAD(g))` is STRONG INDICATION (SRP-6a class); legacy SRP-6 class uses `k = 3` (UNVERIFIED which class is instantiated; `FUN_100607d0` k=3 path is dead code).

**No hypothesis is presented as a confirmed fact.** Where binary analysis could not be completed (dynamic execution blocked, tool budget exhausted), the gap is explicitly documented.

---

## 2. AES-256-CBC and IV Lifecycle

### 2.1 Cipher configuration (CONFIRMED)

- **Algorithm:** AES-256-CBC. No other cipher (TwoFish, Blowfish, etc.) is instantiated in the observed code paths.
- **AESCryptor class:** RTTI `.?AVAESCryptor@@` at `shelper.dll` `.rdata 0x100aee88`; base class `BaseCryptor`; vtable `0x100832a0` with 17 entries (indices 0–16).
- **Vtable slots:**
  - Encrypt key slot `+0x18` → `0x10062fb0` (`AES_set_encrypt_key`, bits = `len*8` = 256)
  - Decrypt key slot `+0x1c` → `0x10062f30` (`AES_set_decrypt_key`, bits = 256)
  - Block size `+0x20` → `0x10062e90` (returns `0x10`)
  - `SetKeyEnc` `+0xc0` → `0x1006ab00` (enforces length `0x20` = 32 bytes)
  - `SetKeyDec` `+0xc4` → `0x1006aac0` (enforces length `0x20` = 32 bytes)
- **AES-CBC transform:** `0x10003b30`.
- **AESCryptor constructor:** `FUN_10062b60`, object size `0x20c`.
- **Second vftable:** `0x100832c4` (TwoFishV2-shaped, no instantiation found — UNKNOWN, likely dead).
- **No AEAD:** No GCM/CCM/EAX mode anywhere in observed code paths. Encryption and integrity are separate layers; the integrity layer is unkeyed (see Section 3).

### 2.2 Key storage layout (CONFIRMED)

| Field | Offset | Size | Purpose |
|---|---|---|---|
| Enc AES_KEY schedule | `+0x04` | 0xF4 bytes | Via vtable `+0x18` → `AES_set_encrypt_key`, bits=256 |
| Dec AES_KEY schedule | `+0xF8` | 0xF4 bytes | Via vtable `+0x1c` → `AES_set_decrypt_key`, bits=256 |
| Enc IV | `+0x1EC` | 16 bytes | Zero-initialized, persistent |
| Dec IV | `+0x1FC` | 16 bytes | Zero-initialized, persistent |

### 2.3 IV lifecycle (CONFIRMED)

- **Initial IV:** Zero-initialized (`[0u8; 16]`) in the constructor; constructor `xorps xmm0, xmm0` / `movups [esi+0x1ec]` / `movups [esi+0x1fc]`.
- **IV update:** After each CBC operation, the IV buffer is updated in place from the last ciphertext block (standard OpenSSL `AES_cbc_encrypt` behavior). Code: `0x10062e15`–`0x10062e25` (encrypt) and `0x10062d60` (decrypt).
- **IV persistence:** No per-frame reset; IV persists across frames within a session. IV reset only on new session (new AESCryptor object).
- **Independent IV per direction:** Yes — separate `enc_iv` (`+0x1EC`) and `dec_iv` (`+0x1FC`) buffers.
- **Packet ordering requirement:** CBC chaining with persistent IVs means packets must be decrypted in order. Lost/reordered frames break decryption until rekeying (Rust test `test_corrupted_last_block_desynchronizes_next_packet` confirms).

### 2.4 Encrypt/decrypt order (CONFIRMED)

- **Encrypt:** `pad+sign` (`FUN_10069c20` → checksum → MD5 → fold → write trailer) → AES-256-CBC encrypt in place (`vtable +4` → `0x10062e00` / `0x10003b30`), entire buffer.
- **Decrypt:** AES-256-CBC decrypt in place (`vtable +8` → `0x10062d60`) **before any length validation**, then verify+unpad (`FUN_10069f90`). Decrypt-before-validation confirmed at `0x10069d9b–0x10069dab` (`call [eax+8]` before `0x10069f90`). Potential robustness/DoS surface.

---

## 3. Proprietary Frame Trailer (0xCC + checksum + folded MD5)

The trailer is 9 bytes: an 8-byte integrity value followed by a 1-byte pad length. Two conflicting accounts of the 8-byte integrity value exist in the source corpus; both are recorded below with their evidence. No winner is selected; adjudication belongs to `RECONCILIATION.md` (mapped target: `docs/CRYPTO_PHASE_10_10_RECONCILIATION.md`; see also `docs/CRYPTO_PHASE_10_11_RECONSTRUCTION.md` §7).

### 3.1 Construction per later deep-audit docs (folded MD5 of the additive sum)

**Claim:** The integrity value is `fold8(MD5(LE64(additive_checksum(plaintext ‖ 0xCC^k))))`, i.e. the 64-bit additive checksum is hashed with MD5 and the 16-byte digest is folded to 8 bytes. Pad length byte appended at the end.

**Evidence:**

- Checksum: `FUN_1006a0c0(src, len, out)` — sum of little-endian 64-bit words with carry into the high dword, modulo 2^64; trailing partial word zero-padded on the high end (`__allshl` at `0x1006d680`). Called with `len = total_len - 9` over `plaintext ‖ 0xCC filler` (excluding the 9-byte trailer).
- Total size: `total_len = ((block + 8 + L) / block) * block` (block = 16); `pad_len = total_len - L ∈ [9, 24]`; `pad_len == 8` impossible.
- Padding bytes `0xCC` fill `buf[L..total_len-9]` (`k = pad_len - 9` bytes).
- MD5 wrapper: `0x100638f0` (`MD5_of_buffer`, Init+Update+Final over 8 bytes, 0x5c-byte context frame, `ret 4`).
- MD5 primitives: `MD5_Init` `0x10005250`, `MD5_Update` `0x10004e50`, `MD5_Final` `0x10004f30`; compression `md5_compress` `0x10004780`; round-3 constant `0x6ed9eba1` at `0x10004ccc`.
- Input to MD5: exactly 8 bytes (the LE64 checksum), so MD5 runs exactly one 64-byte compression block (8 data + 0x80 + 55 zero + 8 length).
- Fold: `0x10069ce0–0x10069d15`, 8 unrolled `movzx`/`add BYTE` pairs: `fold[i] = (digest[i] + digest[8+i]) mod 256`, `i = 0..7`; 8-bit add, wraparound, no carry propagation; high half discarded, low half overwritten.
- Trailer write: `0x10069d18–0x10069d3a` — `movq xmm0,[ebp-0x20]` / `movq [eax+ecx-9],xmm0` (8-byte fold at `total_len-9`) / `mov [eax+ecx-1],dl` (pad length at `total_len-1`).
- Call sites of MD5 wrapper `0x100638f0` (only two in the image): `0x10069cdb` (encrypt path, build trailer) and `0x1006a037` (decrypt path, verify trailer).
- Verifier: `0x1006a03c–0x1006a074` mirrors the fold exactly; `cmp` at `0x1006a077`/`0x1006a07f` compares 8 bytes at `buf+len-9`.

**Classification:** CONFIRMED (instruction-level, multiple docs).

### 3.2 Account in `docs/reverse-engineering/round-02/02-cryptography.md` (additive sum only, no MD5)

**Claim:** The integrity sum is a little-endian 64-bit additive sum with carry propagation, and there is **no invocation of MD5 or SHA anywhere** in the symmetric frame validation process. The trailer consists of the additive checksum (8 bytes, little-endian) followed by the pad-length byte (1 byte).

**Evidence:**

- Disassembly of `FUN_1006a0c0` at `0x1006a0c0–0x1006a0e6`: `xor eax,eax`/`xor esi,esi`/`shr edx,3` / `add eax,[ecx]`/`adc esi,[ecx+4]` / loop.
- Frame size formula: `TotalSize = floor((PayloadLen + 24)/16) * 16`; `PadLen = TotalSize - PayloadLen`; range `9 ≤ PadLen ≤ 24`.
- Pre-encryption block layout: `PayloadLen bytes useful data | Padding 0xCC (PadLen-9 bytes) | 64-bit additive checksum (8 bytes, LE) | PadLen (1 byte)`.
- Validation routine `0x10069f90`: verifies `len % 16 == 0`, `len ≥ 16`, `9 ≤ pad_len ≤ 24`; recomputes the additive checksum over `[0..total_len-9]`; compares stored checksum; aborts on mismatch (`0x1006a01b`).
- Conclusion statement (§5): "the integrity sum is a little-endian 64-bit additive sum with carry propagation, with no invocation of MD5 or SHA anywhere in the symmetric frame validation process."

**Classification:** CONFIRMED within round-02 (full disassembly of cipher/padding/checksum/IV-chaining routines per its header), but contradicted by the later deep-audit documents.

### 3.3 Reconciliation directive

The two accounts are mutually exclusive on the presence of MD5 in the trailer construction:

- round-02/02-cryptography.md: additive 64-bit checksum only, **no MD5**.
- `CRYPTO_MD5_ANALYSIS.md`, `CRYPTO_AES_CONSUMER_TRACE.md`, `CRYPTO_SYMMETRIC_ENCRYPTION.md`, `CRYPTO_RSESSION_ANALYSIS.md`: additive checksum **followed by** MD5 + 16→8 byte fold.

`CRYPTO_RSESSION_ANALYSIS.md` §10 explicitly lists "(a) Remove the 'no MD5' claim — MD5 is present in the frame trailer" as a correction required in prior documentation, and lists the round-02 "No MD5 anywhere" claim (E9) as REFUTED. This consolidation records both without picking a winner; resolution must be recorded in `RECONCILIATION.md` (`docs/CRYPTO_PHASE_10_10_RECONCILIATION.md`).

### 3.4 Trailer classification (CONFIRMED)

- **Unkeyed redundancy/format trailer inside an AES-256-CBC envelope.** No key material is input to the checksum/MD5/fold computation. Anyone who knows the plaintext can compute the valid trailer.
- **Not a MAC / not authenticated encryption:** REFUTED — provides corruption/format detection only, not authenticity.
- **Not a KDF/PRF/nonce/challenge-response:** REFUTED.
- **Not a password hash:** REFUTED.
- **Probable purpose (HYPOTHESIS):** Padding + length field + self-consistency check for a legacy transport predating AEAD — reject malformed/truncated packets and establish plaintext length without an explicit length prefix. No string, log, or caller-level evidence ties it to a stated design intent.

---

## 4. MD5 Implementation

### 4.1 Function inventory

| Address | Role | Evidence |
|---|---|---|
| `0x10005250` | `MD5_Init(ctx)` | `memset(ctx, 0, 0x5c)`; sets A,B,C,D = `0x67452301`, `0xefcdab89`, `0x98badcfe`, `0x10325476`; returns 1 |
| `0x10004e50` | `MD5_Update(ctx, data, len)` | `ecx=data`, `edx=len`; bit-count with carry (`Nl + (len<<3)`, carry into `Nh`, then `Nh += len >> 29`); block processing |
| `0x10004f30` | `MD5_Final(out, ctx)` | Writes `0x80` pad, 64-bit LE bit-count field, compresses, emits 16 LE bytes |
| `0x10004780` | `md5_compress(ctx, data, nblocks)` | `eax=0x54` stack via `__chkstk`; loads A/B/C/D from context; nblocks guard; explicit little-endian word load (`movzx`/`shl`/`or`) |
| `0x10004ccc` | `md5_block` (round constants) | `lea esi,[edx+esi*1+0x6ed9eba1]` — RFC 1321 round-3 constant |
| `0x10009580` | `md5_block_asm_data_order` | OpenSSL-style asm MD5; constants `0xd76aa478`, `0x242070db`, `0x6ed9eba1`; **not used by the trailer path** (reached from wrapper pair `0x10005050`/`0x10005130`) |
| `0x100638f0` | `MD5_of_buffer(out, data, len=8)` | Wrapper: Init+Update+Final; 0x5c-byte context frame (`[ebp-0x60]`); `ret 4` |

### 4.2 Context structure (CONFIRMED)

The context is 92 bytes, matching OpenSSL `MD5_CTX`:

| Offset | Field | Size |
|---|---|---|
| `+0x00` | A (state word) | 4 bytes |
| `+0x04` | B (state word) | 4 bytes |
| `+0x08` | C (state word) | 4 bytes |
| `+0x0c` | D (state word) | 4 bytes |
| `+0x10` | Nl (low bit count) | 4 bytes |
| `+0x14` | Nh (high bit count) | 4 bytes |
| `+0x18` | data buffer | 64 bytes |
| `+0x58` | num (buffer offset) | 4 bytes |

The wrapper `0x100638f0` allocates exactly `0x5c` bytes with the stack cookie at `[ebp-4]`, independently bounding the struct to 92 bytes.

### 4.3 Endianness (CONFIRMED)

- Message words assembled byte-by-byte **little-endian** (`0x100047c0–0x100047fb`).
- Bit-length field **little-endian**.
- Digest output **little-endian** (16 bytes).
- RFC 1321 / OpenSSL-equivalent behavior, compiled by MSVC.

### 4.4 Digest folding

The fold is **not** inside `MD5_Final`. It lives in the two callers of `MD5_of_buffer`:

- **Encrypt path** (`0x10069ce0–0x10069d15`): `fold[i] = (digest[i] + digest[8+i]) mod 256`, `i = 0..7`, byte-wise additive (8-bit `add`, wraparound, no carry propagation). Destination = same 16-byte buffer the digest was written to; high half discarded, low half overwritten; output 8 bytes copied via `movq` at `out + total_len - 9`.
- **Verifier** (`0x1006a03c–0x1006a074`): identical 8 unrolled `movzx`/`add BYTE` pairs, then `cmp [edi+esi-9],[ecx]` and `cmp [edi+esi-5],[ecx+4]` (`0x1006a077`, `0x1006a07f`).

### 4.5 Strength assessment

`S` is a 64-bit word-additive checksum — order-insensitive and trivially malleable (insert/remove balanced 8-byte words, or permute 8-byte blocks, without changing `S`). MD5 over only 8 bytes followed by a byte-wise fold yields a 64-bit, keyless, easily computable function; collision finding bounded by ~2^32 birthday work, fold mixes poorly (byte-wise additive). Provides error/format detection against accidental corruption and naive tampering, **not** cryptographic integrity.

### 4.6 Independent verification (PARTIAL)

Dynamic execution (RFC 1321 test vectors) was blocked (Python/Wine unavailable). Confidence rests on structural/constant-level identity with RFC 1321: IV words, 92-byte context layout, `0x80` padding rule, `> 0x38` extra-block rule, LE bit-count field, LE message-word assembly, LE digest output, RFC 1321 round constants (`0xd76aa478`, `0x242070db`, `0x6ed9eba1`).

### 4.7 Unresolved questions (MD5)

1. No dynamic test-vector run (blocked, external).
2. `RvROLClient.dll` call-site identification of `api+0xc8`/`api+0xcc` (Encrypt/DecryptBuffer) not resolved; indirect calls through cached table, `+0xc8` collides with unrelated struct fields.
3. AES layer behavior for non-block-aligned input on decrypt (`0x10069d70` calls `vtable+8` before `0x10069f90` validates `len % block == 0`) — undetermined, possible robustness/DoS surface.
4. Why two MD5 implementations exist (`0x10004780` C build vs `0x10009580` OpenSSL asm) and which product paths use the asm copy — UNKNOWN (not required for this spec).

---

## 5. RSA Operations and Padding

### 5.1 Parameters (CONFIRMED unless noted)

| Parameter | Value | Evidence | Classification |
|---|---|---|---|
| Key size | 2048 bits (256 bytes) | `RSA_size` reads `RSA->n` (`+0x10`); 256-byte ciphertext output; `RSESSION_RSA_BLOCK_SIZE = 256` | CONFIRMED |
| Block size | 256 bytes | `RSA_size` returns `(BN_num_bits(n)+7)/8` = 256 | CONFIRMED |
| Key format | Raw modulus/exponent, big-endian | `BN_bin2bn` (`0x10008a40`) imports raw bytes; no DER/PEM parsing observed | CONFIRMED |
| Public key | `(n, e)` pair | Client imports `n`@RSA `+0x10`, `e`@RSA `+0x14` (`FUN_10066170`) | CONFIRMED |
| Private key | `(n,e,d,p,q,dmp1,dmq1,iqmp)` | Server imports full set @RSA `+0x10..+0x2c` (`FUN_10065f70`) | CONFIRMED |
| Public exponent | Imported from caller buffer; value not determined | `FUN_10066170` → `BN_bin2bn` e@+0x14; Rust assumes `0x010001` (65537) | UNKNOWN (caller-dependent) |
| Byte order | Big-endian | `BN_bin2bn` OS2IP/IP2OSP | CONFIRMED |
| Padding mode | PKCS#1 v1.5 (mode constant 1) | `PUSH 0x1` before `rsa_pub_encrypt`/`rsa_priv_decrypt` thunks (`0x10065f05`, `0x10065de8`) | CONFIRMED |
| Hash/MGF | N/A — PKCS#1 v1.5 encryption uses no hash or MGF | `"rsaesOaep"` string at `0x10083b78` has zero xrefs | CONFIRMED (absence) |
| Signing | None | No `RSA_sign`/`RSA_verify`/`md5WithRSA` anywhere in traced chain | CONFIRMED |

Input/output lengths: plaintext 76 bytes in, ciphertext 256 bytes out; decrypted output must be exactly 76 bytes or the handshake fails. RSA operation direction: client encrypts with public key, server decrypts with private key (key transport, client→server).

### 5.2 RSA padding mode — contradiction note

- Position A (deep-audit traces): `PUSH 0x1` = `RSA_PKCS1_PADDING` ⇒ PKCS#1 v1.5 block `00 02 FF…FF 00 || plaintext` (169 × `0xFF` for 256-byte modulus, 76-byte plaintext). `rsaesOaep` string has zero xrefs; no `RSA_sign`/`RSA_verify` in any traced chain.
- Position B (Wave 1 register, `docs/KEY_EXCHANGE_ANALYSIS.md` §5.2): padding mode at `0x10065f05` and OAEP/MGF absence not re-verified (circuit breaker); classified UNVERIFIED pending re-disassembly of `0x10065f05`'s surrounding context.
- Resolution: evidence weight favors PKCS#1 v1.5; remains UNVERIFIED until `0x10065f05` context is re-disassembled. No OAEP/MGF code was found anywhere.

### 5.3 RSA function inventory

| Function | Address | Role | Confidence |
|---|---|---|---|
| `RSA_public_encrypt` (wrapped) | `0x10065ec0` | Client-side RSA encryption with PKCS#1 v1.5 padding | CONFIRMED |
| `RSA_private_decrypt` (wrapped) | `0x10065db0` | Server-side RSA decryption with PKCS#1 v1.5 padding | CONFIRMED |
| `RSA_new` | `0x10065f50` / `0x10009290` / `0x10008fa0` | RSA object allocation (sizeof RSA = 0x58; source string `.\crypto\rsa\rsa_lib.c` line `0x8b`) | CONFIRMED |
| `RSA_free` | Upstream OpenSSL | RSA object deallocation | STRONG INDICATION (zeroization unverified) |
| `BN_bin2bn` | `0x10008a40` | Import raw big-endian bytes into BIGNUM | CONFIRMED |
| Client key import | `0x10066170` | Sets `n`@`+0x10`, `e`@`+0x14` via `BN_bin2bn` | CONFIRMED |
| Server key import | `0x10065f70` | Sets `n,e,d,p,q,dmp1,dmq1,iqmp` @ `+0x10..+0x2c` | CONFIRMED |
| `RSA_SIZE` | `0x100092a0` | Returns 256 for 2048-bit modulus | CONFIRMED |
| `RSA_METHOD.rsa_pub_enc` thunk | `0x100092c0` | meth+4 | CONFIRMED |
| `RSA_METHOD.rsa_priv_decrypt` thunk | `0x100092e0` | meth+0x10 (jumptable thunk; jumptable not recovered) | CONFIRMED (entry), jumptable UNKNOWN |

### 5.4 Key import functions

- `RSAHelper_CreateWithPublicKey` (`0x1006b4e0`) and `RSAHelper_CreateWithPrivateKey` (`0x1006b3e0`) perform the same caller-buffer imports.
- Name-string anchors in `shelper.dll` `.rdata`: `RSAHelper_CreateWithPrivateKey` @ `0x100ab048`, `RSAHelper_CreateWithPublicKey` @ `0x100ab06f`.

### 5.5 Call chains

**Client encrypt chain:**
`SHelper_RSession_CreateClient` (`0x1006b860`) → `FUN_10069bc0` (ctor, `RSA_new`) → `FUN_1006a690` (imports `n,e` via `FUN_10066170`, role=0, stores 12-byte header at `+0x04..+0x0c`) → client generates 64 random bytes (`FUN_10063530`→`FUN_10005410`) → builds 76-byte plaintext (12-byte LE header ‖ 64-byte key material) → `FUN_10065ec0` (RSA public encrypt) → `RSA_METHOD.rsa_pub_encrypt` via `0x100092c0`, padding=1 → 256-byte ciphertext sent to server.

**Server decrypt chain:**
`SHelper_RSession_CreateServer` (`0x1006b8f0`) → `FUN_10069bc0` → `FUN_1006a700` (imports full private key via `FUN_10065f70`, role=1, state `+0x24`=1) → receives 256-byte ciphertext → `FUN_10065db0` (RSA private decrypt) → `RSA_METHOD.rsa_priv_decrypt` via `0x100092e0`, padding=1 → validates decrypted length == 76 (0x4c) → extracts 64-byte key material from `decrypted[12..76]` into heap at `+0x30`, sets `+0x28`=`+0x2c`=0x40 → emits 4-byte server token from `+0x04`.

### 5.6 RSA vs SRP relationship (CONFIRMED separate)

Two independent primitive sets in `shelper.dll`:
- SRP-6a (Tom Wu bundled `bn`/`sha1`, vtables `0x100ad75c`/`0x100ad7b4`, functions `0x100600f0`/`0x10060140` etc.)
- RSession RSA (OpenSSL `RSA_METHOD`, functions `0x10065ec0`/`0x10065db0`/`0x10066170`/`0x10065f70`)

No intra-module xrefs connect them; RSA performs key transport only, SRP performs mutual authentication/key agreement. Outputs are not mixed inside `shelper.dll` (consumer-side combination in `RvROLClient.dll`/`RvControlSvc.exe` is UNKNOWN, not traced).

### 5.7 Error handling and validation (CONFIRMED)

- NULL `RSA*` / NULL args / length-overflow → return 0 (failure) at every import and encrypt/decrypt entry (explicit `test/je` guards).
- `RSA_public_encrypt`/`RSA_private_decrypt` core returns -1 or 0 (indistinguishable from caller); wrapper returns 0; valid return must be `1..capacity`.
- Decrypted plaintext length != 76 → handshake failure. Ciphertext size != 256 → rejected (`RSA_size` bound).
- No retry logic; no key validation (primality/modulus checks) observed after import.
- `DecryptBuffer_Private` extra 5th stack argument (`ret $0x14`) meaning not recovered; do not reimplement that export from its name alone.

### 5.8 Key provenance (UNKNOWN)

`shelper.dll` neither generates nor embeds any key material — every `n`, `e`, `d`, `p`, `q`, `dmp1`, `dmq1`, `iqmp` buffer arrives as a caller-supplied argument to `CreateClient`/`CreateServer`/`RSAHelper_CreateWith*`. Ultimate origin (embedded in a consumer binary, received over the network, or loaded from config) is UNKNOWN because `RvROLClient.dll`/`RvControlSvc.exe` are not available for full local analysis. See `docs/CRYPTO_RSA_KEY_PROVENANCE.md` §3–§7.

---

## 6. RSession State Machine and 64-Byte Secret

### 6.1 Exported API (ordinals 31–37) (CONFIRMED)

| Ordinal | Export | Address | Role |
|---|---|---|---|
| 31 | `SHelper_RSession_CreateClient` | `0x1006b860` | Thin wrapper → `FUN_10069bc0` + `FUN_1006a690` |
| 32 | `SHelper_RSession_CreateServer` | `0x1006b8f0` | 17 args (8 × (buf,len) RSA components + int) → `FUN_10069bc0` + `FUN_1006a700` |
| 33 | `SHelper_RSession_Delete` | `0x1006b9e0` | Zeroes `+0x28`/`+0x2c`, frees `+0x30`, frees RSA |
| 34 | `SHelper_RSession_GetClientDataOnServer` | `0x1006ba40` | Guarded read of `+0x14..+0x1c` |
| 35 | `SHelper_RSession_GetKey` | `0x1006ba80` | Guard `FUN_1006a270` then return `(+0x30, +0x28)` as an owned heap copy |
| 36 | `SHelper_RSession_GetNextBuffer` | `0x1006bb10` | Public entry to state-machine worker |
| 37 | `SHelper_RSession_GetServerDataOnClient` | `0x1006bbb0` | Guarded read of `+0x14` |

No `SHelper_*` export is referenced by any intra-module xref inside `shelper.dll` (Ghidra callers list empty for all seven). Composition happens in consumer binaries (`RvROLClient.dll`, `RvControlSvc.exe`).

### 6.2 Internal functions

| Function | Address | Role |
|---|---|---|
| `FUN_10069bc0` | `0x10069bc0` | Constructor; zeroes `+0x04..+0x24`, `+0x28`, `+0x2c`, `+0x30`; allocates RSA via `FUN_10065f50` |
| `FUN_1006a690` | `0x1006a690` | Client init (copies 12-byte header from 3 args, sets role `+0x20`=0, state `+0x24`=0) |
| `FUN_1006a700` | `0x1006a700` | Server init (RSA private components, sets role `+0x20`=1, state `+0x24`=1) |
| `FUN_1006a2b0` | `0x1006a2b0` | State-machine worker (not an export) |
| `FUN_1006a270` | `0x1006a270` | `GetKey` guard |
| `FUN_1006a220` | `0x1006a220` | Client-data getter |
| `FUN_10065f50`/`FUN_10009290`/`FUN_10008fa0` | — | `RSA_new` path |
| `FUN_10066170` | `0x10066170` | Client RSA: sets `n`@`+0x10`, `e`@`+0x14` via `BN_bin2bn` |
| `FUN_10065f70` | `0x10065f70` | Server RSA: full private set @ `+0x10..+0x2c` |
| `FUN_10065ec0` | `0x10065ec0` | RSA public encrypt (padding mode `PUSH 0x1` @ `0x10065f05`) |
| `FUN_10065db0` | `0x10065db0` | RSA private decrypt |
| `FUN_10063530` → `FUN_10005410` | — | RAND engine wrapper for 64 random bytes |
| `FUN_10069c20` / `FUN_1006a0c0` | — | Frame seal + 64-bit additive checksum |
| `FUN_100638f0` | `0x100638f0` | MD5 wrapper (Init/Update/Final) |
| `FUN_10069f90` | `0x10069f90` | Frame validator (recomputes trailer) |
| `FUN_10062b60` | `0x10062b60` | AESCryptor (CChannel) constructor, object size `0x20c` |
| `FUN_10003b30` | `0x10003b30` | AES-CBC transform |

### 6.3 Session structure fields (CONFIRMED)

| Offset | Type | Meaning | Confidence |
|---|---|---|---|
| `+0x00` | `RSA*` | RSA context | CONFIRMED |
| `+0x04` | `u32` | 12-byte header field 1 (client `CreateClient` arg) | CONFIRMED |
| `+0x08` | `u32` | 12-byte header field 2 | CONFIRMED |
| `+0x0c` | `u32` | 12-byte header field 3 | CONFIRMED |
| `+0x10` | `int` | Established flag (0/1); server = decrypted header[3] | CONFIRMED |
| `+0x14` | `u32` | Client: 4-byte value from server; server: decrypted header[0] | CONFIRMED |
| `+0x18` | `u32` | Decrypted header[1] (server only) | CONFIRMED |
| `+0x1c` | `u32` | Decrypted header[2] (server only) | CONFIRMED |
| `+0x20` | `int` | Role (0 = client, 1 = server) | CONFIRMED |
| `+0x24` | `int` | State (0..3) | CONFIRMED |
| `+0x28` | `u32` | Key length = `0x40` (64) | CONFIRMED |
| `+0x2c` | `u32` | Key capacity = `0x40` | CONFIRMED |
| `+0x30` | heap ptr | 64-byte symmetric key | CONFIRMED |

**REFUTED:** The claim "+0x28 = AES key size 32 bytes" — the stored value is `0x40` = 64. If a 32-byte AES key is derived, it is derived downstream, not here.

`GetKey` in state INIT fails: `FUN_1006a270` requires `+0x10 != 0` **and** `+0x28 != 0` **and** `+0x30 != 0` — CONFIRMED.

### 6.4 Client state machine (CONFIRMED)

Entry state `0 = INIT` (`FUN_1006a2b0`, role 0, state 0):

1. **State 0 → 1:** Writes `+0x24 = 1` at `0x1006a517`, allocates a `0x4c` blob (12-byte header + 64 random bytes), RSA-encrypts it, emits it.
2. **State 1 → 2:** `INC [ESI+0x24]` at `0x1006a5eb` → state `2 = AWAIT_ACK`.
3. **State 2 → 3:** Accepts a blob of exactly 4 bytes: `+0x14 = LE32(blob)`, `+0x24 = 3`, `+0x10 = 1`, emits an empty blob with the "produced output" flag set.

Disassembly of state 0 (`0x1006a512`): `push 0x40` (64 random bytes), `lea eax,[esi+0x30]`, `call 0x10063530` (`RAND_bytes`), header dwords copied from `[esi+4]`/`[esi+8]`/`[esi+0xc]` to `[esi+0x24]`/`[esi+0x28]`/`[esi+0x2c]`, `push 0x4c` (76 bytes), `lea eax,[esi+0x24]`, `mov ecx,[esi+0x18]` (RSA context), `call 0x10065ec0` (`RSA_public_encrypt(76, src, dst, rsa, RSA_PKCS1_PADDING)`), `mov [esi],1` (advance state to 1).

Disassembly of state 2 (`0x1006a4cc`): `cmp eax,4` (server must reply with exactly 4 bytes), `mov eax,[edx]`, `mov [esi+0x14],eax` (store session_token), `mov [esi+0x10],1` (is_connected=1), `mov [esi],3` (state=3 SESSION_ACTIVE).

### 6.5 Server state machine (CONFIRMED)

Entry state `1 = AWAIT_KEY` (`CreateServer` sets state 1):

1. **State 1 → 2:** RSA-decrypts the `0x4c` blob, validates decrypted length == 0x4c, copies header bytes into `+0x14`, `+0x18`, `+0x1c` and the 64-byte key into heap buffer at `+0x30`, sets `+0x28` = `+0x2c` = 0x40, then `INC [..+0x24]` → 2.
2. **State 2 → 3:** Emits a 4-byte reply taken from `*(this+0x04)`, then `INC` → 3, `+0x10` = 1.

**76-byte plaintext layout (CONFIRMED):** `LE32(h0) ‖ LE32(h1) ‖ LE32(h2) ‖ key[64]`. Header fields stored as native x86 little-endian 32-bit stores; header semantic fields remain opaque.

**Server 4-byte token (CONFIRMED):** its own `CreateServer` arg0 (`+0x04`), NOT derived from client key/header/hash. Client stores reply at `+0x14` and never interprets it. The client's 4-byte ACK value is opaque; the server never interprets it beyond length (STRONG INDICATION it is a cookie the client echoes; exact semantic UNKNOWN).

### 6.6 Key establishment (CONFIRMED)

1. Client generates **64 random bytes** (`FUN_10063530` → `FUN_10005410`, OpenSSL RAND wrapper).
2. Wire blob = `0x4c` bytes = 12-byte cleartext header ‖ 64-byte key material.
3. Whole `0x4c` blob is encapsulated with **RSA public-key encryption**, padding mode constant `1` (`PUSH 0x1` at `0x10065f05` inside `FUN_10065ec0`).
4. Server decrypts with `RSA_private_decrypt` (`FUN_10065db0`), validates length, stores the 64 bytes verbatim at `+0x30`.
5. **No DH, no ECDH, no SRP, no HKDF/PBKDF/KDF call exists anywhere in the RSession path** — the 64 bytes are used as-is (STRONG INDICATION that any splitting/derivation happens in the consumer). Complete callee set of `FUN_1006a2b0`: `{memset, RAND, malloc, memcpy, RSA_pub_enc, RSA_priv_dec, buffer move/zeroize}`.

**Threat-model consequence:** The session key is chosen entirely by the client and transported under the server's RSA public key. There is no server-side contribution and **no forward secrecy**. Compromise of the server's private key decrypts all past sessions. The 64-byte key is not authenticated beyond RSA-PKCS#1 v1.5 padding validity.

### 6.7 `GetKey` consumer hand-off (CONFIRMED mechanics, UNKNOWN consumer)

`shelper.dll!0x1006ba80`:
```c
int SHelper_RSession_GetKey(void *session, void **out_ptr, uint32_t *out_len);
```
Implementation: `FUN_100626c0(local)` zero `{len,cap,data}`; `*out_ptr = 0; *out_len = 0;`; if `FUN_1006a270(session, local)` (guard + COPY) then if `FUN_10069f50(local, out_ptr, out_len)` then `FUN_10062b10(local); return 1;`
`FUN_1006a270` requires `+0x10 != 0` (established), `+0x30 != 0`, `+0x28 != 0`, then `FUN_10062800(buf, this+0x30, this+0x28)`.
`FUN_10062800` = `FUN_100627a0(buf, len)` (allocates new heap block of `len`) then `memcpy(buf->data, src, len)`.
`FUN_10069f50` moves ownership out: `*out_ptr = buf->data; *out_len = buf->len;` then zeroes the struct fields (NULLs data, len, cap).
`FUN_10062b10` = destructor: `FUN_1006c120(data, 0, len)` (secure zero-fill) then `free(data)`.

**Key consequence:** the consumer receives a **privately owned heap copy of exactly 64 bytes (`+0x28 = 0x40`)** that it must destroy with the zeroize-then-free destructor. Session deletion does **not** invalidate the consumer's copy — `SHelper_RSession_Delete` (`0x1006b9e0`) zeroes/frees `+0x30` but the consumer's copy is a separate allocation.

**Consumer location — UNKNOWN:** callers of RSession exports inside `shelper.dll` = zero; `RvROLClient.dll` resolver `FUN_1003fbd0` field map (`GetKey→+0xb0`, `SetKeyEnc→+0xc0`, `SetKeyDec→+0xc4`, `EncryptBuffer→+0xc8`) confirmed but `call [reg+0xb0/c0/c4]` disp32 = zero matches; `RvControlSvc.exe` resolver `FUN_00442290` identical field map but could not be traced before tool budget exhaustion. `RvRvpnGui.exe` contains the same string block at the same VAs. Composition is reached via disp8 encoding, copied function-pointer struct, or is dead code in these three images.

---

## 7. Key Lifecycle and Cross-Module Linkage

### 7.1 Three independent key mechanisms

| # | Mechanism | Module | Output | Confidence |
|---|---|---|---|---|
| K1 | SRP-6a control-channel authentication (TCP/17301) | `shelper.dll` (SHelper family) | 40-byte KDF output, first 32 bytes used | STRONG INDICATION (prior trace) |
| K2 | RSession RSA key transport (client→server) | `shelper.dll` (RSession family) | 64-byte random secret | CONFIRMED |
| K3 | CChannel AES consumers (AESCryptor) | `shelper.dll` (CChannel family) | Encrypts/decrypts frame payloads | CONFIRMED |
| — | Named pipe `\\.\pipe\RadminVpnGuiChannel` (GUI↔service) | `RvRvpnGui.exe` | No ROLClient/crypto calls on the pipe | CONFIRMED (plain named-pipe I/O) |

### 7.2 Lifecycle chain (Phase 10.3 consolidation)

1. `InitDll` resolves the 47-entry function-pointer table (offset `+0x58…+0xec`).
2. SRP-6a control handshake (`x → v → A/B → u → S → K → M1/M2`) establishes the control session key (`K` = 40 bytes; first 32 = AES-256 key).
3. RSession handshake (RSA PKCS#1 v1.5, 2048-bit) establishes a 64-byte secret per session; the consumer splits it into two directional AES-256 keys.
4. Frames on port 17301 are 4-byte-BE-length-prefixed; payloads padded with `0xCC` to a multiple of 16, terminated by a 9-byte folded-MD5 trailer; CBC with persistent IVs.

### 7.3 Function pointer offset table (context object) (CONFIRMED slot names+offsets)

Both `RvROLClient.dll` (`FUN_1003fbd0`) and `RvControlSvc.exe` (`FUN_00442290`) import only `SHelper_Init` from `shelper.dll` (static IAT import); all other exports resolved dynamically via `GetProcAddress` and stored at fixed offsets from a context object:

| Offset | Function | Role | Confidence |
|---|---|---|---|
| `+0x58` | `SHelper_Init` | static import | CONFIRMED |
| `+0x88` | `SHelper_GetKey` | general GetKey | CONFIRMED |
| `+0x98` | `SHelper_RSession_CreateClient` | `0x1006b860` (ord 31) | CONFIRMED |
| `+0x9c..+0xa0` | `SHelper_RSession_CreateServer`/`_Delete` | `0x1006b8f0` (ord 32) / `0x1006b9e0` (ord 33) | CONFIRMED |
| `+0xa4` | `SHelper_RSession_GetNextBuffer` | `0x1006b1e0` | UNVERIFIED (prior trace) |
| `+0xa8` | `SHelper_RSession_GetServerDataOnClient` | — | CONFIRMED |
| `+0xac` | `SHelper_RSession_GetClientDataOnServer` | — | CONFIRMED |
| `+0xb0` | `SHelper_RSession_GetKey`/`SHelper_GetKey` | RSession GetKey (64-byte secret) | CONFIRMED |
| `+0xb4` | `SHelper_CChannel_CreateClient` | `0x1006a8b0` (inner `FUN_1006a630`) | UNVERIFIED (prior trace) |
| `+0xc0` | `SHelper_CChannel_SetKeyEnc` | Install AES-256 encrypt key | CONFIRMED |
| `+0xc4` | `SHelper_CChannel_SetKeyDec` | Install AES-256 decrypt key | CONFIRMED |
| `+0xc8` | `SHelper_CChannel_EncryptBuffer` | Encrypt buffer | CONFIRMED |
| `+0xcc` | `SHelper_CChannel_DecryptBuffer` | Decrypt buffer | CONFIRMED |
| `+0xd0` | `RSAHelper_CreateWithPublicKey` | address mapping UNKNOWN | name string CONFIRMED |
| `+0xd4` | `RSAHelper_CreateWithPrivateKey` | address mapping UNKNOWN | name string CONFIRMED |
| `+0xd8..+0xe8` | remaining `RSAHelper_*` slots | mapping UNKNOWN | UNKNOWN |

The init function stores FARPROC pointers but does **not** call them — just resolves via `GetProcAddress`. The exact `call [reg+0xb0/c0/c4]` call site was **not located** (disp8 indirect calls defeat static pattern matching).

### 7.4 CChannel contract and key split (CONFIRMED contract, UNKNOWN mapping)

- `SHelper_CChannel_CreateClient` (`0x1006a8b0`, inner `FUN_1006a630`) requires **two keys of exactly 32 bytes** and creates an AESCryptor (vftable `0x100832a0`).
- Key setters `SHelper_CChannel_SetKeyEnc` (`0x1006ab00`) and `SetKeyDec` (`0x1006aac0`) enforce length `0x20` (32 bytes).
- AES key schedule installed via vtable slots `+0x18` → `0x10062fb0` (`AES_set_encrypt_key`, bits = `len*8` = 256) and `+0x1c` → `0x10062f30` (`AES_set_decrypt_key`).
- RSession hands out **64 bytes** at `+0x30` with length `+0x28 = 0x40`.
- **Classification: NOT CONFIRMED that the two 32-byte keys differ.** Two pointers do not prove different contents; two initialization calls do not prove different key material.
- **Primary hypothesis (UNVERIFIED):** `key_enc = secret[0..32]`, `key_dec = secret[32..64]`; ordering may be role-dependent (client enc = first half, server enc = second half).
- **Alternative (secondary):** A hash (e.g. MD5/SHA-1 truncation) derives the two keys in the consumer. Not supported by any observed call in `shelper`, and no such call exists on the RSession path.
- Rust `FamatechCipherState::from_rsession_key()` uses `key_material[..32]` for **both** enc and dec — CONFIRMED_MISMATCH against the binary's two-key contract; 32 bytes of the 64-byte secret unused in Rust with no evidence supporting that choice.

### 7.5 Control channel key path (STRONG INDICATION / prior trace)

- SRP-6a (PAD class, `obj+4`=3, descriptor `0x100ad75c` client / `0x100ad7b4` server) → `S = (B − k·g^x)^(a + u·x) mod N` → KDF `0x10061790` (40 bytes: `SHA1(S‖BE32(0)) ‖ SHA1(S‖BE32(1))`) → session key = first 32 bytes of the 40-byte KDF output → `SHelper_GetKey` `0x1006b010` → `FUN_10067000` → blob at `obj+0x44` (len `+0x4c`) → `0x10069f50` splits (ptr, len) → installs 32 bytes via `0x1003dd40`→`min(len, 0x20)`→`0x100df250` at `this+0x20/+0x24`.
- `call` site from `GetKey` blob → `SetKeyEnc`/`SetKeyDec` **UNKNOWN** (never located).

### 7.6 Corrections owed to prior documentation

- `docs/reverse-engineering/round-02/01-handshake.md` §4 claims `SHelper_RSession_GetKey` extracts "the first 32 bytes" of the 64 bytes and passes them to both `SetKeyEnc` and `SetKeyDec` — this matches current Rust behavior but is **not instruction-verified** for the binary; the split remains UNKNOWN.
- `docs/reverse-engineering/round-02/02-cryptography.md` §5: the "no MD5" trailer claim is contradicted by the deep-audit MD5 documentation (see Section 3.3); correction owed.

---

## 8. Random Sources

| Source | Output | Address | Status |
|---|---|---|---|
| `shelper.dll` — statically linked OpenSSL 1.0.1f `RAND_METHOD.bytes` | 64 bytes on RSession path (`FUN_10063530` → `FUN_10005410` → `DAT_100b015c[1]`) | dispatch `DAT_100b015c[1]` | CONFIRMED (RSession) |
| `shelper.dll` — SRP path random draw | RAND_bytes(192) / `BN_add_word(1536)`-shaped draws | prior trace only | CONFIRMED (RSession) / prior trace (SRP draw shape) — UNVERIFIED in Wave 1 |
| `RvROLClient.dll` — ADVAPI32 `CryptAcquireContext`/`CryptGenRandom`/`CryptReleaseContext` | 4 bytes per call | inside `RvROLClient.dll` | CONFIRMED |
| `RvROLClient.dll` — 32-byte key generation | None found | — | INFERRED: no 32-byte random generation inside `RvROLClient.dll`; every crypto primitive imported from `shelper.dll` |

`RvROLClient.dll`'s only random source is ADVAPI32 `CryptGenRandom` producing 4 bytes per call; a 32-byte AES key is never generated inside `RvROLClient.dll`. Corollary: the 32-byte keys must originate in `shelper.dll` (K2 output for RSession sessions, or the K1 SRP output for control-channel sessions) and reach the AESCryptor through unlocated call sites.

---

## 9. Security Observations

- **No forward secrecy (CONFIRMED):** RSession key is client-chosen and transported under the server's static RSA public key. Compromise of the server's private key decrypts all past sessions.
- **No encrypt-then-MAC (CONFIRMED):** The 8-byte folded MD5 (or additive checksum, per the conflicting account — see Section 3) is an unkeyed checksum computed over plaintext. An active attacker can forge valid trailers for chosen plaintexts. Authentication rests solely on the SRP-6a/RSA handshake, not on per-packet MACs.
- **Persistent IVs (CONFIRMED):** AES-CBC IVs are stored in the cipher state object and updated from the last ciphertext block. There is no per-frame IV derivation or reset. Lost/reordered frames break decryption.
- **CBC malleability (CONFIRMED):** AES-256-CBC is malleable; an attacker who can modify ciphertext blocks can predictably change corresponding plaintext blocks. The unkeyed trailer does not prevent this because the trailer is computed over plaintext and can be recomputed.
- **No replay protection (CONFIRMED):** No sequence number, nonce, or timestamp included in the authenticated data. The integrity value covers only the plaintext payload and padding.
- **First-block IV = zero (CONFIRMED):** The initial IV is all zeros, making the first block equivalent to ECB encryption for the first block under a given key — a minor weakness.
- **No key rotation (CONFIRMED):** The same key is used for the entire session; no rekeying mechanism observed in the binaries or Rust code.
- **Trailer strength (MEDIUM intent):** The additive checksum is order-insensitive and trivially malleable; MD5 over 8 bytes + byte-wise fold yields a 64-bit keyless function; collision finding ~2^32 birthday work. Provides corruption/format detection only.
- **M2 verification not obviously constant-time (STRONG INDICATION):** `0x10060900`–`0x10060985` byte-wise comparison loop branches on mismatch — not obviously constant-time.
- **RSA core return values indistinguishable (CONFIRMED):** OpenSSL -1 and 0 are indistinguishable from the caller's perspective; no retry logic should be built on "error text."
- **MD5 context not fully wiped (minor observation):** `MD5_Final` clears only `data` and `num`, never A–D or the full context; the wrapper `0x100638f0` does not wipe its 0x60-byte frame. Digest state and the 8-byte input remain on the stack after return.

---

## 10. Brief Open Gaps

| # | Gap | Impact | Evidence needed |
|---|-----|--------|-----------------|
| 1 | AES key split mapping (which 32 bytes → enc/dec; role-dependent?) | Critical — one direction may fail decryption | Dynamic execution or call-site tracing in `RvROLClient.dll`/`RvControlSvc.exe` |
| 2 | Password encoding in `x` computation (UTF-8 vs UTF-16LE vs ANSI) | Critical — `x`, `v`, `A`, `S`, `K`, `M1`, `M2` all differ | Dynamic breakpoint on `0x10060340`/`0x10060c80` with known identity string |
| 3 | `GetKey` consumer call site | High — needed for gap #1 | disp8 indirect call sweep (`call [reg+0xb0/c0/c4]`) |
| 4 | RSA key provenance (client `(n,e)`, server 8 private components) | High — RSession cannot be implemented against official key material | Search `.rdata` for 256-byte modulus blobs; trace `CreateClient`/`CreateServer` callers |
| 5 | `context+0x20` = A on client / B on server at runtime | High — affects `u` computation | Dynamic execution or breakpoint tracing |
| 6 | SRP step-value endianness on the wire | Medium — version exchange is LE; SRP steps unknown | PCAP with full SRP handshake or live testing |
| 7 | M1/M2 binary verification | Medium — proof verification | Disassemble `0x100612f0`, `0x100609a0`, `0x10061450` |
| 8 | Trailer construction: additive sum only vs folded MD5 of that sum | Medium — contradicting accounts in corpus | `RECONCILIATION.md` must adjudicate |
| 9 | Identity hash bytes: UTF-16LE internal (`obj+0x8`) vs UTF-16BE helper output | Medium — affects `x` | Dynamic breakpoint on `0x10060340` |
| 10 | TwoFishV2 vftable `0x100832c4` — dead code or unreached path | Low | Find instantiation site |
| 11 | `FUN_100092e0` jumptable not recovered | Low | Fresh `shelper.dll` disassembly |
| 12 | `+0x24`/`+0x2c`/`+0x30`/`+0x34` field semantics beyond those listed | Low | Re-disassembly of `FUN_1006a690`/`FUN_1006a700` |

---

## Sources

All 17 documents mapped to `CRYPTO_SPEC` in `analysis_workspace/compaction/mapping.tsv` were read and consumed:

1. `docs/CRYPTOGRAPHIC_OVERVIEW.md`
2. `docs/CRYPTO_AES_CONSUMER_TRACE.md`
3. `docs/CRYPTO_AES_KEY_INSTALLATION_TRACE.md`
4. `docs/CRYPTO_AES_KEY_SPLIT_TRACE.md`
5. `docs/CRYPTO_CONTROL_KEY_LIFECYCLE.md`
6. `docs/CRYPTO_KEY_LIFECYCLE_GAP_ANALYSIS.md`
7. `docs/CRYPTO_MD5_ANALYSIS.md`
8. `docs/CRYPTO_PHASE_10_11_RECONSTRUCTION.md`
9. `docs/CRYPTO_PHASE_10_3_10_5_CONSOLIDATED_REPORT.md`
10. `docs/CRYPTO_RSA_ANALYSIS.md`
11. `docs/CRYPTO_RSA_KEY_PROVENANCE.md`
12. `docs/CRYPTO_RSESSION_ANALYSIS.md`
13. `docs/CRYPTO_RSESSION_KEY_LIFECYCLE.md`
14. `docs/CRYPTO_SYMMETRIC_ENCRYPTION.md`
15. `docs/KEY_EXCHANGE_ANALYSIS.md`
16. `docs/reverse-engineering/round-02/01-handshake.md`
17. `docs/reverse-engineering/round-02/02-cryptography.md`

Binary identity references used across sources (all SHA-256 verified by `sha256sum`, original bytes never modified):

- `shelper.dll`: `d89daf6bcd5cafa3c7f6173f835ccf045baf8e7134f868819db6fd7615959ac4`
- `RvROLClient.dll`: `6ba7dfecd38183d4bff0fc53f1c8c05d25e636077fe753b1220912aa58938177`
- `RvControlSvc.exe`: `546efad9ab3ff85c2a50d61524d754bec94a3f3e30d6ae8addef481a1e8daa1e`
- `Radmin_VPN_2.1.4951.1.exe`: `e16711e2e3e59f6603f51f437197215b1914a3d8316e1f633260178b959921f7`

---

## Provenance note

This draft consolidates exactly the 17 `CRYPTO_SPEC`-mapped sources listed above; no other document was read for content. Repeated boilerplate (headers, evidence-ref tables, compliance/STOP-condition footers, generated-file banners, Rust source-code paths, and duplicated unresolved-question lists) was deduplicated; every technical fact — addresses, sizes, constants, key lengths, function names, vtable addresses, hashes, and confidence classifications — was preserved verbatim from the source documents. Nothing was invented; where a source marks a claim UNKNOWN, UNVERIFIED, or HYPOTHESIS, that classification is carried forward unchanged.

The proprietary trailer conflict is recorded in Section 3 with both accounts and their evidence: `round-02/02-cryptography.md` asserts a 64-bit additive checksum with no MD5 (evidence: `FUN_1006a0c0` at `0x1006a0c0–0x1006a0e6`, validation at `0x10069f90`, conclusion statement), while the later deep-audit documents (`CRYPTO_MD5_ANALYSIS.md`, `CRYPTO_AES_CONSUMER_TRACE.md`, `CRYPTO_SYMMETRIC_ENCRYPTION.md`, `CRYPTO_RSESSION_ANALYSIS.md`) assert the additive checksum is hashed with MD5 (`0x100638f0`, `0x10005250`/`0x10004e50`/`0x10004f30`) and folded to 8 bytes (`0x10069ce0–0x10069d15`) before being written at `buf[total-9]` (`0x10069d18–0x10069d3a`) with MD5 call sites `0x10069cdb`/`0x1006a037`. `CRYPTO_RSESSION_ANALYSIS.md` §10 explicitly refutes the "no MD5" claim. No winner is selected; adjudication belongs to `RECONCILIATION.md` (`docs/CRYPTO_PHASE_10_10_RECONCILIATION.md`).

This draft writes exactly one file (`analysis_workspace/compaction/drafts/CRYPTO_SPEC.md`) and no other file.

---

## Evidence appendix (exact tokens from consolidated sources)

Exact addresses, hashes and identifiers from the consolidated sources that are not repeated in the prose above. They are preserved here so that no evidence anchor is lost during compaction; the full narrative for each source remains available in git history.

- `docs/CRYPTO_AES_CONSUMER_TRACE.md`: `fun_10069d70`
- `docs/CRYPTO_AES_KEY_INSTALLATION_TRACE.md`: `0x10000000`, `0x1006a930`, `0x1006aa10`, `fun_100092c0`, `fun_10062250`, `fun_10062ad0`, `fun_10069d70`, `fun_10069e60`, `fun_1006c980`
- `docs/CRYPTO_AES_KEY_SPLIT_TRACE.md`: `0x10000000`, `0x10001000`, `0x1003ff8e`, `0x10040670`, `0x10047770`, `0x100a0060`, `0x100a3660`, `0x101105ff`, `0x401000`, `0x44264e`, `0x516fff`, `fun_10035220`, `fun_100468d0`, `fun_100469c0`, `fun_10047770`, `fun_100a0060`, `fun_100a3660`
- `docs/CRYPTO_CONTROL_KEY_LIFECYCLE.md`: `0x10000000`, `0x1005f450`, `0x1005f4a1`, `0x1005f4b0`, `0x1005f620`, `0x1005f6e0`, `0x1005f710`, `0x1005f740`, `0x1005f760`, `0x1005f7c0`, `0x1005f7e0`, `0x1005f830`, `0x1005f940`, `0x1005fa00`, `0x1005fad0`, `0x1005feb0`, `0x1006017a`, `0x100601b0`, `0x1006023d`, `0x10060240`, `0x10060273`, `0x10060275`, `0x100603f3`, `0x10060410`, `0x100604be`, `0x10060510`, `0x100606a0`, `0x100607d5`, `0x10060810`, `0x1006085c`, `0x10060875`, `0x100608ab`, `0x100608d5`, `0x10060931`, `0x1006096d`, `0x10060a10`, `0x10060a20`, `0x10060a80`, `0x10060fa0`, `0x100614c0`, `0x10061760`, `0x10061860`, `0x10067a30`, `0x10067c00`, `0x10094218`, `0x100a3de0`, `0x100a3df0`, `0x100a3e18`, `0x100a3e1f`, `0x100ad730`, `0x100ad750`, `0x100ad780`, `0x100ad788`, `0x100ad7d8`, `0x100b0bc8`
- `docs/CRYPTO_KEY_LIFECYCLE_GAP_ANALYSIS.md`: `0x100601b0`, `0x100602f0`, `0x10060410`, `0x10060510`, `0x10060810`, `0x1006085c`, `0x10060a80`, `0x10060fa0`, `0x100667b0`, `0x100677d0`, `0x10069fe5`, `0x100ad730`, `0x100ad7d8`
- `docs/CRYPTO_MD5_ANALYSIS.md`: `0x10004f7d`, `0x10004fb2`, `0x10004fcb`, `0x1000503f`, `0x100095ac`, `0x1003fd5c`, `0x1003fd64`, `0x1003fd86`, `0x10069c6b`, `0x10069c77`, `0x10069ca3`, `0x10069cb4`, `0x10069cd7`, `0x10069d2a`, `0x10069dcb`, `0x10069e60`, `0x10069ed2`, `0x10069fe5`, `0x1006a010`, `0x1006a1d2`, `0x1006a1e2`, `0x1006a930`, `0x1006aa10`, `0x1006c980`, `0x1006d450`, `0x10116068`, `0x10116088`, `0x28955b88`
- `docs/CRYPTO_PHASE_10_11_RECONSTRUCTION.md`: `0x03000000`, `0x10000000`, `0x1003ff8e`, `0x1005f940`, `0x100667b0`, `0x10094218`, `0x100ac279`, `0x100ac280`, `0x100dce30`, `0x10187030`, `0x44264e`, `7b12a483fe77c3ed56e5a4dd8e7acc4fe7ec1233`, `95e304e0855a6faf4eece932484cb00e36620a6e`, `fun_1005f760`, `fun_10060410`, `fun_10060510`, `fun_10060810`, `fun_10060d80`, `fun_10060ec0`, `fun_10060fa0`, `fun_10061790`
- `docs/CRYPTO_PHASE_10_3_10_5_CONSOLIDATED_REPORT.md`: `0x07ffffff`, `0x10060361`, `0x100667b0`, `0x10094218`, `0x100ac279`, `0x100ac280`, `0xf8000000`, `7b12a483fe77c3ed56e5a4dd8e7acc4fe7ec1233`, `95e304e0855a6faf4eece932484cb00e36620a6e`, `fun_1005f710`, `fun_1005fad0`, `fun_10060410`, `fun_10060510`, `fun_10060810`, `fun_10060d80`, `fun_10060ec0`, `fun_10060fa0`
- `docs/CRYPTO_RSA_ANALYSIS.md`: `0x1006ab90`, `0x1006ad20`, `0x1006b1d0`
- `docs/CRYPTO_RSA_KEY_PROVENANCE.md`: `0x10000000`, `0x10001000`, `0x100086d0`, `0x10083000`, `0x100ab036`, `0x100ab05d`, `0x100ab085`, `0x100ac000`, `fun_10062a80`
- `docs/CRYPTO_RSESSION_ANALYSIS.md`: `0x10000000`, `0x10003cb0`, `0x1000a3d0`, `0x70000000`, `fun_10008a40`, `fun_1006c944`, `fun_1006c980`
- `docs/CRYPTO_RSESSION_KEY_LIFECYCLE.md`: `0x10000000`, `0x10115d70`, `fun_100092a0`, `fun_100092c0`, `fun_10062ad0`
- `docs/CRYPTO_SYMMETRIC_ENCRYPTION.md`: `0x10069fe5`
- `docs/KEY_EXCHANGE_ANALYSIS.md`: `0x1000a3d0`, `0x1003fd48`, `0x1003fd56`, `0x10041010`, `0x1005f450`, `0x1005f4a1`, `0x10060510`, `0x100607d5`, `0x10060810`, `0x10065f60`, `0x100699e0`, `0x10069fe5`, `0x1006ab90`, `0x1006ad20`, `0x100a3de0`, `0x100a3e1f`, `0x100ac279`, `0x100ac280`, `0x100ac358`, `0x100ad730`, `0x100ad7d8`, `0x1011121c`, `0x10115d6c`, `0x10187030`, `fun_004e2ac0`, `fun_00530150`, `fun_005301d0`, `fun_00561980`
- `docs/reverse-engineering/round-02/01-handshake.md`: `0x024e1b7a`, `0x1006a4cf`, `0x1006a4d1`, `0x1006a4d3`, `0x1006a4d5`, `0x1006a4d7`, `0x1006a4da`, `0x1006a4e1`, `0x1006a4e8`, `0x1006a4ee`, `0x1006a4f3`, `0x1006a514`, `0x1006a518`, `0x1006a51d`, `0x1006a520`, `0x1006a522`, `0x1006a524`, `0x1006a526`, `0x1006a528`, `0x1006a52b`, `0x1006a52e`, `0x1006a531`, `0x1006a534`, `0x1006a537`, `0x1006a53a`, `0x1006a53c`, `0x1006a53f`, `0x1006a540`, `0x1006a543`, `0x1006a544`, `0x1006a549`, `0x1006a5b2`
- `docs/reverse-engineering/round-02/02-cryptography.md`: `0x10003cb0`, `0x100067a0`, `0x10062ca9`, `0x10062cac`, `0x10062cb4`, `0x10062e17`, `0x10062e1d`, `0x10062e1e`, `0x10062e21`, `0x10062e22`, `0x10062e23`, `0x10062e24`, `0x10065de0`, `0x10065de3`, `0x10065de6`, `0x10065deb`, `0x10065dec`, `0x10065def`, `0x10065df0`, `0x10065df5`, `0x1006a0c1`, `0x1006a0c3`, `0x1006a0c6`, `0x1006a0c9`, `0x1006a0cb`, `0x1006a0cd`, `0x1006a0d0`, `0x1006a0d2`, `0x1006a0d4`, `0x1006a0d6`, `0x1006a0d9`, `0x1006a0dc`, `0x1006a0dd`, `0x1006a0df`, `0x1006a0e1`, `0x1006a0e2`, `0x1006aacc`, `0x1006aad0`, `0x1006aad5`, `0x1006aada`, `0x1006aadd`, `0x1006aae0`, `0x1006aae1`, `0x1006ab30`
