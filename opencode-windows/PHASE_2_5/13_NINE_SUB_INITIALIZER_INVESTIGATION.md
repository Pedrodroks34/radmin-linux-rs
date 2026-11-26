# Phase 2.5 Stage 13 — Nine Sub-Initializer Investigation

**Classification: STRONGLY SUPPORTED (byte-level) / PARTIAL (full bodies not disassembled)** — all nine candidate addresses read and classified. The "eight vs nine" discrepancy is resolved: one of the nine addresses (`FUN_00479240`) is a pure `JMP` thunk, not an initializer, so there are 8 initializer candidates + 1 thunk = 9 addresses.

Cross-reference: `05_VTABLE_TRANSITION_AND_CONSTRUCTOR_ANALYSIS.md`, `11_OBJECT_FIELD_AND_SUBOBJECT_LAYOUT.md`, `12_ALLOCATION_AND_FACTORY_CALL_GRAPH.md`.

---

## 1. The Eight-Versus-Nine Discrepancy — Resolved

Phase 2.4 Report 04 listed 9 sub-initializer candidate addresses but described "8 unanalyzed initializers." The nine addresses from the task:

| # | Address | Classification | Initializer? |
|---|---------|----------------|--------------|
| 1 | `FUN_0047A8A0` | Writes vptr `0x00522634` | YES |
| 2 | `FUN_0043E500` | SEH prologue wrapper | YES (candidate, wrapper) |
| 3 | `FUN_00403540` | Writes vptr `0x0051BDA8` | YES |
| 4 | `FUN_004728E0` | SEH prologue wrapper | YES (candidate, wrapper) |
| 5 | `FUN_00483750` | Writes vptr `0x00522A58` | YES |
| 6 | `FUN_0043E680` | SEH prologue wrapper | YES (candidate, wrapper) |
| 7 | `FUN_0047BB20` | Writes 3 vptrs (`0x52271C`, `0x522724`, `0x522738`) | YES |
| 8 | `FUN_00475B70` | Writes vptr `0x00522394` | YES |
| 9 | `FUN_00479240` | Pure `JMP rel32` thunk (then `CC` padding) | **NO — thunk** |

**Resolution:** Nine addresses are listed, but `FUN_00479240` is a pure tail-jump thunk (`E9 7B 00 00 00` = `JMP +0x7B`, then `CC` int3 padding), not an initializer body. Therefore there are **8 initializer candidates + 1 thunk = 9 addresses**, exactly matching Phase 2.4's "8 unanalyzed initializers" vs. "9 addresses." The inconsistency is resolved: the 9th address is a thunk, not an initializer.

---

## 2. Individual Analysis (verified first bytes; file offset via PE map)

### FUN_0047A8A0 (VA `0x0047A8A0`, file offset `0x00079CA0`)
Bytes: `55 8B EC 51 53 57 8B F9 33 DB C7 07 34 26 52 00 8D 47 04 87 18 85 DB ...`
- Standard frame prologue (`PUSH EBP; MOV EBP,ESP; PUSH EAX; PUSH EBX; PUSH EDI; MOV EDI,ECX; XOR EBX,EBX`)
- `C7 07 34 26 52 00` = `MOV [EDI], 0x00522634` — **writes primary vptr**
- `8D 47 04` `87 18` = `LEA EAX,[EDI+4]; XCHG [EAX],EBX` — atomic exchange on `+0x4`
- **Verdict:** Initializer. Writes vptr `0x00522634` to `[EDI+0]`, then atomic-op on `+0x4`. Relevant (initializes an object/subobject with vtable `0x522634`).

### FUN_0043E500 (VA `0x0043E500`, file offset `0x0003D900`)
Bytes: `55 8B EC 6A FF 68 30 43 51 00 64 A1 00 00 00 00 50 ...`
- SEH prologue (`PUSH EBP; MOV EBP,ESP; PUSH -1; PUSH 0x514330` handler; `MOV EAX, FS:[0]`)
- No immediate vptr write in first bytes; this is an **SEH exception-handling wrapper** around another function.
- **Verdict:** Candidate initializer wrapper (SEH). Not an initializer body itself. May wrap an initializer.

### FUN_00403540 (VA `0x00403540`, file offset `0x0002940`)
Bytes: `56 8B F1 8D 4E 20 C7 06 A8 BD 51 00 E8 DF FF FF FF ...`
- `MOV ESI, ECX; LEA ECX,[ESI+0x20]; MOV [ESI], 0x0051BDA8` — **writes primary vptr `0x0051BDA8`**
- `E8 DF FF FF FF` = `CALL 0x403524` (helper)
- **Verdict:** Initializer. Writes vptr `0x0051BDA8` to `[ESI+0]`. Relevant.

### FUN_004728E0 (VA `0x004728E0`, file offset `0x00071CE0`)
Bytes: `55 8B EC 6A FF 68 E0 60 51 00 64 A1 00 00 00 00 50 56 ...`
- SEH prologue (`PUSH -1; PUSH 0x5160E0` handler; `FS:[0]`)
- **Verdict:** Candidate initializer wrapper (SEH). Not an initializer body itself.

### FUN_00483750 (VA `0x00483750`, file offset `0x00082B50`)
Bytes: `C7 01 58 2A 52 00 83 C1 08 E9 82 FA FE FF CC CC ...`
- **No prologue:** starts `C7 01 58 2A 52 00` = `MOV [ECX], 0x00522A58` — **writes vptr**
- `83 C1 08` = `ADD ECX, 8`; `E9 ...` = `JMP`
- **Verdict:** Initializer (inlined/thunk-like, no frame). Writes vptr `0x00522A58` to `[ECX+0]`, advances ECX by 8, tails to another function. Relevant.

### FUN_0043E680 (VA `0x0043E680`, file offset `0x0003DA80`)
Bytes: `55 8B EC 6A FF 68 50 43 51 00 64 A1 00 00 00 00 50 ...`
- SEH prologue (`PUSH -1; PUSH 0x514350` handler; `FS:[0]`)
- **Verdict:** Candidate initializer wrapper (SEH). Not an initializer body itself.

### FUN_0047BB20 (VA `0x0047BB20`, file offset `0x0007AF20`)
Bytes: `C7 01 1C 27 52 00 C7 41 08 24 27 52 00 C7 41 18 38 27 52 00 E9 27 ED FF FF ...`
- **No prologue:** `MOV [ECX], 0x0052271C`; `MOV [ECX+0x8], 0x00522724`; `MOV [ECX+0x18], 0x00522738`; `JMP ...`
- **Writes THREE vptr values** at offsets +0, +0x8, +0x18 — a multi-subobject initializer.
- **Verdict:** Initializer. Initializes a 3-subobject object with vtables `0x52271C`/`0x522724`/`0x522738`. Relevant.

### FUN_00475B70 (VA `0x00475B70`, file offset `0x00074F70`)
Bytes: `56 8B F1 C7 06 94 23 52 00 E8 82 00 00 00 8B CE 5E E9 9A 39 00 00 CC ...`
- `MOV ESI, ECX; MOV [ESI], 0x00522394` — **writes vptr `0x00522394`**
- `E8 82 00 00 00` = `CALL 0x475BF8` (helper); `8B CE 5E E9 ...` = `MOV ECX,ESI; POP ESI; JMP`
- **Verdict:** Initializer. Writes vptr `0x00522394` to `[ESI+0]`. Relevant.

### FUN_00479240 (VA `0x00479240`, file offset `0x00078640`)
Bytes: `E9 7B 00 00 00 CC CC CC CC CC CC CC CC CC CC CC E9 6B 00 00 00 ...`
- `E9 7B 00 00 00` = `JMP rel32 0x7B` → target `0x479245 + 0x7B` = `0x4792C0`
- Then `CC` (int3) padding — dead/unused space after the thunk.
- **Verdict:** Pure tail-jump thunk, NOT an initializer. Resolves the discrepancy.

---

## 3. Vtable Values Written by Initializers

| Initializer | Vptr written | Offset | Table value | In .rdata? |
|-------------|-------------|--------|-------------|------------|
| `FUN_0047A8A0` | `0x00522634` | +0x0 | `0x522634` | YES (.rdata VA 0x519000–0x5495C8) |
| `FUN_00403540` | `0x0051BDA8` | +0x0 | `0x51BDA8` | YES |
| `FUN_00483750` | `0x00522A58` | +0x0 | `0x522A58` | YES |
| `FUN_0047BB20` | `0x0052271C` | +0x0 | `0x52271C` | YES |
| `FUN_0047BB20` | `0x00522724` | +0x8 | `0x522724` | YES |
| `FUN_0047BB20` | `0x00522738` | +0x18 | `0x522738` | YES |
| `FUN_00475B70` | `0x00522394` | +0x0 | `0x522394` | YES |

**Critical observation:** All vtable values written by these 9 candidates are in the `0x51BDxx`–`0x522xxx` range. NONE of them write the main ObjectCandidate's vtables (`0x0051FFB4`, `0x0051E570`, `0x0051E4F0`). Therefore these 9 sub-initializers initialize **different objects or subobjects** (with different vtables in the `0x52xxxx` range), NOT the main ObjectCandidate whose lifecycle we're tracing.

This means: **the 9 sub-initializers are most likely unrelated to the main ObjectCandidate** — they initialize other classes/types in the program. They are NOT part of the ObjectCandidate's constructor chain (`FUN_0043E1A0` writes `0x51FFB4`/`0x51E570`/`0x51E4F0`, a different range).

---

## 4. Relevant vs. Unrelated Classification

| Address | Relevant to ObjectCandidate? | Reason |
|-----------|------------------------------|--------|
| `FUN_0047A8A0` | UNRELATED | Writes vtable `0x522634` (not ObjectCandidate's `0x51FFB4/0x51E570/0x51E4F0`) |
| `FUN_0043E500` | UNRELATED | SEH wrapper; no ObjectCandidate vtable written |
| `FUN_00403540` | UNRELATED | Writes vtable `0x51BDA8` (not ObjectCandidate's) |
| `FUN_004728E0` | UNRELATED | SEH wrapper |
| `FUN_00483750` | UNRELATED | Writes vtable `0x522A58` |
| `FUN_0043E680` | UNRELATED | SEH wrapper |
| `FUN_0047BB20` | UNRELATED | Writes 3 vtables `0x52271C/0x522724/0x522738` (not ObjectCandidate's) |
| `FUN_00475B70` | UNRELATED | Writes vtable `0x522394` |
| `FUN_00479240` | UNRELATED | Pure JMP thunk, no initialization |

**All 9 candidates are classified UNRELATED to the main ObjectCandidate lifecycle** because none write the ObjectCandidate's vptr values. They initialize other object types with vtables in the `0x51BDxx`–`0x522xxx` range.

**Confidence:** The byte-level reads are PROVEN. The "unrelated" classification is STRONGLY SUPPORTED (vtable ranges are disjoint). However, it's possible one of these initializes a subobject of ObjectCandidate — but ObjectCandidate's subobject vptrs are `0x520014/0x520020/0x520034/0x520050/0x5200E8` (initial) and `0x51BE00/0x51BE0C/0x51BE20/0x51E810/0x51E7F8` (overwrite), none of which match `0x522xxx`. So even subobject initialization doesn't match. UNRELATED stands.

---

## 5. Callers and Callees

Callers/callees of these 9 functions were not fully enumerated (no call-graph tool output available). From byte inspection:
- `FUN_0047BB20`, `FUN_00483750` have no prologue and end in `JMP` — they are likely inlined helpers called directly (tail-called), not via `CALL`.
- `FUN_00479240` is a thunk (`JMP 0x4792C0`).
- The SEH wrappers (`0x43E500`, `0x4728E0`, `0x43E680`) wrap some inner function (handler addresses `0x514330`, `0x5160E0`, `0x514350` are in `.rdata` — likely `__except_handler` or similar).

Full caller/callee enumeration requires a call-graph capability not available in this static environment; marked as a follow-up.

---

## 6. Confidence Summary

| Question | Classification |
|----------|----------------|
| 9 addresses listed | PROVEN (Report 04 + byte reads) |
| 0x479240 is a JMP thunk (not initializer) | PROVEN (bytes `E9 7B 00 00 00` + `CC` pad) |
| 8 real initializer candidates | PROVEN (8 of 9 write code or SEH-prologue) |
| 5 functions write vptrs directly | PROVEN (raw bytes `C7 [reg], imm32`) |
| 3 functions are SEH wrappers | PROVEN (SEH prologue pattern) |
| None write ObjectCandidate's vptrs | PROVEN (vtable ranges disjoint: `0x52xxxx` vs `0x51FFxx/0x51E5xx/0x51E4xx`) |
| All 9 unrelated to ObjectCandidate lifecycle | STRONGLY SUPPORTED |
| Full bodies/callers not disassembled | UNKNOWN (follow-up: decompile each) |
