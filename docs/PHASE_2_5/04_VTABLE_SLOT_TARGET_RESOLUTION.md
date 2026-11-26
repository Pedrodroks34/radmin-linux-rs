# Phase 2.5 Stage 04 — Vtable Slot Target Resolution (+0x34 and +0x58)

**Classification: PROVEN / PARTIALLY UNRESOLVED** — all slot addresses and pointer values read from the actual executable; targets resolved where disassembly is available; two corrected Table A targets (`0x004510A0`, `0x00450FC0`) not yet disassembled.

Cross-reference: `03_VTABLE_ADDRESS_POINT_CORRECTION.md`, `05_VTABLE_TRANSITION_AND_CONSTRUCTOR_ANALYSIS.md`.

---

## 1. Method

For each candidate vptr, the effective slot address is `vptr + slot_offset`:
- `+0x34` = slot 13
- `+0x58` = slot 22

Bytes read as 4 little-endian at the slot VA, mapped VA→RVA→file offset via the PE section table (all in `.rdata`).

---

## 2. Complete Slot Investigation

### Table A — vptr `0x0051FFB4`

| Slot | Offset | Slot VA | File offset | Bytes (hex) | Pointer (U32LE) | Target | Resolution status | Evidence |
|------|--------|---------|-------------|-------------|-----------------|--------|-------------------|----------|
| 0 | +0x00 | `0x0051FFB4` | `0x0011E9B4` | F0 EC 43 00 | `0x0043ECF0` | `FUN_0043ECF0` (constructor wrapper) | RESOLVED | Report 03; unusual for slot 0 |
| 1 | +0x04 | `0x0051FFB8` | `0x0011E9B8` | E0 F3 44 00 | `0x0044F3E0` | `FUN_0044F3E0` | RESOLVED (addr only) | — |
| 2 | +0x08 | `0x0051FFBC` | `0x0011E9BC` | F0 F3 44 00 | `0x0044F3F0` | `FUN_0044F3F0` (indirect dispatch) | RESOLVED | — |
| 12 | +0x30 | `0x0051FFE4` | `0x0011E9E4` | F0 0F 45 00 | `0x00450FF0` | `FUN_00450FF0` | RESOLVED (addr only) | — |
| **13** | **+0x34** | **`0x0051FFE8`** | **`0x0011E9E8`** | **A0 10 45 00** | **`0x004510A0`** | `FUN_004510A0` | **UNRESOLVED (body)** | Corrected from report's `0x00451010` |
| 14 | +0x38 | `0x0051FFEC` | `0x0011E9EC` | 80 10 45 00 | `0x00451080` | `FUN_00451080` | RESOLVED (addr only) | — |
| 20 | +0x50 | `0x00520004` | `0x0011EA04` | 70 10 45 00 | `0x00451070` | `FUN_00451070` | RESOLVED | `XOR EAX,EAX; RET` (returns 0) |
| 21 | +0x54 | `0x00520008` | `0x0011EA08` | 90 10 45 00 | `0x00451090` | `FUN_00451090` | RESOLVED | `XOR EAX,EAX; RET` (returns 0) |
| **22** | **+0x58** | **`0x0052000C`** | **`0x0011EA0C`** | **A0 0F 45 00** | **`0x00450FA0`** | `FUN_00450FA0` | **UNRESOLVED (body)** | Corrected from report's `0x00451070` |

### Table B — vptr `0x0051E570`

| Slot | Offset | Slot VA | File offset | Bytes | Pointer | Target | Resolution status | Evidence |
|------|--------|---------|-------------|-------|---------|--------|-------------------|----------|
| 0 | +0x00 | `0x0051E570` | `0x0011CF70` | D0 EE 43 00 | `0x0043EED0` | `FUN_0043EED0` | RESOLVED (destructor candidate) | `55 8B EC 56 8B F1` prologue |
| 1 | +0x04 | `0x0051E574` | `0x0011CF74` | E0 F3 44 00 | `0x0044F3E0` | `FUN_0044F3E0` | RESOLVED (addr only) | Shared with Table A slot 1 |
| **13** | **+0x34** | **`0x0051E5A4`** | **`0x0011CFA4`** | **B0 10 45 00** | **`0x004510B0`** | `FUN_004510B0` | RESOLVED | `B8 10 00 00 00 C3` = MOV EAX,0x10; RET (returns 16) |
| 21 | +0x54 | `0x0051E5C4` | `0x0011CFC4` | 90 10 45 00 | `0x00451090` | `FUN_00451090` | RESOLVED | `XOR EAX,EAX; RET` (returns 0) |
| **22** | **+0x58** | **`0x0051E5C8`** | **`0x0011CFC8`** | **C0 0F 45 00** | **`0x00450FC0`** | `FUN_00450FC0` | **UNRESOLVED (body)** | Corrected from report's `0x00451090` |

### Table C — vptr `0x0051E4F0`

| Slot | Offset | Slot VA | File offset | Bytes | Pointer | Target | Resolution status | Evidence |
|------|--------|---------|-------------|-------|---------|--------|-------------------|----------|
| 0 | +0x00 | `0x0051E4F0` | `0x0011CEF0` | 10 F1 43 00 | `0x0043F110` | `FUN_0043F110` | RESOLVED (scalar deleting destructor candidate) | `55 8B EC F6 45 08` prologue |
| 1 | +0x04 | `0x0051E4F4` | `0x0011CEF4` | E0 F3 44 00 | `0x0044F3E0` | `FUN_0044F3E0` | RESOLVED (addr only) | Shared with Tables A/B slot 1 |
| **13** | **+0x34** | **`0x0051E524`** | **`0x0011CF24`** | **B0 10 45 00** | **`0x004510B0`** | `FUN_004510B0` | RESOLVED | `MOV EAX,0x10; RET` (returns 16) — shared with Table B slot 13 |
| 21 | +0x54 | `0x0051E544` | `0x0011CF44` | 90 10 45 00 | `0x00451090` | `FUN_00451090` | RESOLVED | `XOR EAX,EAX; RET` (returns 0) — shared with Table B slot 21 |
| **22** | **+0x58** | **`0x0051E548`** | **`0x0011CF48`** | **C0 0F 45 00** | **`0x00450FC0`** | `FUN_00450FC0` | **UNRESOLVED (body)** | Corrected; shared with Table B slot 22 |

---

## 3. Target Function Details (disassembled)

| Target VA | Disassembly (verified bytes) | Interpretation |
|-----------|------------------------------|----------------|
| `0x00451010` | `33 C0 C3 CC CC CC` = `XOR EAX,EAX; RET; int3...` | Returns 0. (Report's Table A slot-13 claim — actually Table A slot 12 relative to real vptr, but present at Table A nominal-slot-13 / `0x0051FFE0`.) |
| `0x00451070` | `33 C0 C3 CC CC CC` = `XOR EAX,EAX; RET` | Returns 0. Table A slot 20. |
| `0x00451090` | `33 C0 C3 CC CC CC` = `XOR EAX,EAX; RET` | Returns 0. Tables B/C slot 21 (shared). |
| `0x004510B0` | `B8 10 00 00 00 C3` = `MOV EAX,0x10; RET` | Returns 16 (0x10). Tables B/C slot 13 (shared). |
| `0x004510A0` | **bytes `A0 10 45 00` is the pointer; body at `0x004510A0` not yet read** | UNRESOLVED — corrected Table A slot 13 target |
| `0x00450FA0` | **body at `0x00450FA0` not yet read** | UNRESOLVED — corrected Table A slot 22 target |
| `0x00450FC0` | **body at `0x00450FC0` not yet read** | UNRESOLVED — corrected Table B/C slot 22 target |

---

## 4. Sharing Between Tables

| Target | Tables | Slots |
|--------|--------|-------|
| `0x0044F3E0` | A, B, C | slot 1 of all three (shared) |
| `0x004510B0` | B, C | slot 13 of both (shared; returns 16) |
| `0x00451090` | B, C | slot 21 of both (shared; returns 0) |
| `0x00450FC0` | B, C | slot 22 of both (shared; unresolved body) |

Table A shares NO slot-13/slot-22 targets with B or C (Table A slot 13/22 are `0x004510A0`/`0x00450FA0`, distinct). Table A slot 20/21 (`0x00451070`/`0x00451090`) coincide in value with B/C slot 21 (`0x00451090`) but at different addresses.

---

## 5. Destructor / Deleting Destructor / Adjustment Thunk Identification

| Function | VA | Evidence | Classification |
|----------|----|----------|----------------|
| `FUN_0043ECF0` | `0x0043ECF0` | Constructor wrapper: calls `FUN_0043E1A0`, conditional `FUN_004e6cd7(this)`. Also Table A slot 0. | Constructor wrapper (unusual as vtable slot 0) |
| `FUN_0043EED0` | `0x0043EED0` | Table B slot 0. Prologue `55 8B EC 56 8B F1`. | Destructor candidate (intermediate table) |
| `FUN_0043F110` | `0x0043F110` | Table C slot 0. `55 8B EC F6 45 08` (tests stack arg bit — scalar deleting destructor pattern). | Scalar deleting destructor candidate (final table) |
| `FUN_0044F3F0` | `0x0044F3F0` | Table A slot 2; the indirect-dispatch function itself. | Virtual method (not a destructor) |
| Adjustment thunks | `0x0043E85E`–`0x0043E881` | `SUB ECX, <off>; JMP FUN_0043ECF0` for offs 0x38/0x40/0x50/0x98/0x9C. | This-pointer adjustment thunks (multiple inheritance) |

No separate "deleting destructor" distinct from `FUN_0043F110` is confirmed. `FUN_0043F110`'s stack-arg-bit test is consistent with a scalar deleting destructor, but the body was not fully disassembled in this phase.

---

## 6. Unresolved Entries

| Table | Slot | Target VA | Why unresolved | Next evidence needed |
|-------|------|-----------|----------------|----------------------|
| A | 13 | `0x004510A0` | Body not disassembled | Read/disassemble `0x004510A0` |
| A | 22 | `0x00450FA0` | Body not disassembled | Read/disassemble `0x00450FA0` |
| B | 22 | `0x00450FC0` | Body not disassembled | Read/disassemble `0x00450FC0` |
| C | 22 | `0x00450FC0` | Body not disassembled | Same as B slot 22 (shared) |

---

## 7. Consistency Check with Call Sites

`FUN_0044F3F0` calls `[EAX+0x34]` and `[EAX+0x58]` where EAX = object vptr.
- If vptr = Table A (`0x0051FFB4`): slot 13 → `0x004510A0` (unresolved), slot 22 → `0x00450FA0` (unresolved).
- If vptr = Table B (`0x0051E570`): slot 13 → `0x004510B0` (returns 16), slot 22 → `0x00450FC0` (unresolved).
- If vptr = Table C (`0x0051E4F0`): slot 13 → `0x004510B0` (returns 16), slot 22 → `0x00450FC0` (unresolved).

The runtime-active vptr (and therefore which targets are actually invoked) is UNKNOWN statically because `FUN_0044F3F0` has no direct callers (Report 02, R9). This is a genuine runtime-only question, not resolvable by static analysis.
