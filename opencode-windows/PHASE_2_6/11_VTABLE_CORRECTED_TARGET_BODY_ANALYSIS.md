# Phase 2.6 Stage 11 — Vtable Corrected Target Body Analysis

**Classification: PROVEN** — all seven target function bodies decoded by Capstone + Manual + REA. Slot-13 targets return 16 (0x10); slot-22 targets vary (`0x450FA0`/`0x450FC0` are argument-dependent; `0x451090`/`0x451070`/`0x451010` return 0).

Cross-reference: `03_INDEPENDENT_X86_INSTRUCTION_DECODING_AUDIT.md`, `04_FUN_004731E0_CORRECTED_INSTRUCTION_AND_SEMANTICS.md`.

---

## 1. Verified Vtable Slot Mapping

Using the corrected vptr address points (Report 03):

| Table | Vptr | Slot +0x34 (slot 13) | Slot address | Target | Target VA |
|-------|------|---------------------|--------------|--------|-----------|
| A | `0x0051FFB4` | `0x0051FFB4 + 0x34 = 0x0051FFE8` | `0x0051FFE8` | `FUN_004510A0` | `0x004510A0` |
| A | `0x0051FFB4` | Slot +0x58 (slot 22): `0x0051FFB4 + 0x58 = 0x0052000C` | `0x0052000C` | `FUN_00450FA0` | `0x00450FA0` |
| B | `0x0051E570` | `0x0051E570 + 0x34 = 0x0051E5A4` | `0x0051E5A4` | `FUN_004510B0` | `0x004510B0` |
| B | `0x0051E570` | `0x0051E570 + 0x58 = 0x0051E5C8` | `0x0051E5C8` | `FUN_00450FC0` | `0x00450FC0` |
| C | `0x0051E4F0` | `0x0051E4F0 + 0x34 = 0x0051E524` | `0x0051E524` | `FUN_004510B0` | `0x004510B0` (shared w/ B) |
| C | `0x0051E4F0` | `0x0051E4F0 + 0x58 = 0x0051E548` | `0x0051E548` | `FUN_00450FC0` | `0x00450FC0` (shared w/ B) |

---

## 2. Target Function Bodies (fully decoded)

### `0x004510A0` — Table A slot 13
| VA | Bytes | Instruction |
|----|-------|-------------|
| `0x004510A0` | `B8 10 00 00 00` | `MOV EAX, 0x10` |
| `0x004510A5` | `C3` | `RET` |

**Semantics:** `return 16;` (0x10). Returns a constant size/value.

### `0x004510B0` — Table B slot 13, Table C slot 13 (shared)
| VA | Bytes | Instruction |
|----|-------|-------------|
| `0x004510B0` | `B8 10 00 00 00` | `MOV EAX, 0x10` |
| `0x004510B5` | `C3` | `RET` |

**Semantics:** `return 16;` (0x10). **Shared** between Table B and Table C slot 13. Identical to `0x004510A0`.

### `0x00451090` — Table B slot 21
| VA | Bytes | Instruction |
|----|-------|-------------|
| `0x00451090` | `33 C0` | `XOR EAX, EAX` |
| `0x00451092` | `C3` | `RET` |

**Semantics:** `return 0;`

### `0x00451070` — Table A slot 20
| VA | Bytes | Instruction |
|----|-------|-------------|
| `0x00451070` | `33 C0` | `XOR EAX, EAX` |
| `0x00451072` | `C3` | `RET` |

**Semantics:** `return 0;`

### `0x00451010` — Table A nominal slot 13 (actually slot 12 relative to real vptr)
| VA | Bytes | Instruction |
|----|-------|-------------|
| `0x00451010` | `33 C0` | `XOR EAX, EAX` |
| `0x00451012` | `C3` | `RET` |

**Semantics:** `return 0;` (This is the address Phase 2.5 mislabeled as Table A slot 13; it's actually at nominal-base offset.)

### `0x00450FA0` — Table A slot 22 (argument-dependent)
| VA | Bytes | Instruction |
|----|-------|-------------|
| `0x00450FA0` | `55 8B EC` | `PUSH EBP; MOV EBP, ESP` |
| `0x00450FA3` | `8B 45 08` | `MOV EAX, [EBP+8]` (EAX = arg) |
| `0x00450FA6` | `83 F8 02` | `CMP EAX, 2` |
| `0x00450FA9` | `74 0E` | `JZ +0x0E` → return 0 |
| `0x00450FAB` | `83 F8 20` | `CMP EAX, 0x20` |
| `0x00450FAE` | `74 09` | `JZ +0x09` → return 0 |
| `0x00450FB0` | `B8 C5 00 00 00` | `MOV EAX, 0xC5` |
| `0x00450FB5` | `5D C2 04 00` | `POP EBP; RET 4` |
| `0x00450FB9` | `33 C0` | `XOR EAX, EAX` |
| `0x00450FBB` | `5D C2 04 00` | `POP EBP; RET 4` |

**Semantics:**
```c
int __stdcall FUN_00450FA0(int arg)
{
    if (arg == 2) return 0;
    if (arg == 0x20) return 0;
    return 0xC5;  // 197
}
```
Both `arg==2` and `arg==0x20` return 0; everything else returns 0xC5 (197). This is argument-dependent, not a constant.

### `0x00450FC0` — Table B slot 22, Table C slot 22 (shared)
| VA | Bytes | Instruction |
|----|-------|-------------|
| `0x00450FC0` | `55 8B EC 8B 45 08 83 F8 02 74 0E 83 F8 20 74 09 B8 C5 00 00 00 5D C2 04 00 33 C0 5D C2 04 00` | (identical to `0x00450FA0`) |

**Semantics:** Identical to `FUN_00450FA0` — argument-dependent, returns 0 for arg 2 or 0x20, 0xC5 otherwise. **Shared** between Table B and Table C slot 22.

---

## 3. Slot Target Summary Table

| Table | Slot +0x34 target | Returns | Slot +0x58 target | Returns |
|-------|-------------------|---------|-------------------|---------|
| A (`0x51FFB4`) | `0x004510A0` | 16 (0x10) | `0x00450FA0` | arg-dependent (0 or 0xC5) |
| B (`0x51E570`) | `0x004510B0` | 16 (0x10) | `0x00450FC0` | arg-dependent (0 or 0xC5) |
| C (`0x51E4F0`) | `0x004510B0` | 16 (0x10) | `0x00450FC0` | arg-dependent (0 or 0xC5) |

**Observations:**
- Slot 13 (`+0x34`) is consistent: returns 16 across all tables (B and C share `0x4510B0`; A has `0x4510A0`, also returns 16).
- Slot 22 (`+0x58`) for Table B/C is shared (`0x450FC0`, arg-dependent). Table A slot 22 is `0x450FA0` (same logic, separate address).
- `0x451090`, `0x451070`, `0x451010` all return 0 (used at other slots, not +0x34/+0x58).

---

## 4. Dispatch Correlation (`FUN_0044F3F0`)

`FUN_0044F3F0` calls `[EAX+0x34]` and `[EAX+0x58]` where EAX = object vptr.

| Active vptr | Table | `[vptr+0x34]` result | `[vptr+0x58]` result |
|-------------|-------|---------------------|---------------------|
| `0x51FFB4` | Table A | 16 (`0x4510A0`) | arg-dependent (`0x450FA0`) |
| `0x51E570` | Table B | 16 (`0x4510B0`) | arg-dependent (`0x450FC0`) |
| `0x51E4F0` | Table C | 16 (`0x4510B0`, shared) | arg-dependent (`0x450FC0`, shared) |

**Guard:** calls execute only if `[EDI+0x28]==5 && [EDI+0x2C]!=0`. Also `INC [EDI+0x30]`.

---

## 5. Confidence Summary

| Finding | Classification |
|---------|---------------|
| Slot-13 targets return 16 (all tables) | PROVEN |
| Slot-22 Table B/C target `0x450FC0` is arg-dependent | PROVEN |
| Slot-22 Table A target `0x450FA0` is arg-dependent (same logic) | PROVEN |
| B/C slot 13 and slot 22 are shared between tables | PROVEN |
| Table A slot 13/22 are separate addresses (not shared with B/C) | PROVEN |
| `0x451090`/`0x451070`/`0x451010` return 0 (other slots) | PROVEN |
| Phase 2.5 "slot 13 = 0x451010 (returns 0)" for Table A | CONTRADICTED (that's nominal-base slot 12 / real slot 12; real slot 13 = `0x4510A0` returning 16) |
