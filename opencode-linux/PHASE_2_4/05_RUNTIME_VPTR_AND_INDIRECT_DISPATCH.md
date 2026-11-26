# Phase 2.4 Stage 05 — Runtime Vptr and Indirect Dispatch

**Classification: BLOCKED** (requires Windows runtime debugging; no Windows debugger available in Linux environment)

## 1. Target Function: FUN_0044F3F0

| Property | Value |
|----------|-------|
| Address | 0x0044F3F0 |
| Convention | `__thiscall` (ECX = `this` / EDI) |
| Direct callers | NONE (REA procedure_callers returned empty) |
| Invocation | Only reachable via indirect vtable dispatch |

## 2. Indirect Call Sites

Four indirect call sites within FUN_0044F3F0:

| VA | Instruction | Raw Bytes | Offset | Guard Condition |
|----|-------------|-----------|--------|-----------------|
| 0x44F4EE | `CMP [EDI+0x28], 5` | 83 7F 28 05 | — | field_0x28 == 5 |
| 0x44F4F4 | `CMP [EDI+0x2C], 0` | 83 7F 2C 00 | — | field_0x2C != 0 |
| 0x44F4FE | `INC [EDI+0x30]` | FF 47 30 | — | field_0x30++ |
| 0x44F4FA | `MOV EAX, [EDI]` | 8B 07 | — | Load vptr |
| 0x44F501 | `CALL [EAX+0x34]` | FF 50 34 | +0x34 | Slot 13 |
| 0x44F50D | `CALL [EAX+0x58]` | FF 50 58 | +0x58 | Slot 22 |
| 0x44F5AA | `CALL [EAX+0x34]` | FF 50 34 | +0x34 | Slot 13 (2nd call) |
| 0x44F5B6 | `CALL [EAX+0x58]` | FF 50 58 | +0x58 | Slot 22 (2nd call) |

**Guard logic:** The indirect calls execute only if `field_0x28 == 5 && field_0x2C != 0`. If either condition fails, the calls are skipped.

## 3. Vtable Tables

### Table A (Base: 0x0051FFAC, 40 slots)

| Slot | VA | Value | Source |
|------|-----|-------|--------|
| 0 | 0x51FFAC | 0x0043E8E0 | Constructor initial write |
| 1 | 0x51FFB0 | 0x00539A4C | Non-.text (data) |
| 2 | 0x51FFB4 | 0x0043ECF0 | **First vptr write** |
| 3 | 0x51FFB8 | 0x0044F3E0 | |
| 4 | 0x51FFBC | 0x0044F3F0 | FUN_0044F3F0 itself |
| 13 | 0x51FFE0 | 0x00451010 | |
| 22 | 0x520004 | 0x00451070 | Returns 0 |

### Table B (Intermediate: 0x0051E570)

| Slot | VA | Value |
|------|-----|-------|
| 0 | 0x51E570 | 0x0043EED0 |
| 13 | 0x51E5A4 | 0x004510B0 |
| 22 | 0x51E5C4 | 0x00451090 | Returns 0 |

### Table C (Final: 0x0051E4F0)

| Slot | VA | Value |
|------|-----|-------|
| 0 | 0x51E4F0 | 0x0043F110 |
| 13 | 0x51E524 | 0x004510B0 |
| 22 | 0x51E544 | 0x00451090 | Returns 0 |

## 4. Slot Targets Under Each Vptr State

### If vptr = Table A (0x51FFB4, first write):
- Slot 13 (+0x34): 0x00451010 → `XOR EAX, EAX; RET` (returns 0)
- Slot 22 (+0x58): 0x00451070 → `XOR EAX, EAX; RET` (returns 0)

### If vptr = Table B (0x51E570, intermediate write):
- Slot 13 (+0x34): 0x004510B0 → `MOV EAX, 0x10; RET` (returns 16)
- Slot 22 (+0x58): 0x00451090 → `XOR EAX, EAX; RET` (returns 0)

### If vptr = Table C (0x51E4F0, final write):
- Slot 13 (+0x34): 0x004510B0 → `MOV EAX, 0x10; RET` (returns 16)
- Slot 22 (+0x58): 0x00451090 → `XOR EAX, EAX; RET` (returns 0)

## 5. Non-.Text Table Slots (Purpose Unknown)

| Table | Slot | VA | Value | Type |
|-------|------|-----|-------|------|
| A | 1 | 0x51FFB0 | 0x00539A4C | Non-.text (0x539xxx range) |
| A | 25 | 0x520010 | 0x00539xxx | Non-.text |
| A | 28 | 0x52001C | 0x00539xxx | Non-.text |
| A | 33 | 0x520030 | 0x00539xxx | Non-.text |
| A | 38 | 0x520048 | 0x00539xxx | Non-.text |
| B | 3 slots | — | 0x00539xxx | Non-.text |
| C | 3 slots | — | 0x00539xxx | Non-.text |

## 6. Runtime Vptr State — UNRESOLVED

**The critical question:** Which vptr is active when FUN_0044F3F0 executes?

The constructor writes three different vptrs sequentially:
1. 0x51FFB4 (Table A slot 2 = FUN_0043ECF0)
2. 0x51E570 (Table B)
3. 0x51E4F0 (Table C)

**We cannot determine statically which vptr is active at the time of the indirect call because:**
- FUN_0044F3F0 has no direct callers (REA procedure_callers empty)
- The constructor's call chain is unreachable from any known caller
- No runtime execution trace is available (no Windows debugger)

**If vptr = Table A:** Both indirect calls return 0 (FUN_00451010 and FUN_00451070 both XOR EAX,EAX; RET)
**If vptr = Table B or C:** Slot 13 returns 16, Slot 22 returns 0

## 7. Confidence Classification

| Question | Classification | Basis |
|----------|---------------|-------|
| Indirect call instructions exist | CONFIRMED | Raw bytes verified at 8 addresses |
| Guard conditions (field_0x28==5, field_0x2C!=0) | CONFIRMED | Raw bytes verified |
| Table A/B/C contents | CONFIRMED | Raw byte extraction |
| Slot targets under each vptr state | CONFIRMED | Static table extraction |
| Which vptr is active at runtime | BLOCKED | No runtime evidence available |
| Whether guard condition is ever satisfied | UNKNOWN | field_0x28/0x2C initial values unknown |
| FUN_0044F3F0 is ever called | UNKNOWN | No direct callers found |