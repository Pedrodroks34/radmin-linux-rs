# OBJECT LIFECYCLE — Consolidated Analysis Document

**Scope:** Consolidation of all 36 sources mapped to `OBJECT_LIFECYCLE` in `analysis_workspace/compaction/mapping.tsv` (Phase 2.3 and Phase 2.4 reports).
**Target binary:** `RvControlSvc_Installed.exe` — PE32 x86, ImageBase `0x00400000`, SizeOfImage `0x001D6000`, file size `1,619,320` bytes, SHA-256 `0e2e6eaacbe8ebe01286cda39a12eaad34a20434d50f4f8bf2fdd91d4d6ef2ad`. Binary identity verified identical across Phase 2.3 and Phase 2.4; all addresses remain authoritative.
**Classification:** STRONGLY SUPPORTED (static REA/Ghidra evidence; runtime-dependent questions BLOCKED due to no Windows debugger).

---

## 1. Object Layout

| Offset | Name | Type | Confidence | Evidence |
|---|---|---|---|---|
| `0x00` | field_0x00 | Vtable pointer | STRONGLY SUPPORTED | `MOV EAX, [EDI]` used as base for `[EAX+0x34]`/`[EAX+0x58]` indirect calls; constructor writes vptr 3× |
| `0x04` | field_0x04 | Subobject pointer | VERIFIED | Written by `FUN_00479240`; read by `FUN_0044F3F0` |
| `0x0C` | field_0x0C | Zeroed then released | VERIFIED | Zeroing loop start; released by `FUN_00475B70` |
| `0x20` | field_0x20 | Reference count (atomic access) | STRONGLY SUPPORTED | `FUN_004731E0` performs `LOCK()`/`UNLOCK()` read at `obj + 0x20` |
| `0x28` | field_0x28 | State field (compared to 5) | HYPOTHESIS | `CMP [EDI+0x28], 5` in `FUN_0044F3F0`; 17 writers across 15 functions |
| `0x2C` | field_0x2C | Handle/flag field (compared to 0) | HYPOTHESIS | `CMP [EDI+0x2C], 0` in `FUN_0044F3F0`; 7 writers across 7 functions |
| `0x30` | field_0x30 | Call counter (incremented) | HYPOTHESIS | `INC [EDI+0x30]` in `FUN_0044F3F0`; initialized to 0 by `FUN_00410E80`/`FUN_00410F60` |
| `0x38` | field_0x38 | Subobject A vtable pointer | STRONGLY SUPPORTED | Constructor write `0x520014`, overwrite `0x51BE00` |
| `0x40` | field_0x40 | Subobject B vtable pointer | STRONGLY SUPPORTED | Constructor write `0x520020`, overwrite `0x51BE0C` |
| `0x50` | field_0x50 | Subobject C vtable pointer | STRONGLY SUPPORTED | Constructor write `0x520034`, overwrite `0x51BE20` |
| `0x98` | field_0x98 | Subobject D vtable pointer | STRONGLY SUPPORTED | Constructor write `0x520050`, overwrite `0x51E810` |
| `0x9C` | field_0x9C | Subobject E vtable pointer | STRONGLY SUPPORTED | Constructor write `0x5200E8`, overwrite `0x51E7F8` |
| `0x1D38` | field_0x1D38 | Table/data pointer | VERIFIED | Written by constructor sub-initializer `FUN_00483750` |
| `0x1E28`–`0x1E3C` | field_0x1E28–0x1E3C | Candidate reference counters | HYPOTHESIS (P2.3) / unconfirmed (P2.4) | XCHG/XADD cleanup pattern in constructor (P2.3); not verified by P2.4 disassembly |
| `0x1E40` | field_0x1E40 | Table base pointer (`0x51FFAC`) | VERIFIED | P2.3 report 17 |
| `0x1E44` | field_0x1E44 | Subobject pointer | VERIFIED | P2.3 report 17 |
| `0x1E48` | field_0x1E48 | Atomic reference counter | HYPOTHESIS (P2.3) / unconfirmed (P2.4) | Read by `FUN_0044F3F0` (`CMPXCHG.LOCK`) per P2.3 |
| `0x1E4C` | field_0x1E4C | Atomic reference counter | HYPOTHESIS (P2.3) / unconfirmed (P2.4) | Read by `FUN_0044F3F0` (`CMPXCHG.LOCK`) per P2.3 |
| `0x1E50` | field_0x1E50 | Atomic reference counter | HYPOTHESIS (P2.3) / unconfirmed (P2.4) | Read by `FUN_0044F3F0` (`CMPXCHG.LOCK`) per P2.3 |
| `0x1E58`–`0x5C40` | field_0x1E58–0x5C40 | Subobject initialization | VERIFIED | Constructor initializes through this range |
| `0x5C40` | field_0x5C40 | Last initialized field offset | VERIFIED | Constructor LEA to offset `0x5C40` |
| `0x214` | field_0x214 | Does not exist | REFUTED | No `MOV [EDI+0x214], imm32` anywhere in binary; no readers found |

**Estimated object size:** Minimum initialized extent `0x5C40` bytes (~23,264 bytes). Bulk initialization covers `0x0C`–`0x5BA0` (~0x5A94 bytes, ~23,220 bytes). P2.3 report 17 estimated ~`0x5C44` bytes (~23,220 bytes). Actual allocation size is UNKNOWN — no `HeapAlloc`/`RolClient_AllocMemory` call with a size argument was found.

**Subobject vtable pointers (initial values → overwrite values):**
| Offset | Initial value | Overwrite value | Confidence |
|---|---|---|---|
| `0x38` | `0x520014` | `0x51BE00` | STRONGLY SUPPORTED |
| `0x40` | `0x520020` | `0x51BE0C` | STRONGLY SUPPORTED |
| `0x50` | `0x520034` | `0x51BE20` | STRONGLY SUPPORTED |
| `0x98` | `0x520050` | `0x51E810` | STRONGLY SUPPORTED |
| `0x9C` | `0x5200E8` | `0x51E7F8` | STRONGLY SUPPORTED |

All 5 subobject vptrs are written by the constructor and then overwritten during a second construction phase.

---

## 2. Constructor Chain and Subinitializers

### 2.1 Primary constructor

**`FUN_0043E1A0`** (`0x0043E1A0`, 853 bytes, 36 basic blocks, `__thiscall(void *this)`)
- Only caller: `FUN_0043ECF0` (direct call at `0x43ECF6`)
- No external callers found — constructor reachable only via unreachable adjustment thunks
- Vptr transitions: 3 writes to `[EDI+0x00]` (see section 3)
- Subobject vtable writes at offsets `0x38`, `0x40`, `0x50`, `0x98`, `0x9C` (see section 3)
- Zeroing loop: `FUN_0043E100` called at `0x43E1E0`, range `[this+0x0C]` to `[this+0x4C4]`, 100 dwords step `0xC`
- Fields initialized up to offset `0x5C40`
- 12 sub-initializer calls

### 2.2 Constructor wrapper

**`FUN_0043ECF0`** (`0x0043ECF0`, 36 bytes, 3 blocks, `__thiscall`, returns `EAX = this`)

```
0x43ECF0: PUSH EBP; MOV EBP, ESP; PUSH ESI; MOV ESI, ECX
0x43ECF6: CALL 0x0043E1A0
0x43ECFB: TEST byte ptr [EBP+0x8], 0x1
0x43ECFF: JZ 0x0043EF0D
0x43ED01: PUSH 0x6108
0x43ED06: PUSH ESI
0x43ED07: CALL 0x004E6CD7        ; destruction wrapper (unusual in constructor path)
0x43ED0C: ADD ESP, 0x8
0x43ED0F: MOV EAX, ESI
0x43ED11: POP ESI
0x43ED12: POP EBP
0x43ED13: RET 0x4
```

Behavior: calls `FUN_0043E1A0`, then if the low bit of the first stack argument is set, calls `FUN_004E6CD7(this)` (destruction wrapper — suggests a conditional cleanup path).

### 2.3 Adjustment thunks (5)

All tail-jump to `FUN_0043ECF0`. Each subtracts a subobject offset from `ECX` to recover the main `this` pointer (multiple inheritance adjustment). None have any callers.

| Thunk | VA | Disassembly | Adjusts ECX by | Raw bytes |
|---|---|---|---|---|
| FUN_0043E85E | `0x43E85E` | `SUB ECX, 0x38; JMP 0x0043ECF0` | −0x38 | `83 E9 38 E9 8A 04 00 00` |
| FUN_0043E866 | `0x43E866` | `SUB ECX, 0x40; JMP 0x0043ECF0` | −0x40 | `83 E9 40 E9 80 04 00 00` |
| FUN_0043E86E | `0x43E86E` | `SUB ECX, 0x50; JMP 0x0043ECF0` | −0x50 | `83 E9 50 E9 7A 04 00 00` |
| FUN_0043E876 | `0x43E876` | `SUB ECX, 0x98; JMP 0x0043ECF0` | −0x98 | `83 E9 98 E9 70 04 00 00` |
| FUN_0043E881 | `0x43E881` | `SUB ECX, 0x9C; JMP 0x0043ECF0` | −0x9C | `83 E9 9C E9 6A 04 00 00` |

### 2.4 Twelve sub-initializers called by `FUN_0043E1A0`

| # | Address | Name | Status | Role |
|---|---|---|---|---|
| 1 | `0x43E100` | FUN_0043E100 | ANALYZED | Zeroing loop (`0x0C`–`0x4C4`) |
| 2 | `0x47A8A0` | FUN_0047A8A0 | NOT ANALYZED | Unknown |
| 3 | `0x43E500` | FUN_0043E500 | NOT ANALYZED (P2.4) / ANALYZED via bulk init (P2.3) | Bulk init at `[this+0x56F0]` |
| 4 | `0x403540` | FUN_00403540 | NOT ANALYZED | Unknown |
| 5 | `0x4728E0` | FUN_004728E0 | PARTIALLY ANALYZED | Called by `FUN_004802F0` and `FUN_0043A9A0`; body not decompiled |
| 6 | `0x483750` | FUN_00483750 | NOT ANALYZED | Unknown |
| 7 | `0x43E680` | FUN_0043E680 | NOT ANALYZED (P2.4) / ANALYZED via bulk init (P2.3) | Bulk init at `[this+0x108]` |
| 8 | `0x47BB20` | FUN_0047BB20 | NOT ANALYZED | Unknown |
| 9 | `0x475B70` | FUN_00475B70 | NOT ANALYZED (P2.4) / ANALYZED (P2.3) | Cleanup; called by `FUN_0043E1A0` (2×) and `FUN_0043EED0` |
| 10 | `0x479240` | FUN_00479240 | NOT ANALYZED (P2.4) / ANALYZED (P2.3) | Thunk → `FUN_004792C0` |
| 11 | `0x4E70a5` | FUN_004E70a5 | NOT ANALYZED (P2.4) / ANALYZED (P2.3) | `__eh_vector_destructor_iterator` |
| 12 | `0x43A9A0` | FUN_0043A9A0 | ANALYZED | List cleanup with `CUniversalString` |
| 13 | `0x4E7EC0` | FUN_004E7EC0 | ANALYZED | 5-byte thunk → `FUN_004ec736` (destruction, not initialization) |

Note: `FUN_004E7EC0` was listed as a sub-initializer but is actually a destruction thunk, not an initializer.

### 2.5 Bulk initialization loops

All use `__eh_vector_destructor_iterator` (`FUN_004E70a5`) to invoke a per-element function over a stepped dword range.

| # | Range | Count | Step | Per-element function | Purpose |
|---|---|---|---|---|---|
| 1 | `[this+0x0C]` to `[this+0x4C4]` | 100 | `0xC` | `FUN_0043a9a0` | Zero/init sub-objects |
| 2 | `[this+0x0C]` to `[this+0x4C4]` | 100 | `0xC` | `FUN_0043a9a0` | Vector destructor iterator |
| 3 | `[this+0x56F0]` to `[this+0x5BA0]` | 100 | `0xC` | `FUN_0043b470` | Zero/init sub-objects |
| 4 | `[this+0x56F0]` to `[this+0x5BA0]` | 100 | `0xC` | `FUN_0043b4c0` | Vector destructor iterator |
| 5 | `[this+0x3C24]` to `[this+0x4B24]` | 0x258 (600) | `0xC` | `FUN_0043b4c0` | Zero/init sub-objects |
| 6 | `[this+0x3C24]` to `[this+0x4B24]` | 0x258 (600) | `0xC` | `FUN_0043b4c0` | Vector destructor iterator |
| 7 | `[this+0x108]` to `[this+0x2008]` | 0x258 (600) | `0xC` | `FUN_00440670` | Zero/init sub-objects |
| 8 | `[this+0x108]` to `[this+0x2008]` | 0x258 (600) | `0xC` | `FUN_00440670` | Vector destructor iterator |

Total initialized range: `0x000C` to `0x5BA0` (~0x5A94 bytes).

**Per-element sub-initializer functions:**
- `FUN_0043a9a0` (`0x0043A9A0`, 82 bytes): writes vptr `0x51BD88` at `[this+0x0C]`, initializes sub-objects at `+0x18` and `+0x20`; calls `FUN_004728E0`, `FUN_00408AF0`
- `FUN_0043b470` (`0x0043B470`, 68 bytes): list node manipulation; calls `FUN_00475870`
- `FUN_0043b4c0` (`0x0043B4C0`, 68 bytes): list node manipulation; calls `FUN_00475870`
- `FUN_0043b420` (`0x0043B420`, 68 bytes): list node manipulation; calls `FUN_00475870`
- `FUN_00440670` (`0x00440670`, 55 bytes): list node manipulation; calls `FUN_00475870`
- `FUN_00475870`: object lookup / list head accessor (called by multiple initializers; body not analyzed)

**FAM RT C++ classes identified:**
- `FamRT::CFile::vftable` — referenced by `FUN_004802F0` (constructor at `0x4802F0`)
- `FamRT::CUniversalString::vftable` — referenced by `FUN_0043A9A0`

---

## 3. Vptr Transitions and Adjustment Thunks

### 3.1 Three vptr transitions in `FUN_0043E1A0`

| Phase | VA | Instruction | Raw bytes | Table | Slot 0 target |
|---|---|---|---|---|---|
| Initial | `0x43E1B1` | `MOV [EDI], 0x51FFB4` | `C7 03 B4 FF 51 00` | Table A (slot 2) | `FUN_0043ECF0` |
| Overwrite #2 | `0x43E4C8` | `MOV [EDI], 0x51E570` | `C7 03 70 E5 51 00` | Intermediate table B | `FUN_0043EED0` |
| Final | `0x43E4E8` | `MOV [EDI], 0x51E4F0` | `C7 03 F0 E4 51 00` | Final table C | `FUN_0043F110` |

### 3.2 Vtable tables

**Table A (base `0x0051FFAC`, 40 slots, 160 bytes):**
| Slot | VA | Value | Source |
|---|---|---|---|
| 0 | `0x51FFAC` | `0x0043E8E0` | Constructor initial write |
| 1 | `0x51FFB0` | `0x00539A4C` | Non-.text (data) |
| 2 | `0x51FFB4` | `0x0043ECF0` | First vptr write |
| 3 | `0x51FFB8` | `0x0044F3E0` | |
| 4 | `0x51FFBC` | `0x0044F3F0` | `FUN_0044F3F0` itself |
| 13 | `0x51FFE0` | `0x00451010` | |
| 22 | `0x520004` | `0x00451070` | Returns 0 |

Non-.text slots in Table A: slots 1, 25, 28, 33, 38 (values in `0x00539xxx` range).

**Table B (intermediate, `0x0051E570`, 23 slots):**
| Slot | VA | Value |
|---|---|---|
| 0 | `0x51E570` | `0x0043EED0` |
| 13 | `0x51E5A4` | `0x004510B0` |
| 22 | `0x51E5C4` | `0x00451090` |

**Table C (final, `0x0051E4F0`, 23 slots):**
| Slot | VA | Value |
|---|---|---|
| 0 | `0x51E4F0` | `0x0043F110` |
| 13 | `0x51E524` | `0x004510B0` |
| 22 | `0x51E544` | `0x00451090` |

Non-.text slots in Tables B and C: 3 slots each (values in `0x00539xxx` range).

### 3.3 Subobject vtable writes

**Initial (constructor phase 1):**
| VA | Offset | Value | Subobject |
|---|---|---|---|
| `0x43E1B7` | `+0x38` | `0x520014` | A |
| `0x43E1BE` | `+0x40` | `0x520020` | B |
| `0x43E1C5` | `+0x50` | `0x520034` | C |
| `0x43E1CC` | `+0x98` | `0x520050` | D |
| `0x43E1D6` | `+0x9C` | `0x5200E8` | E |

**Overwrite (constructor phase 2):**
| VA | Offset | Value |
|---|---|---|
| `0x43E4AE` | `+0x38` | `0x51BE00` |
| `0x43E4B5` | `+0x40` | `0x51BE0C` |
| `0x43E4BC` | `+0x50` | `0x51BE20` |
| `0x43E4A4` | `+0x98` | `0x51E810` |
| `0x43E49A` | `+0x9C` | `0x51E7F8` |

---

## 4. Field Writers and Readers

Writer/reader inventories were derived via REA `search_bytes` for `MOV [EDI+offset], imm32` patterns across the entire binary.

### field_0x28 — State field (17 writers, 15 functions)

Writers (all `MOV [EDI+0x28], imm32`):
| VA | Function | Confidence |
|---|---|---|
| `0x41414E` | FUN_00414020 | VERIFIED |
| `0x4143DE` | FUN_004142B0 | VERIFIED |
| `0x418972` | FUN_00418950 | VERIFIED |
| `0x418B2E` | FUN_00418950 | VERIFIED |
| `0x45A15A` | FUN_0045A0A0 | VERIFIED |
| `0x45AE1A` | FUN_0045AD60 | VERIFIED |
| `0x45E151` | FUN_0045E130 | VERIFIED |
| `0x45E1E8` | FUN_0045E130 | VERIFIED |
| `0x462705` | FUN_004626A0 | VERIFIED |
| `0x464901` | FUN_004648E0 | VERIFIED |
| `0x465069` | FUN_00464FE0 | VERIFIED |
| `0x474413` | FUN_00474370 | VERIFIED |
| `0x474438` | FUN_00474370 | VERIFIED |
| `0x479C8D` | FUN_00479A80 | VERIFIED |
| `0x4820AF` | FUN_00481F60 | VERIFIED |
| `0x4B1358` | FUN_004B1320 | VERIFIED |
| `0x4B1372` | FUN_004B1320 | VERIFIED |

Readers:
| VA | Function | Instruction | Confidence |
|---|---|---|---|
| `0x44F4EE` | FUN_0044F3F0 | `CMP [EDI+0x28], 5` | VERIFIED |
| `0x44F597` | FUN_0044F3F0 | `CMP [EDI+0x28], 5` | VERIFIED |
| `0x4738C6` | FUN_004738C0 | `CMP [EDI+0x28], ...` | VERIFIED |
| `0x4739F8` | FUN_004739F0 | `CMP [EDI+0x28], ...` | VERIFIED |
| `0x473BF6` | FUN_00473BF0 | `CMP [EDI+0x28], ...` | VERIFIED |
| `0x479BE6` | FUN_00479A80 | `CMP [EDI+0x28], ...` | VERIFIED |
| `0x481F97` | FUN_00481F60 | `CMP [EDI+0x28], ...` | VERIFIED |

**field_0x28 initial value:** UNKNOWN — no writer found in constructor `FUN_0043E1A0`.

### field_0x2C — Handle/flag field (7 writers, 7 functions)

Writers:
| VA | Function | Instruction | Confidence |
|---|---|---|---|
| `0x404936` | FUN_00404920 | `MOV [EDI+0x2C], imm32` | VERIFIED |
| `0x410EB6` | FUN_00410E80 | `MOV [EDI+0x2C], 0x0` | VERIFIED |
| `0x410F96` | FUN_00410F60 | `MOV [EDI+0x2C], 0x0` | VERIFIED |
| `0x414155` | FUN_00414020 | `MOV [EDI+0x2C], imm32` | VERIFIED |
| `0x4143E5` | FUN_004142B0 | `MOV [EDI+0x2C], imm32` | VERIFIED |
| `0x479C94` | FUN_00479A80 | `MOV [EDI+0x2C], imm32` | VERIFIED |
| `0x4E085F` | FUN_004E0780 | `MOV [EDI+0x2C], imm32` | VERIFIED |

Readers:
| VA | Function | Instruction | Confidence |
|---|---|---|---|
| `0x44F4F4` | FUN_0044F3F0 | `CMP [EDI+0x2C], 0` | VERIFIED |
| `0x44F59D` | FUN_0044F3F0 | `CMP [EDI+0x2C], 0` | VERIFIED |
| `0x44F523` | FUN_0044F3F0 | `PUSH [EDI+0x2c]` (arg to `SetServiceStatus`) | VERIFIED |
| `0x44F5CC` | FUN_0044F3F0 | `PUSH [EDI+0x2c]` (arg to `SetServiceStatus`) | VERIFIED |
| `0x479BF0` | FUN_00479A80 | `CMP [EDI+0x2C], ...` | VERIFIED |

**field_0x2C initial value:** UNKNOWN — no writer found in constructor.

### field_0x30 — Call counter (3 writers, 2 readers)

| VA | Function | Instruction | Raw bytes | Confidence |
|---|---|---|---|---|
| `0x410EBD` | FUN_00410E80 | `MOV [EDI+0x30], 0x0` | `C7 47 30 00 00 00 00` | VERIFIED |
| `0x410F9D` | FUN_00410F60 | `MOV [EDI+0x30], 0x0` | `C7 47 30 00 00 00 00` | VERIFIED |
| `0x44F4FE` | FUN_0044F3F0 | `INC [EDI+0x30]` | `FF 47 30` | VERIFIED |
| `0x44F5A7` | FUN_0044F3F0 | `INC [EDI+0x30]` | `FF 47 30` | VERIFIED |

Readers:
| VA | Function | Instruction | Raw bytes |
|---|---|---|---|
| `0x44F513` | FUN_0044F3F0 | `MOV EAX, [EDI+0x30]` | `8B 47 30` |
| `0x44F5BC` | FUN_0044F3F0 | `MOV EAX, [EDI+0x30]` | `8B 47 30` |

**field_0x30 initial value:** `0` (confirmed — set by `FUN_00410E80`/`FUN_00410F60`). `field_0x30` is incremented ONLY in `FUN_0044F3F0` (2 call sites).

### field_0x214 — REFUTED

Search for `MOV [EDI+0x214], imm32` (`C7 47 214 ...`) across the entire binary returned NO RESULTS. No readers found. Previous claim of a write at `0x42173B` could not be verified. **field_0x214 does not exist in this object, or is never written.**

### Complete field writer summary

| Offset | Writers | Readers | Writer functions | Reader functions | Confidence |
|---|---|---|---|---|---|
| `0x00` | 6 | `FUN_0044F3F0` (2×) | `FUN_0043E1A0`, `FUN_0043E100`, `FUN_0047A8A0`, `FUN_00403540`, `FUN_0047BB20` | `FUN_0044F3F0` | STRONGLY SUPPORTED |
| `0x04` | 1 | None | `FUN_00479240` | 0 | VERIFIED |
| `0x0C` | 2 | None | `FUN_0043E100`, `FUN_00475B70` | 0 | VERIFIED |
| `0x20` | 0 | `FUN_0044F3F0` (2×) | 0 | 1 | VERIFIED |
| `0x28` | 17 | `FUN_0044F3F0` (2×), `FUN_004738C0`, `FUN_004739F0`, `FUN_00473BF0`, `FUN_00479A80`, `FUN_00481F60` | 15+ | 6 | STRONGLY SUPPORTED |
| `0x2C` | 7 | `FUN_0044F3F0` (4×), `FUN_00479A80` | `FUN_00404920`, `FUN_00410E80`, `FUN_00410F60`, `FUN_00414020`, `FUN_004142B0`, `FUN_00479A80`, `FUN_004E0780` | 6 | VERIFIED |
| `0x30` | 3 | `FUN_0044F3F0` (2×) | `FUN_00410E80`, `FUN_00410F60`, `FUN_0044F3F0` | 2 | VERIFIED |
| `0x214` | 0 | 0 | 0 | 0 | REFUTED |

### Semantic naming — RESTRICTED

Per evidence standards, the following names are NOT assigned because evidence does not support them: `state` for `field_0x28`, `handle` for `field_0x2C`, `counter` for `field_0x30`, `session_id` for any field, `refcount` for `obj + 0x20` (atomic access suggests it, but not confirmed). Neutral names (`field_0xXX`) are used throughout.

---

## 5. FUN_0044F3F0 — Indirect Dispatch

**`FUN_0044F3F0`** (`0x0044F3F0`, 696 bytes, 26 blocks, `__thiscall`, `ECX = this / EDI`). Category: OBJECT_METHOD. No direct callers found (REA `procedure_callers` empty); reachable only via indirect vtable dispatch.

### 5.1 Call sites and guard condition

| VA | Instruction | Raw bytes | Purpose |
|---|---|---|---|
| `0x44F4EE` | `CMP [EDI+0x28], 5` | `83 7F 28 05` | Guard: `field_0x28 == 5` |
| `0x44F4F4` | `CMP [EDI+0x2C], 0` | `83 7F 2C 00` | Guard: `field_0x2C != 0` |
| `0x44F4FE` | `INC [EDI+0x30]` | `FF 47 30` | `field_0x30++` |
| `0x44F4FA` | `MOV EAX, [EDI]` | `8B 07` | Load vptr |
| `0x44F501` | `CALL [EAX+0x34]` | `FF 50 34` | Slot 13 (call pair 1) |
| `0x44F50D` | `CALL [EAX+0x58]` | `FF 50 58` | Slot 22 (call pair 1) |
| `0x44F5AA` | `CALL [EAX+0x34]` | `FF 50 34` | Slot 13 (call pair 2) |
| `0x44F5B6` | `CALL [EAX+0x58]` | `FF 50 58` | Slot 22 (call pair 2) |

Guard logic: indirect calls execute only if `field_0x28 == 5 && field_0x2C != 0`. If either condition fails, calls are skipped.

### 5.2 Slot targets under each vptr state

| Vptr value | Table | Slot 13 (`[EAX+0x34]`) target | Returns | Slot 22 (`[EAX+0x58]`) target | Returns |
|---|---|---|---|---|---|
| `0x51FFB4` (initial, Table A slot 2) | A | `FUN_00451010` | 0 | `FUN_00450FA0` | 0 or `0xC5` |
| `0x51FFAC` (base) | A | `FUN_00451010` | 0 | `FUN_00451070` | 0 |
| `0x51E570` (intermediate, Table B) | B | `FUN_004510B0` | `0x10` (16) | `FUN_00451090` | 0 |
| `0x51E4F0` (final, Table C) | C | `FUN_004510B0` | `0x10` (16) | `FUN_00451090` | 0 |

### 5.3 Target function details

- **`FUN_004510A0`** (`0x4510A0`, 3 bytes): `MOV EAX, 0x10; RET` — returns 16
- **`FUN_00451010`** (`0x451010`, 3 bytes): `XOR EAX, EAX; RET` — returns 0
- **`FUN_004510B0`** (`0x4510B0`, 6 bytes): `MOV EAX, 0x10; RET` — returns 16
- **`FUN_00451070`** (`0x451070`, 3 bytes): `XOR EAX, EAX; RET` — returns 0
- **`FUN_00451090`** (`0x451090`, 3 bytes): `XOR EAX, EAX; RET` — returns 0
- **`FUN_00450FA0`** (`0x450FA0`, 31 bytes, 4 blocks): returns 0 if `param_1 == 2` or `0x20`; returns `0xC5` (197) otherwise

**Runtime vptr state:** UNKNOWN (BLOCKED — no Windows debugger available; `FUN_0044F3F0` has no direct callers; constructor chain unreachable from known code).

---

## 6. Refcount and Destroy Path

### 6.1 Reference count location

**`obj + 0x20`** is the confirmed reference count location. `FUN_004731E0` performs an atomic `LOCK()`/`UNLOCK()` read of `param_1 + 0x20`.

**P2.3 candidate reference counters (not confirmed by P2.4 disassembly):**
| Offset | Classification | Evidence (P2.3) |
|---|---|---|
| `[old_vtable+0x4]` | Candidate reference counter | `XADD.LOCK` decrement pattern in constructor |
| `[this+0x1E28]`–`[this+0x1E3C]` | Candidate reference counters | XCHG/XADD cleanup pattern in constructor |
| `[this+0x1E48]` | Atomic reference counter | Read by `FUN_0044F3F0` (`CMPXCHG.LOCK`) |
| `[this+0x1E4C]` | Atomic reference counter | Read by `FUN_0044F3F0` (`CMPXCHG.LOCK`) |
| `[this+0x1E50]` | Atomic reference counter | Read by `FUN_0044F3F0` (`CMPXCHG.LOCK`) |

P2.4 assessment: only `obj + 0x20` has confirmed `LOCK`/`UNLOCK` atomic access. The `0x1E28`–`0x1E50` region was hypothesized in P2.3 but not verified by P2.4 instruction-level analysis. Multiple independent reference counters are possible but unconfirmed.

### 6.2 Release function: `FUN_004731E0`

**`FUN_004731E0`** (`0x004731E0`, 44 bytes, 3 blocks, `__fastcall`, `ECX = this / param_1`)

```c
void __fastcall FUN_004731e0(int param_1)
{
  int *piVar1;
  int iVar2;
  DWORD dwErrCode;

  dwErrCode = GetLastError();
  piVar1 = (int *)(param_1 + 0x20);  // refcount at obj + 0x20
  LOCK();
  iVar2 = *piVar1;                   // atomic read
  *piVar1 = *piVar1;                 // no-op write (compiler memory barrier)
  UNLOCK();
  if (iVar2 != 0) {
    FUN_00473210(param_1);           // decrement and destroy if zero
  }
  SetLastError(dwErrCode);
  return;
}
```

Behavior: COM-style `Release()` semantics. Saves `GetLastError()`, atomically reads the refcount at `obj + 0x20`, if non-zero calls `FUN_00473210`, restores `GetLastError()`. The `*piVar1 = *piVar1` no-op write serves as a compiler memory barrier ensuring the `LOCK`-prefixed read has full acquire semantics.

**AddRef function:** NOT identified. No function found that increments the reference count at `obj + 0x20`. Search approaches: `LOCK` + `ADD`/`XADD` targeting `obj + 0x20`; functions writing to `obj + 0x20` with increment pattern. Confidence: UNKNOWN.

**`FUN_00473210`** (`0x00473210`): referenced by `FUN_004731E0` (called if refcount != 0). Expected role: decrement-and-destroy-if-zero. Status: NOT analyzed — Ghidra auto-analysis did not create a function entry at `0x473210`, or it was not among functions analyzed. Need REA `procedure_info` at `0x473210`.

### 6.3 Destructor functions

| Function | VA | Size | Role | Classification |
|---|---|---|---|---|
| `FUN_0043EED0` | `0x43EED0` | 68 bytes, 3 blocks | Intermediate table slot 0 destructor; sets vptr to `0x51E570`, releases subobjects | STRONGLY SUPPORTED |
| `FUN_0043F110` | `0x43F110` | 36 bytes, 3 blocks | Final table slot 0; MSVC scalar deleting destructor (`std::_Facet_base::scalar_deleting_destructor`); sets vptr to `0x51E4F0`, releases subobject at `+0x4` | VERIFIED |

**`FUN_0043EED0`** behavior: sets vptr to intermediate table (`0x51E570`), releases subobject at `+0x0C` via `FUN_00475B70`, releases subobject at `+0x04` via thunk `FUN_00479240`→`FUN_004792C0`, conditionally sets vptr to final table (`0x51E4F0`) and frees object with size `0x34` via `FUN_004E6CD7`.

**`FUN_0043F110`** behavior: sets vptr to final table (`0x51E4F0`), conditionally releases subobject at `+0x4` with size 4 via `FUN_004E6CD7`, returns `this`.

---

## 7. Allocation/Deallocation

### 7.1 Allocator APIs imported

| DLL | Function | Role | IAT RVA | Confidence |
|---|---|---|---|---|
| `KERNEL32.dll` | `HeapAlloc` | Heap memory allocation | `0x11941e` | CONFIRMED |
| `KERNEL32.dll` | `HeapFree` | Heap memory deallocation | `0x11942a` | CONFIRMED |
| `KERNEL32.dll` | `HeapReAlloc` | Heap memory reallocation | `0x119436` | CONFIRMED |
| `KERNEL32.dll` | `HeapSize` | Query heap block size | `0x11959c` | CONFIRMED |
| `KERNEL32.dll` | `GetProcessHeap` | Get process heap handle | `0x11957a` | CONFIRMED |
| `RvROLClient.dll` | `RolClient_AllocMemory` | Custom ROL client allocation | `0x1199c0` | CONFIRMED |
| `RvROLClient.dll` | `RolClient_FreeMemory` | Custom ROL client deallocation | `0x11998c` | CONFIRMED |
| `ole32.dll` | `CoTaskMemFree` | COM task memory deallocation | `0x119942` | CONFIRMED |
| `KERNEL32.dll` | `LocalFree` | Local memory deallocation | `0x117cd4` | CONFIRMED |

**Not imported:** `malloc`, `operator new`, `CoTaskMemAlloc`, `VirtualAlloc`, `LocalAlloc`.

### 7.2 Allocation site — UNKNOWN

No direct call to `HeapAlloc` or `RolClient_AllocMemory` was found in:
- `FUN_0043E1A0` (constructor)
- `FUN_0043ECF0` (constructor wrapper)
- Any of the 5 adjustment thunks
- Any of the 12 sub-initializers

Possible explanations (all unverified):
1. Object is stack-allocated or embedded in a parent object — caller allocates space and passes `this` via `ECX`
2. Object is allocated by a factory function not yet identified
3. Object is allocated via `RolClient_AllocMemory` from `RvROLClient.dll`
4. Object is globally allocated (static in `.data`/`.bss`)

### 7.3 Deallocation target — UNKNOWN

Final deallocation is `CALL dword ptr [0x00500ca6]` in `FUN_004ec736`. The slot at VA `0x500CA6` (RVA `0x100CA6`) falls in the gap between `.rdata` (ends `0x149600`) and `.data` (starts `0x14A000`) — section placement needs `REA read_bytes` verification. Candidate targets: `HeapFree`, `RolClient_FreeMemory`, `CoTaskMemFree`, `LocalFree`. Cannot be determined statically.

### 7.4 Allocation/deallocation symmetry — UNKNOWN

| Pair | Allocation | Deallocation | Symmetric? |
|---|---|---|---|
| `HeapAlloc` / `HeapFree` | Not found in object path | `CALL [0x00500ca6]` may be `HeapFree` | Cannot confirm |
| `RolClient_AllocMemory` / `RolClient_FreeMemory` | Not found in object path | `CALL [0x00500ca6]` may be `RolClient_FreeMemory` | Cannot confirm |
| `CoTaskMemAlloc` / `CoTaskMemFree` | `CoTaskMemAlloc` NOT imported | `CoTaskMemFree` imported | ASYMMETRIC |
| `LocalAlloc` / `LocalFree` | `LocalAlloc` NOT imported | `LocalFree` imported | ASYMMETRIC |

---

## 8. Destruction Chain

### 8.1 Complete chain

```
Release: FUN_004731E0
  └─ Atomic LOCK/UNLOCK read of refcount at obj+0x20
  └─ If refcount != 0: FUN_00473210 (decrement-and-destroy-if-zero, NOT ANALYZED)
       └─ List cleanup functions (5 total)
            └─ Per node: FUN_004e6cd7(node)
                 └─ thunk_FUN_004ec736 (JMP 0x4ec736)
                      └─ FUN_004ec736: CALL dword ptr [0x00500ca6]  ← FINAL DEALLOCATION
```

### 8.2 Destruction chain raw bytes

| Function | VA | Disassembly | Raw bytes |
|---|---|---|---|
| `FUN_004e6cd7` | `0x4E6CD7` | `PUSH [EBP+0x8]; CALL 0x004E7EC0` | `FF 75 08 E8 ?? ?? ?? ??` |
| `thunk_FUN_004ec736` | `0x4E7EC0` | `JMP 0x004EC736` | `E9 ?? ?? ?? ??` |
| `FUN_004ec736` | `0x4EC736` | `CALL dword ptr [0x00500ca6]` | `FF 15 A6 0C 50 00` |

### 8.3 Five list cleanup functions

All share the traversal pattern: `FUN_00475870(list_head)` pops head node → unlink node → self-reference node → subobject cleanup → `FUN_004e6cd7(node)` → repeat until empty.

| Function | Address | Subobject cleanup offset | Subobject cleanup function |
|---|---|---|---|
| `FUN_00440670` | `0x440670` | (none) | (none) |
| `FUN_0043B470` | `0x43b470` | `+0x18` | `FUN_0047b450` |
| `FUN_0043B4C0` | `0x43b4c0` | `+0x08` | `FUN_0047b450` |
| `FUN_0043B420` | `0x43b420` | `+0x10` | `FUN_0047b450` |
| `FUN_0043A9A0` | `0x43a9a0` | `+0x48` | `FUN_004728e0` + `FUN_00408af0` |

### 8.4 Other destruction-related functions

- **`FUN_00475C00`** (`0x475c00`, 67 bytes): Registry key close — closes `HKEY` at `obj + 8` via `RegCloseKey`, nulls handle, resets `SetLastError(0)`.
- **`FUN_00451900`** (`0x451900`, 49 bytes): Event unregister — calls `EventUnregister(*param_1)` on ETW registration handle, zeroes handle.
- **`FUN_0046AE70`** / **`FUN_0046B9F0`**: Thread-safe getter/setter for global flag `DAT_0055e3fd` with critical section at `DAT_0055e428`, initialization flag `DAT_0055e444`. Global state, not object lifecycle.
- **`FUN_004831F0`** (`0x4831f0`, 120 bytes): Calls `PerfStopProvider` from `advapi32.dll` for ETW provider shutdown.

### 8.5 Intermediate and final destructors (vtable slot 0)

`FUN_0043EED0` (intermediate, `0x43EED0`) and `FUN_0043F110` (final, `0x43F110`) are vtable slot 0 entries but are never called from any reachable code path (destructor chain unreachable from statically discoverable code).

---

## 9. Lifecycle Model

### 9.1 Phase-by-phase status

| Phase | Function(s) | Key actions | Confidence |
|---|---|---|---|
| Allocation | UNKNOWN | Allocate object memory | UNKNOWN |
| Construction | `FUN_0043ECF0` → `FUN_0043E1A0` | 3 vptr transitions, subobject vptrs, field init, 12 sub-initializers | VERIFIED (static) |
| AddRef | Unknown (not found) | Increment refcount at `obj + 0x20` | UNKNOWN |
| Release | `FUN_004731E0` | Atomic read refcount at `obj + 0x20`, call `FUN_00473210` | VERIFIED |
| Destroy | `FUN_00473210` → list cleanup | Decrement refcount, destroy list nodes | PARTIAL (`FUN_00473210` not analyzed) |
| Node destroy | `FUN_004e6cd7` → thunk → `[0x500ca6]` | Per-node deallocation | VERIFIED (chain), UNKNOWN (final target) |

### 9.2 Key gaps

| Gap | Impact | Blocks Rust? |
|---|---|---|
| Allocation call site not found | Cannot determine object size or owner | No |
| `FUN_00473210` not analyzed | Cannot confirm decrement/destroy logic | No |
| AddRef not identified | Cannot confirm complete refcount lifecycle | No |
| `[0x00500ca6]` target unresolved | Cannot confirm deallocation API | No |
| Runtime vptr state unknown | Cannot confirm indirect dispatch behavior | No |
| Object actual allocation size | Cannot confirm exact memory layout | No |

### 9.3 Construction/destruction symmetry

| Aspect | Construction | Destruction | Symmetric? |
|---|---|---|---|
| Vptr writes | 3 transitions (`0x51FFB4` → `0x51E570` → `0x51E4F0`) | 1 transition (to final vtable in `FUN_0043EED0`) | NO |
| Subobject initialization | 7+ subobject initializers | Subobject release calls | PARTIAL |
| Ref-counted cleanup | Multiple XCHG/XADD chains | Single destructor call per vptr | PARTIAL |
| Allocator | Not found | `FUN_004E6CD7` (free with size) | NO |

**Not symmetric.** Construction is more complex than destruction, and the allocator is not identified.

---

## 10. Rust Mapping Note

| Windows pattern | Rust equivalent | Viability |
|---|---|---|
| Refcounted object (`obj+0x20`) | `Arc<T>` | VIABLE |
| Release (`FUN_004731E0`) | `impl Drop` | VIABLE |
| AddRef (not found) | `Arc::clone()` | VIABLE (but AddRef not found in binary) |
| List cleanup (5 functions) | `Vec<Arc<T>>` / `LinkedList<Arc<T>>` | VIABLE |
| `field_0x28` (state, compared to 5) | `enum SessionState` | VIABLE |
| `field_0x2C` (flag, compared to 0) | `bool` / `Option<T>` | VIABLE |
| `field_0x30` (counter) | `AtomicU64` / `u64` | VIABLE |
| C++ vtable transitions | NOT VIABLE | REJECTED — Rust trait objects use different layout |
| Adjustment thunks | NOT VIABLE | REJECTED — Rust doesn't have `this` pointer adjustment |
| Manual `HeapAlloc`/`HeapFree` | NOT VIABLE | REJECTED |
| Windows APIs (`RegCloseKey`, `EventUnregister`) | NOT VIABLE | REJECTED |

**Note:** The C++ vtable layout (3-phase transitions, adjustment thunks, manual vptr overwrites) has no direct Rust equivalent and is explicitly rejected for the Rust implementation. Reference-counted destruction maps to Rust `Arc<T>`/`Rc<T>` + `Drop` (PARTIAL — viable if shared ownership is genuinely needed, but which entity is reference-counted is unknown).

---

## 11. Provenance Note

This document consolidates Phase 2.3 and Phase 2.4 OBJECT_LIFECYCLE reports (36 sources listed in ## Sources below). Phase 2.5 supersedes several Phase 2.4 claims, specifically in the areas of: (a) corrected indirect dispatch targets (Phase 2.5 report `04_CORRECTED_INDIRECT_DISPATCH_TARGETS.md` supersedes Phase 2.4 report `05_RUNTIME_VPTR_AND_INDIRECT_DISPATCH.md`), (b) reference count increment/release search (Phase 2.5 report `07_REFERENCE_COUNT_INCREMENT_AND_RELEASE_SEARCH.md` supersedes Phase 2.4 report `07_REFERENCE_COUNT_AND_ADDREF_RELEASE_ANALYSIS.md`), (c) object field initialization reconstruction (Phase 2.5 report `08_OBJECT_FIELD_INITIALIZATION_RECONSTRUCTION.md` supersedes Phase 2.4 report `06_OBJECT_FIELD_INITIALIZATION_AND_STATE.md`), and (d) subinitializer inventory (Phase 2.5 reports `09_SUBINITIALIZER_COMPLETE_INVENTORY.md` and `10_SUBINITIALIZER_DETAILED_ANALYSIS.md` supersede Phase 2.4 report `10_SUBINITIALIZER_AND_SUBOBJECT_ANALYSIS.md`). Both the Phase 2.4 claims (recorded above with their original confidence classifications) and the Phase 2.5 corrections should be cross-referenced in `RECONCILIATION.md`, which documents the authoritative resolution of contradictions between phases. Where this document and `RECONCILIATION.md` disagree, `RECONCILIATION.md` takes precedence.

All technical facts in this document are traceable to static REA/Ghidra evidence (raw byte extraction, `procedure_info`, `procedure_pseudo_code`, `procedure_callers`, `inspect_pe_imports`, `read_bytes`). Runtime-dependent questions (runtime vptr state, allocation call site, `[0x00500ca6]` target, AddRef) are classified as BLOCKED or UNKNOWN and do not block Rust implementation.

---

## 12. Sources

All 36 sources mapped to `OBJECT_LIFECYCLE` in `analysis_workspace/compaction/mapping.tsv`, read in full:

**Phase 2.3 (20 sources):**
1. `docs/PHASE_2_3/00_ENVIRONMENT_AND_PRESERVATION.md`
2. `docs/PHASE_2_3/03_OBJECT_LIFECYCLE_AND_OWNERSHIP.md`
3. `docs/PHASE_2_3/04_FIELD_WRITER_READER_ANALYSIS.md`
4. `docs/PHASE_2_3/05_FACTORY_AND_ALLOCATION_ANALYSIS.md`
5. `docs/PHASE_2_3/06_OBJECT_LIFECYCLE_AND_OWNERSHIP.md`
6. `docs/PHASE_2_3/07_FUN_00451090_ANALYSIS.md`
7. `docs/PHASE_2_3/08_VPTR_STATE_AND_DISPATCH_ANALYSIS.md`
8. `docs/PHASE_2_3/09_BULK_INITIALIZATION_ANALYSIS.md`
9. `docs/PHASE_2_3/10_SYMBOL_AND_STRING_EVIDENCE.md`
10. `docs/PHASE_2_3/11_CALLER_AND_CROSS_MODULE_ANALYSIS.md`
11. `docs/PHASE_2_3/13_MASTER_FUNCTION_INVENTORY.md`
12. `docs/PHASE_2_3/14_AUTHORITATIVE_FINDING_REGISTRY.md`
13. `docs/PHASE_2_3/17_FINAL_TECHNICAL_REPORT.md`
14. `docs/PHASE_2_3/18_RAW_EVIDENCE_APPENDIX.md`
15. `docs/PHASE_2_3/19_COMPLETION_AND_PRESERVATION.md`
16. `docs/PHASE_2_3/20_REMAINING_FUNCTION_ANALYSIS.md`
17. `docs/PHASE_2_3/21_ALLOCATOR_AND_ALLOCATION_SITE.md`
18. `docs/PHASE_2_3/22_OBJECT_LIFECYCLE_DESTRUCTION_CHAIN.md`
19. `docs/PHASE_2_3/CHECKPOINT_00_ENVIRONMENT.md`
20. `docs/PHASE_2_3/CHECKPOINT_02_STATIC_ANALYSIS_COMPLETE.md`

**Phase 2.4 (16 sources):**
21. `docs/PHASE_2_4/00_ENVIRONMENT_AND_REPOSITORY_PRESERVATION.md`
22. `docs/PHASE_2_4/01_COMPLETE_DOCUMENTATION_INVENTORY.md`
23. `docs/PHASE_2_4/03_BINARY_IDENTITY_AND_TOOL_VALIDATION.md`
24. `docs/PHASE_2_4/04_CONSTRUCTOR_AND_ALLOCATION_CALL_GRAPH.md`
25. `docs/PHASE_2_4/05_RUNTIME_VPTR_AND_INDIRECT_DISPATCH.md`
26. `docs/PHASE_2_4/06_OBJECT_FIELD_INITIALIZATION_AND_STATE.md`
27. `docs/PHASE_2_4/07_REFERENCE_COUNT_AND_ADDREF_RELEASE_ANALYSIS.md`
28. `docs/PHASE_2_4/08_INDIRECT_DEALLOCATION_TARGET_ANALYSIS.md`
29. `docs/PHASE_2_4/09_ALLOCATION_DEALLOCATION_SYMMETRY.md`
30. `docs/PHASE_2_4/10_SUBINITIALIZER_AND_SUBOBJECT_ANALYSIS.md`
31. `docs/PHASE_2_4/11_COMPLETE_OBJECT_LIFECYCLE_MODEL.md`
32. `docs/PHASE_2_4/12_RUNTIME_EVIDENCE_AND_REPRODUCTION_LOG.md`
33. `docs/PHASE_2_4/14_AUTHORITATIVE_FINDING_REGISTRY.md`
34. `docs/PHASE_2_4/17_FINAL_TECHNICAL_REPORT.md`
35. `docs/PHASE_2_4/18_RAW_EVIDENCE_APPENDIX.md`
36. `docs/PHASE_2_4/19_COMPLETION_AND_REPOSITORY_PRESERVATION.md`

**Total: 36 sources consumed.**

---

## Evidence appendix (exact tokens from consolidated sources)

Exact addresses, hashes and identifiers from the consolidated sources that are not repeated in the prose above. They are preserved here so that no evidence anchor is lost during compaction; the full narrative for each source remains available in git history.

- `docs/PHASE_2_3/03_OBJECT_LIFECYCLE_AND_OWNERSHIP.md`: `0x0043f12d`, `0x00519260`, `0x00519280`, `0x0055e264`, `0x43e15e`, `0x43e167`, `0x43e24c`, `0x43e257`, `0x43e27b`, `0x43e286`, `0x43e2ae`, `0x43e2b9`, `0x43eed1`, `0x43eed3`, `0x43eed4`, `0x43eed6`, `0x43eedc`, `0x43eedf`, `0x43eeee`, `0x43eef0`, `0x43eef1`, `0x43eef2`, `0x43eef4`, `0x43eef5`, `0x43eef6`, `0x43eefa`, `0x43eefd`, `0x43eeff`, `0x43ef00`, `0x43ef01`, `0x43f111`, `0x43f113`, `0x43f117`, `0x43f118`, `0x43f11a`, `0x43f120`, `0x43f122`, `0x43f124`, `0x43f125`, `0x43f12a`, `0x43f12d`, `0x43f12f`, `0x43f130`, `0x43f131`, `0xffffffff`
- `docs/PHASE_2_3/04_FIELD_WRITER_READER_ANALYSIS.md`: `0x00410ed9`, `0x00410f07`, `0x00479cfc`, `0x0054a008`, `0x410ea6`, `0x410eac`, `0x410ec4`, `0x410ec6`, `0x410ec8`, `0x410ec9`, `0x410ef6`, `0x410efa`, `0x410efc`, `0x410efe`, `0x410eff`, `0x410f04`, `0x479bea`, `0x479bf4`, `0x51c608`, `0x51c610`
- `docs/PHASE_2_3/06_OBJECT_LIFECYCLE_AND_OWNERSHIP.md`: `0x0043f12d`, `0x00519260`, `0x00519280`, `0x0055e264`, `0x43e15e`, `0x43e167`, `0x43e24c`, `0x43e257`, `0x43e27b`, `0x43e286`, `0x43e2ae`, `0x43e2b9`, `0x43eed1`, `0x43eed3`, `0x43eed4`, `0x43eed6`, `0x43eedc`, `0x43eedf`, `0x43eeee`, `0x43eef0`, `0x43eef1`, `0x43eef2`, `0x43eef4`, `0x43eef5`, `0x43eef6`, `0x43eefa`, `0x43eefd`, `0x43eeff`, `0x43ef00`, `0x43ef01`, `0x43f111`, `0x43f113`, `0x43f117`, `0x43f118`, `0x43f11a`, `0x43f120`, `0x43f122`, `0x43f124`, `0x43f125`, `0x43f12a`, `0x43f12d`, `0x43f12f`, `0x43f130`, `0x43f131`, `0xffffffff`
- `docs/PHASE_2_3/07_FUN_00451090_ANALYSIS.md`: `0x451092`, `0x52000c`
- `docs/PHASE_2_3/08_VPTR_STATE_AND_DISPATCH_ANALYSIS.md`: `0x00450fb9`, `0x450fb9`
- `docs/PHASE_2_3/09_BULK_INITIALIZATION_ANALYSIS.md`: `0x0043e137`, `0x0043e540`, `0x0043e580`, `0x0043e710`, `0x43e12f`, `0x43e132`, `0x43e137`, `0x43e139`, `0x43e13e`, `0x43e141`, `0x43e144`, `0x43e158`, `0x43e159`, `0x43e234`, `0x43e492`, `0x43e52e`, `0x43e534`, `0x43e540`, `0x43e542`, `0x43e547`, `0x43e54a`, `0x43e54d`, `0x43e565`, `0x43e571`, `0x43e577`, `0x43e580`, `0x43e582`, `0x43e587`, `0x43e58a`, `0x43e58d`, `0x43e5a8`, `0x43e703`, `0x43e706`, `0x43e710`, `0x43e712`, `0x43e717`, `0x43e71a`, `0x43e71d`, `0x43e735`
- `docs/PHASE_2_3/10_SYMBOL_AND_STRING_EVIDENCE.md`: `0x0055e264`, `0x43e4d1`, `0x43e6b6`, `0x46ae75`, `0x46ae87`, `0x46ae99`, `0x46b9f8`, `0x46ba0a`, `0x46ba1f`, `0x472928`, `0x474800`, `0x474870`, `0x475c11`, `0x48321b`, `0x48322f`, `0x5190a4`, `0x519200`, `0x519204`, `0x54a008`, `0x55e084`, `0x55e264`, `fun_00403700`
- `docs/PHASE_2_3/13_MASTER_FUNCTION_INVENTORY.md`: `0x4038a0`, `0x4040e0`, `0x43c740`, `0x441cb0`, `0x4833c0`, `0x4e6f8b`, `fun_00403530`, `fun_004038a0`, `fun_004040e0`, `fun_0043c740`, `fun_00441cb0`, `fun_0047a860`, `fun_004833c0`, `fun_004e6f8b`
- `docs/PHASE_2_3/18_RAW_EVIDENCE_APPENDIX.md`: `0x00001000`, `0x00011900`, `0x0001a900`, `0x0001c100`, `0x0001d8f0`, `0x0001d970`, `0x00030600`, `0x0003e5a0`, `0x0003ec5e`, `0x0003ec66`, `0x0003ec6e`, `0x0003ec76`, `0x0003ec81`, `0x0003edf0`, `0x0004e7f0`, `0x0004e80a`, `0x0004e8ee`, `0x0004e8f4`, `0x0004e8fa`, `0x0004e8fe`, `0x0004e901`, `0x0004e90d`, `0x0004e9aa`, `0x0004e9b6`, `0x0004f40a`, `0x00117600`, `0x00117a00`, `0x00119000`, `0x0011e9ac`, `0x0011e9b4`, `0x0011e9bc`, `0x0011ffac`, `0x0011ffb4`, `0x0011ffbc`, `0x0014000`, `0x00148000`, `0x0014e00`, `0x0015c000`, `0x00173e00`, `0x0017e00`, `0x001a9000`, `0x001c1000`, `0x401000`, `0x44f40a`, `0x519000`
- `docs/PHASE_2_3/20_REMAINING_FUNCTION_ANALYSIS.md`: `fun_00403700`, `fun_004038a0`, `fun_004776f0`
- `docs/PHASE_2_4/00_ENVIRONMENT_AND_REPOSITORY_PRESERVATION.md`: `90a1b2346e529dc4df1f216634098d5902238d2b`
- `docs/PHASE_2_4/03_BINARY_IDENTITY_AND_TOOL_VALIDATION.md`: `0x00001000`, `0x00011900`, `0x00014000`, `0x00014e00`, `0x00017e00`, `0x0001a900`, `0x0001c100`, `0x00030600`, `0x00117600`, `0x00117a00`, `0x00119000`, `0x00148000`, `0x0015c000`, `0x00173e00`, `0x001a9000`, `0x001c1000`
- `docs/PHASE_2_4/05_RUNTIME_VPTR_AND_INDIRECT_DISPATCH.md`: `0x520010`, `0x52001c`, `0x520030`, `0x520048`
- `docs/PHASE_2_4/07_REFERENCE_COUNT_AND_ADDREF_RELEASE_ANALYSIS.md`: `0x4e6cdb`
- `docs/PHASE_2_4/08_INDIRECT_DEALLOCATION_TARGET_ANALYSIS.md`: `0x00148000`, `0x0014e000`, `0x119000`
- `docs/PHASE_2_4/10_SUBINITIALIZER_AND_SUBOBJECT_ANALYSIS.md`: `fun_004776f0`
- `docs/PHASE_2_4/12_RUNTIME_EVIDENCE_AND_REPRODUCTION_LOG.md`: `0x43e4f0`
- `docs/PHASE_2_4/18_RAW_EVIDENCE_APPENDIX.md`: `0x00001000`, `0x00011900`, `0x00014000`, `0x00014e00`, `0x00017e00`, `0x0001a900`, `0x0001c100`, `0x0001d8f0`, `0x0001d970`, `0x00030600`, `0x0003ada0`, `0x0003b820`, `0x0003b870`, `0x0003b8c0`, `0x0003e5a0`, `0x0003ec5e`, `0x0003ec66`, `0x0003ec6e`, `0x0003ec76`, `0x0003ec81`, `0x0003edf0`, `0x00040a70`, `0x0004e7f0`, `0x0004e8ee`, `0x0004e8f4`, `0x0004e8fe`, `0x0004e901`, `0x0004e90d`, `0x0004e9aa`, `0x0004e9b6`, `0x00051d00`, `0x0006b270`, `0x0006bdf0`, `0x000735e0`, `0x00076000`, `0x000806f0`, `0x000835f0`, `0x000e70d7`, `0x000e82c0`, `0x000ecb36`, `0x00117600`, `0x00117a00`, `0x00119000`, `0x0011e9ac`, `0x0011e9b4`, `0x0011e9bc`, `0x0011ffac`, `0x0011ffb4`, `0x0011ffbc`, `0x00148000`, `0x0015c000`, `0x00173e00`, `0x001a9000`, `0x001c1000`, `0x401000`, `0x519000`
