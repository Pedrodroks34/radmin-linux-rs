# Phase 2.6 Stage 02 — Phase 2.5 Critical Correction Matrix

**Classification: PROVEN / CONTRADICTED** — every corrected or contradicted Phase 2.5 conclusion is documented here with the actual bytes, correct instruction, and corrected interpretation. Phase 2.6 independently re-decoded all critical instructions using Capstone 5.0.7 and a manual opcode decoder, cross-checked against REA/Ghidra raw bytes.

Cross-reference: `03_INDEPENDENT_X86_INSTRUCTION_DECODING_AUDIT.md`, `04_FUN_004731E0_CORRECTED_INSTRUCTION_AND_SEMANTICS.md`, `05_FUN_00473210_POINTER_INDIRECTION_ANALYSIS.md`, `10_REFERENCE_COUNTER_AND_CONTROL_BLOCK_RECONSTRUCTION.md`, `17_RUST_BEHAVIORAL_COMPATIBILITY_REASSESSMENT.md`, `20_PHASE_2_6_FINAL_TECHNICAL_REPORT.md`.

---

## 1. Correction Matrix

| # | Phase 2.5 claim | Report | Actual bytes (VA) | Correct instruction | Previous semantic interpretation | Corrected interpretation | Classification |
|---|-----------------|--------|-------------------|---------------------|----------------------------------|--------------------------|----------------|
| C1 | `LOCK XCHG [EDX], ESI` exchanges `field_0x20` to zero | 09 | `F0 0F C1 32` at `0x004731F2` | `LOCK XADD [EDX], ESI` (opcode `0F C1` = XADD, not `87` = XCHG) | Release = decrement/exchange-to-zero counter | Release = **atomic read (fetch-add-zero)** of pointer; field **UNCHANGED**; teardown called iff old pointer != NULL | PROVEN |
| C2 | `MOV ECX, [ESI+0x20]` loads the VALUE at field_0x20 | 08 | `8D 4E 20` at `0x0047321D` | `LEA ECX, [ESI+0x20]` (opcode `8D` = LEA, not `8B` = MOV) | `ECX` holds value `*(this+0x20)`; `XCHG [ECX],EDX` is pointer-indirect | `ECX` holds **address** `&this->field_0x20`; `XCHG [ECX],EDX` is **direct field write** | PROVEN |
| C3 | `MOV ECX, [ESI+0x24]` loads the VALUE at field_0x24 | 08 | `8D 4E 24` at `0x0047322D` | `LEA ECX, [ESI+0x24]` (opcode `8D` = LEA, not `8B` = MOV) | `ECX` holds value `*(this+0x24)`; `XCHG [ECX],EDX` is pointer-indirect | `ECX` holds **address** `&this->field_0x24`; `XCHG [ECX],EDX` is **direct field write** | PROVEN |
| C4 | `XCHG [ECX], EDX` operates on pointer-indirect pointee | 08 | `87 11` at `0x00473226` / `0x00473230` | `XCHG [ECX], EDX` where ECX = LEA-computed address of field | `*(*(this+0x20))` and `*(*(this+0x24))` | `*(this+0x20)` and `*(this+0x24)` (direct object fields) | PROVEN |
| C5 | `field_0x20` is an integer reference counter | 09, 10 | Accessed via `LEA EDX,[EDI+0x20]`; `LOCK XADD [EDX],0` reads it; `XCHG [&field_0x20],0` nulls it | `LOCK XADD [&field_0x20], 0` | `field_0x20` is a counter incremented/decremented | `field_0x20` is a **pointer** (release latch: non-NULL=alive, NULL=released); never incremented | STRONGLY SUPPORTED |
| C6 | `field_0x20` is decremented by Release | 09 | `LOCK XADD [EDX], ESI` with ESI=0 | Field = old + 0 = old (unchanged) | Counter decremented by 1 | Counter **not modified** by Release; only read atomically | PROVEN |
| C7 | `field_0x20` is zeroed by Release | 09 | Zeroed by `FUN_00473210` `XCHG [&field_0x20], 0` (at `0x473226`), NOT by Release | Release zeroes the counter | Release only reads; teardown (called by Release) zeroes | STRONGLY SUPPORTED |
| C8 | Teardown = decrement-and-destroy-if-zero | 08 | `XCHG [&field_0x20], 0`; `XCHG [&field_0x24], 1`; helper `FUN_00489750`; no branch | Teardown decrements counter, destroys if zero | Teardown **NULLs the pointer** and **sets flag to 1**; `neg/sbb/xor/neg` is dead code | PROVEN |
| C9 | External control block exists (field_0x20 is pointer-to-pointer) | 10 | All accesses via `LEA` (direct address-of); no pointer dereference of field_0x20 | `*(*(this+0x20))` indirection | No indirection; `field_0x20` is a direct field | STRONGLY SUPPORTED |
| C10 | `CALL [0x00500ca6]` indirect through memory slot | 14 | `E8 58 45 01 00` at `0x4EC749` = `CALL 0x500CA6` (direct relative) | `0x500CA6` is code in `.text` (prologue `8B FF 55 8B EC`) | Indirect slot / IAT entry / data pointer | Direct call to function; not IAT, not data | PROVEN (confirms P2.5 Report 06 correction) |
| C11 | `FUN_00489750` import unknown | 06 | `FF 15 38 91 51 00` = `CALL [0x519138]` | `DeleteCriticalSection` (KERNEL32 ILT[12], resolved via ILT) | Unknown import | `DeleteCriticalSection(&this->field_0x08)`; `field_0x08` is CRITICAL_SECTION | PROVEN |
| C12 | Table A slot 13 = `0x451010` (returns 0) | 11 | Slot 13 = vptr `0x51FFB4 + 0x34 = 0x51FFE8`; bytes `A0 10 45 00` → `0x4510A0` | `0x4510A0` = `MOV EAX, 0x10; RET` (returns 16) | Table A slot 13 returns 0 | Table A slot 13 returns 16; `0x451010` is nominal-base slot 12, not real slot 13 | PROVEN |
| C13 | Table B/C slot 22 = `0x451090` (returns 0) | 11 | Slot 22 = vptr `0x51E570/0x51E4F0 + 0x58 = 0x51E5C8/0x51E548`; bytes `C0 0F 45 00` → `0x450FC0` | `0x450FC0` = arg-dependent (0 or 0xC5) | Table B/C slot 22 returns 0 | Table B/C slot 22 returns arg-dependent value; `0x451090` is slot 21 | PROVEN |

---

## 2. Root Cause of Corrections

| Error type | Occurrences | Example |
|------------|-------------|---------|
| Opcode `0F C1` (XADD) misread as `87` (XCHG) | C1 | `F0 0F C1 32` → claimed `LOCK XCHG`, actual `LOCK XADD` |
| Opcode `8D` (LEA) misread as `8B` (MOV) | C2, C3 | `8D 4E 20` → claimed `MOV ECX,[ESI+0x20]`, actual `LEA ECX,[ESI+0x20]` |
| Nominal table base used instead of constructor vptr | C12, C13 | Table A slot 13 computed from `0x51FFAC` instead of `0x51FFB4` (off by one slot) |
| Decompiler pseudocode trusted over raw bytes | C1–C13 | All corrections traceable to re-decoding raw bytes |

---

## 3. Decoder Verification (for each corrected instruction)

| VA | Instruction | Capstone 5.0.7 | Manual decoder | REA bytes | Agreement |
|-----|-------------|----------------|----------------|-----------|-----------|
| `0x4731F2` | `LOCK XADD [EDX], ESI` | `lock xadd dword ptr [edx], esi` | `lock xadd [edx], esi` | `f0 0f c1 32` | YES |
| `0x47321D` | `LEA ECX, [ESI+0x20]` | `lea ecx, [esi + 0x20]` | `lea ecx, [esi + 0x20]` | `8d 4e 20` | YES |
| `0x473226` | `XCHG [ECX], EDX` | `xchg dword ptr [ecx], edx` | `xchg [ecx], edx` | `87 11` | YES |
| `0x47322D` | `LEA ECX, [ESI+0x24]` | `lea ecx, [esi + 0x24]` | `lea ecx, [esi + 0x24]` | `8d 4e 24` | YES |
| `0x473230` | `XCHG [ECX], EDX` | `xchg dword ptr [ecx], edx` | `xchg [ecx], edx` | `87 11` | YES |

---

## 4. Impact on Ownership Model

| Phase 2.5 model | Phase 2.6 corrected model | Basis |
|-----------------|---------------------------|-------|
| `Arc<T>`-style strong refcount (increment + decrement) | `Box<T>`-style single ownership (release-once latch) | No AddRef found (Report 09); field never incremented (Report 08) |
| Reference counter (integer) | Release-latch pointer | `LOCK XADD(...,0)` doesn't modify; `XCHG(...,0)` nulls (Reports 04, 05) |
| External control block | None — all direct field access | LEA-based addressing (Report 07) |
| Decrement-and-destroy-if-zero | Atomic read + conditional teardown + NULL + flag | XADD read; XCHG writes (Reports 04, 05) |

---

## 5. Confidence Summary

| Correction | Classification | Basis |
|------------|---------------|-------|
| C1–C5 (instruction decoding) | PROVEN | Capstone + Manual + REA all agree |
| C6–C8 (Release/teardown semantics) | STRONGLY SUPPORTED | Derived from verified instructions |
| C9 (no control block) | STRONGLY SUPPORTED | All accesses via LEA; no indirection |
| C10 (direct call, not indirect slot) | PROVEN | Confirms Phase 2.5 Report 06 |
| C11 (`DeleteCriticalSection`) | PROVEN | ILT[12] resolution |
| C12–C13 (vtable slot targets) | PROVEN | Byte reads at corrected slot addresses |

No Phase 2.5 conclusion is preserved merely because it appeared in a prior report. All corrections are traceable to verified machine bytes.
