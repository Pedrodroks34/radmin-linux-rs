# Phase 2.5 Stage 17 — Final Technical Report

**Classification: VERIFIED** (all confirmed findings traceable to static REA/Ghidra evidence)

## 1. Target Binary Identity

| Property | Value |
|----------|-------|
| Path | `/home/rhuan/Desktop/opencode/RvControlSvc_Installed.exe` |
| SHA-256 | `0e2e6eaacbe8ebe01286cda39a12eaad34a20434d50f4f8bf2fdd91d4d6ef2ad` |
| PE Format | PE32 x86 |
| ImageBase | 0x00400000 |

## 2. Corrected Object Layout Summary

| Offset | Name | Type | Confidence |
|--------|------|------|------------|
| 0x00 | field_0x00 | Vtable pointer | STRONGLY SUPPORTED |
| 0x04 | field_0x04 | Subobject pointer | VERIFIED |
| 0x08 | field_0x08 | Critical section | STRONGLY SUPPORTED (DeleteCriticalSection called) |
| 0x0C | field_0x0C | Zeroed then released | VERIFIED |
| 0x20 | field_0x20 | Reference count / destroy flag | STRONGLY SUPPORTED (atomic access) |
| 0x24 | field_0x24 | Atomic flag / generation counter | STRONGLY SUPPORTED (atomic exchange) |
| 0x28 | field_0x28 | State field (compared to 5) | HYPOTHESIS |
| 0x2C | field_0x2C | Handle/flag field (compared to 0) | HYPOTHESIS |
| 0x30 | field_0x30 | Call counter (incremented) | HYPOTHESIS |
| 0x38 | field_0x38 | Subobject A vtable pointer | STRONGLY SUPPORTED |
| 0x40 | field_0x40 | Subobject B vtable pointer | STRONGLY SUPPORTED |
| 0x50 | field_0x50 | Subobject C vtable pointer | STRONGLY SUPPORTED |
| 0x98 | field_0x98 | Subobject D vtable pointer | STRONGLY SUPPORTED |
| 0x9C | field_0x9C | Subobject E vtable pointer | STRONGLY SUPPORTED |
| 0x5C40 | field_0x5C40 | Last initialized field offset | VERIFIED |

**field_0x214:** Does not exist — no writes found anywhere.

## 3. Corrected Constructor Summary

| Property | Value |
|----------|-------|
| Function | FUN_0043E1A0 (0x43E1A0) |
| Size | 853 bytes, 36 basic blocks |
| Wrapper | FUN_0043ECF0 (0x43ECF0) |
| Adjustment thunks | 5 at 0x43E85E–0x43E881 |
| External callers | NONE |
| Vptr transitions | 3×: 0x51FFB4 → 0x51E570 → 0x51E4F0 |
| Subobject vptrs | 5 at offsets 0x38, 0x40, 0x50, 0x98, 0x9C |
| Sub-initializers | 12 identified; 4 analyzed; 9 not analyzed |
| Fields NOT initialized by constructor | obj+0x20, obj+0x28, obj+0x2C |

## 4. Corrected Reference Counting Summary

| Property | Value |
|----------|-------|
| Refcount location | obj + 0x20 |
| Read function | FUN_004731E0 (atomic LOCK/UNLOCK read) |
| Destroy function | FUN_00473210 (sets refcount to 0, exchanges obj+0x24, deletes critical section at obj+8) |
| AddRef function | NOT FOUND |
| Lifecycle pattern | Destroy-on-read-nonzero (NOT standard COM AddRef/Release) |
| Critical section | obj + 8, deleted by FUN_00473210 via DeleteCriticalSection |

## 5. Corrected Indirect Dispatch Matrix

| Vptr State | vptr Value | Slot 13 (+0x34) | Slot 22 (+0x58) |
|------------|------------|-----------------|-----------------|
| Initial | 0x0051FFB4 | 0x51FFE8 → 0x4510A0 → returns 0 | 0x52000C → 0x450FA0 → unknown |
| Intermediate | 0x0051E570 | 0x51E5A4 → 0x4510B0 → returns 16 | 0x51E5C8 → 0x450FC0 → unknown |
| Final | 0x0051E4F0 | 0x51E524 → 0x4510B0 → returns 16 | 0x51E548 → 0x450FC0 → unknown |

## 6. Corrected Deallocation Summary

| Property | Value |
|----------|-------|
| Destruction chain | FUN_004731E0 → FUN_00473210 → 5 list cleanup functions → FUN_004e6cd7 → thunk → FUN_004ec736 → CALL [0x500CA6] |
| 0x500CA6 section | .text (VA 0x401000–0x519000) |
| 0x500CA6 content | `free` function entry (code, not pointer) |
| CALL [0x500CA6] DWORD value | 0x8B55FF8B (not valid pointer) |
| Actual deallocation target | UNKNOWN (requires runtime debugging) |

## 7. Phase 2.4 Corrections Summary

| # | Phase 2.4 Claim | Phase 2.5 Correction |
|---|----------------|---------------------|
| C1 | Table A base = vptr | vptr = 0x51FFB4, not table base 0x51FFAC |
| C2 | Table B slot 22 address | 0x51E5C8, not 0x51E5C4 |
| C3 | Table C slot 22 address | 0x51E548, not 0x51E544 |
| C4 | Table A slot 13 target | 0x4510A0 (→0), not 0x451010 |
| C5 | Table A slot 22 target | 0x450FA0 (?), not 0x451070 |
| C6 | Table B slot 22 target | 0x450FC0 (?), not 0x451090 |
| C7 | Table C slot 22 target | 0x450FC0 (?), not 0x451090 |
| C8 | 0x500CA6 section | .text, not .data/gap |
| C9 | 0x500CA6 is IAT slot | `free` function code, not pointer |
| C10 | FUN_00473210 = Release | Destroy/reset, not Release |
| C11 | Standard AddRef/Release | Destroy-on-read-nonzero; no AddRef |
| C12 | Subinitializer count | 9, not 8 |
| C13 | obj+0x20/0x28/0x2C initialized | Not initialized by constructor |

## 8. Blocker Summary

| Blocker | Classification | Blocks Rust? |
|---------|---------------|--------------|
| Object allocation site | BLOCKED | No |
| Object allocation size | BLOCKED | No |
| Runtime vptr state | BLOCKED | No |
| Indirect call targets at runtime | BLOCKED | No |
| CALL [0x500CA6] target | BLOCKED | No |
| AddRef function | UNKNOWN | No |
| 9 sub-initializer bodies | UNKNOWN | No |
| obj+0x20/0x28/0x2C initial values | UNKNOWN | No |
| FUN_00450FA0/FUN_00450FC0/FUN_004728E0 bodies | UNKNOWN | No |
| Constructor reachability | UNKNOWN | No |

## 9. Next Phase Recommendation

**Phase 2.6:** Obtain Windows debugging environment and execute the Stage 12 debugging plan:
1. Breakpoint at HeapAlloc/RolClient_AllocMemory
2. Breakpoint at FUN_0043E1A0 constructor
3. Breakpoint at FUN_0044F3F0 indirect dispatch
4. Breakpoint at CALL [0x500CA6]
5. Analyze 9 sub-initializer bodies
6. Search for AddRef function