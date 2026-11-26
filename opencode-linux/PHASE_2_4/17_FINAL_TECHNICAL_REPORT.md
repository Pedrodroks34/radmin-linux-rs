# Phase 2.4 Stage 17 — Final Technical Report

**Classification: VERIFIED** (all confirmed findings traceable to static REA/Ghidra evidence)

## 1. Target Binary Identity

| Property | Value |
|----------|-------|
| Path | `/home/rhuan/Desktop/opencode/RvControlSvc_Installed.exe` |
| SHA-256 | `0e2e6eaacbe8ebe01286cda39a12eaad34a20434d50f4f8bf2fdd91d4d6ef2ad` |
| PE Format | PE32 x86 |
| ImageBase | 0x00400000 |
| SizeOfImage | 0x001D6000 |

## 2. Object Layout Summary

| Offset | Name | Type | Confidence |
|--------|------|------|------------|
| 0x00 | field_0x00 | Vtable pointer | STRONGLY SUPPORTED |
| 0x04 | field_0x04 | Subobject pointer | VERIFIED |
| 0x0C | field_0x0C | Zeroed then released | VERIFIED |
| 0x20 | field_0x20 | Reference count (atomic access) | STRONGLY SUPPORTED |
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

## 3. Constructor Summary

| Property | Value |
|----------|-------|
| Function | FUN_0043E1A0 (0x43E1A0) |
| Size | 853 bytes, 36 basic blocks |
| Wrapper | FUN_0043ECF0 (0x43ECF0) |
| Adjustment thunks | 5 at 0x43E85E–0x43E881 |
| External callers | NONE (thunks have no callers) |
| Vptr transitions | 3×: 0x51FFB4 → 0x51E570 → 0x51E4F0 |
| Subobject vptrs | 5 at offsets 0x38, 0x40, 0x50, 0x98, 0x9C |
| Sub-initializers | 12 identified, 4 analyzed, 8 not analyzed |

## 4. Reference Counting Summary

| Property | Value |
|----------|-------|
| Refcount location | obj + 0x20 |
| Release function | FUN_004731E0 (atomic LOCK/UNLOCK read) |
| Decrement/destroy | FUN_00473210 (referenced, not analyzed) |
| AddRef function | NOT IDENTIFIED |
| Atomic operations | LOCK-prefixed read confirmed |

## 5. Destruction Chain

```
FUN_004731E0 (Release)
  └─ FUN_00473210 (decrement/destroy-if-zero, NOT ANALYZED)
       └─ 5 list cleanup functions
            └─ FUN_004e6cd7(node) per node
                 └─ thunk_FUN_004ec736 (JMP 0x4ec736)
                      └─ FUN_004ec736: CALL [0x00500ca6]
```

**Final deallocation target:** UNKNOWN ([0x00500ca6] value not resolved)

## 6. Indirect Dispatch Summary

| Property | Value |
|----------|-------|
| Function | FUN_0044F3F0 (0x44F3F0) |
| Direct callers | NONE |
| Guard condition | field_0x28 == 5 && field_0x2C != 0 |
| Vptr load | MOV EAX, [EDI] at 0x44F4FA |
| Indirect calls | [EAX+0x34] (slot 13) at 0x44F501/0x44F5AA; [EAX+0x58] (slot 22) at 0x44F50D/0x44F5B6 |
| Vtable tables | Table A: 0x51FFAC; Table B: 0x51E570; Table C: 0x51E4F0 |
| Runtime vptr state | UNKNOWN (blocked — no Windows debugger) |

## 7. Allocator Summary

| API | DLL | Status |
|-----|-----|--------|
| HeapAlloc | KERNEL32.dll | Imported, no call found in object path |
| HeapFree | KERNEL32.dll | Imported, likely deallocation target |
| HeapReAlloc | KERNEL32.dll | Imported, no call found |
| HeapSize | KERNEL32.dll | Imported, no call found |
| GetProcessHeap | KERNEL32.dll | Imported, no call found |
| RolClient_AllocMemory | RvROLClient.dll | Imported, no call found |
| RolClient_FreeMemory | RvROLClient.dll | Imported, likely deallocation target |
| CoTaskMemFree | ole32.dll | Imported, no call found |
| LocalFree | KERNEL32.dll | Imported, no call found |

**Object allocation site:** UNKNOWN
**Object actual size:** UNKNOWN

## 8. Rust Compatibility Summary

| Windows Pattern | Rust Equivalent | Viability |
|----------------|-----------------|-----------|
| Refcounted object (obj+0x20) | `Arc<T>` | VIABLE |
| Release (FUN_004731E0) | `impl Drop` | VIABLE |
| AddRef (not found) | `Arc::clone()` | VIABLE |
| List cleanup (5 functions) | `Vec<Arc<T>>` / `LinkedList<Arc<T>>` | VIABLE |
| field_0x28 (state, ==5) | `enum SessionState` | VIABLE |
| field_0x2C (flag, ==0) | `bool` / `Option<T>` | VIABLE |
| field_0x30 (counter) | `AtomicU64` / `u64` | VIABLE |
| C++ vtable transitions | NOT VIABLE | REJECTED |
| Adjustment thunks | NOT VIABLE | REJECTED |
| Manual HeapAlloc/HeapFree | NOT VIABLE | REJECTED |
| Windows APIs (RegCloseKey, EventUnregister) | NOT VIABLE | REJECTED |

## 9. Blockers Summary

| Blocker | Classification | Blocks Rust? |
|---------|---------------|--------------|
| Object allocation site | BLOCKED | No |
| Object allocation size | BLOCKED | No |
| Runtime vptr state | BLOCKED | No |
| Indirect call targets at runtime | BLOCKED | No |
| FUN_00473210 body | UNKNOWN | No |
| AddRef function | UNKNOWN | No |
| [0x500ca6] target | UNKNOWN | No |
| Allocation/deallocation symmetry | UNKNOWN | No |

## 10. Next Phase Recommendation

**Phase 2.5:** Resolve remaining blockers using Windows runtime debugging:
1. Capture object allocation at runtime (HeapAlloc breakpoint)
2. Capture runtime vptr state at FUN_0044F3F0
3. Resolve [0x500ca6] deallocation target
4. Analyze FUN_00473210 body
5. Search for AddRef function

If Windows debugging remains unavailable, all remaining blockers are classified as BLOCKED/UNKNOWN and do not block Rust implementation.