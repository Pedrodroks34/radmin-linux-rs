# Phase 2.4 Stage 09 — Allocation/Deallocation Symmetry

**Classification: UNKNOWN** (allocation site not found; deallocation target not resolved)

## 1. Allocation Side

| Aspect | Finding | Confidence |
|--------|---------|------------|
| Allocator APIs imported | HeapAlloc, HeapFree, HeapReAlloc, HeapSize, GetProcessHeap (KERNEL32); RolClient_AllocMemory, RolClient_FreeMemory (RvROLClient.dll); CoTaskMemFree (ole32); LocalFree (KERNEL32) | CONFIRMED (PE import table) |
| Allocation call in constructor | NONE found | CONFIRMED (analyzed FUN_0043E1A0, FUN_0043ECF0, all thunks) |
| Allocation call in sub-initializers | NONE found | CONFIRMED (analyzed available sub-initializers) |
| Factory function | NOT IDENTIFIED | UNKNOWN |
| Object allocation size | UNKNOWN | No HeapAlloc call with size argument found |
| Stack allocation possibility | UNKNOWN | Not ruled out |
| Parent object embedding | UNKNOWN | Not ruled out |
| Global/static allocation | UNKNOWN | Not ruled out |

## 2. Deallocation Side

| Aspect | Finding | Confidence |
|--------|---------|------------|
| Deallocation chain | FUN_004e6cd7 → thunk → FUN_004ec736 → CALL [0x00500ca6] | STRONGLY SUPPORTED |
| All 5 list cleanup functions call FUN_004e6cd7 | CONFIRMED | Pseudocode verified |
| Final deallocation target | UNKNOWN | [0x00500ca6] value not resolved |
| HeapFree as likely target | HYPOTHESIS | Imported; standard deallocation API |
| RolClient_FreeMemory as likely target | HYPOTHESIS | Imported; custom ROL deallocation |

## 3. Symmetry Assessment

| Pair | Allocation | Deallocation | Symmetric? |
|------|-----------|--------------|------------|
| HeapAlloc / HeapFree | Not found in object path | CALL [0x00500ca6] may be HeapFree | Cannot confirm |
| RolClient_AllocMemory / RolClient_FreeMemory | Not found in object path | CALL [0x00500ca6] may be RolClient_FreeMemory | Cannot confirm |
| CoTaskMemAlloc / CoTaskMemFree | CoTaskMemAlloc NOT imported | CoTaskMemFree imported | ASYMMETRIC (not a pair) |
| LocalAlloc / LocalFree | LocalAlloc NOT imported | LocalFree imported | ASYMMETRIC (not a pair) |

**Conclusion:** Cannot confirm allocation/deallocation symmetry because:
1. No allocation call site was found for the object
2. The deallocation target at [0x00500ca6] is unresolved

## 4. Object Size Estimates

| Estimate | Value | Basis | Confidence |
|----------|-------|-------|------------|
| Minimum initialized extent | 0x5C40 bytes (~23,264 bytes) | Constructor initializes fields up to 0x5C40 | CONFIRMED |
| Zeroing loop range | 0x0C–0x4C4 | FUN_0043E100 zeroing loop | CONFIRMED |
| Reported size (~0x5C44) | 0x5C44 bytes (~23,236 bytes) | Report 17 | UNVERIFIED (0x4 bytes beyond last init) |
| Actual allocation size | UNKNOWN | No allocation call with size found | UNKNOWN |

**Important:** The highest initialized field offset (0x5C40) is NOT the same as the allocation size. The actual allocation size cannot be determined without finding the allocation call.

## 5. List Node Allocation

The 5 list cleanup functions destroy nodes via FUN_004e6cd7 → CALL [0x00500ca6]. Whether list nodes use the same allocator as the parent object is unknown because:
- No node allocation site was found
- The deallocation target is shared (all nodes go through the same CALL [0x00500ca6])

## 6. Reference Count and Deallocation Timing

| Aspect | Finding | Confidence |
|--------|---------|------------|
| Refcount at obj + 0x20 | CONFIRMED | FUN_004731E0 accesses it atomically |
| Release calls FUN_00473210 if refcount != 0 | CONFIRMED | Pseudocode |
| Object freed when refcount reaches 0 | HYPOTHESIS | Expected pattern, but FUN_00473210 not analyzed |
| AddRef not identified | CONFIRMED (absence) | Not found in static analysis |

**Critical gap:** Without AddRef, we cannot confirm the reference counting lifecycle is complete. The object may be created with refcount 1 and never have AddRef called, or AddRef may be inlined.

## 7. Confidence Classification

| Question | Classification | Basis |
|----------|---------------|-------|
| Same allocator for alloc and dealloc | UNKNOWN | Allocation site not found |
| Object freed exactly once | UNKNOWN | No allocation/deallocation pair observed |
| Object freed only after refcount reaches 0 | HYPOTHESIS | Expected pattern, not confirmed |
| List nodes use same allocator as parent | UNKNOWN | No node allocation site found |
| Actual allocation size | UNKNOWN | No size argument observed |
| Minimum initialized extent | CONFIRMED | 0x5C40 bytes |