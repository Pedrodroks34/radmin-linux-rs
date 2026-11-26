# Phase 2.5 Stage 11 — Constructor Reachability and Factory Analysis

**Classification: UNRESOLVED** (no external callers found; factory not identified)

## 1. Purpose

Investigate whether the constructor `FUN_0043E1A0` is reachable from any known entry point, and identify any factory function that allocates and constructs the object.

## 2. Constructor Call Chain

```
External caller (UNKNOWN)
    ↓
Adjustment thunks (5 total, no callers found)
    ↓
FUN_0043ECF0 (constructor wrapper, 0x43ECF0)
    ↓
FUN_0043E1A0 (primary constructor, 0x43E1A0)
    ↓
12 sub-initializer calls (4 analyzed, 9 not)
```

## 3. Caller Analysis Results

| Function | Direct Callers Found | Caller Type | Status |
|----------|---------------------|-------------|--------|
| FUN_0043E1A0 | FUN_0043ECF0 only | Direct call | CONFIRMED |
| FUN_0043ECF0 | 5 adjustment thunks | Direct calls | CONFIRMED |
| Thunk 0x43E85E | None | N/A | CONFIRMED (no callers) |
| Thunk 0x43E866 | None | N/A | CONFIRMED (no callers) |
| Thunk 0x43E86E | None | N/A | CONFIRMED (no callers) |
| Thunk 0x43E876 | None | N/A | CONFIRMED (no callers) |
| Thunk 0x43E881 | None | N/A | CONFIRMED (no callers) |

**Critical finding:** The entire construction chain has **no identified external callers**. The adjustment thunks are unreachable from any known caller in the static call graph.

## 4. Possible Explanations (All Unverified)

| Explanation | Likelihood | Evidence Needed |
|-------------|-----------|-----------------|
| Factory function allocates + constructs | Possible | Search for HeapAlloc call followed by constructor call |
| Object embedded in parent object | Possible | Search for parent object construction |
| Global/static object | Possible | Search .data/.bss for object-sized region |
| Stack allocation | Possible | Search for constructor called with stack pointer |
| Constructor is dead code | Possible | Class may be unused in this executable |
| Indirect call through function pointer | Possible | Search vtables and function tables for constructor addresses |
| Constructor called via unanalyzed code | Possible | 9 sub-initializers not yet analyzed may contain calls |

## 5. Allocator Call Site Search

**Allocator APIs imported:**
- `HeapAlloc` (KERNEL32, IAT RVA 0x11941e)
- `HeapFree` (KERNEL32, IAT RVA 0x11942a)
- `RolClient_AllocMemory` (RvROLClient.dll, IAT RVA 0x1199c0)
- `RolClient_FreeMemory` (RvROLClient.dll, IAT RVA 0x11998c)

**Search result:** No direct call to `HeapAlloc` or `RolClient_AllocMemory` found in:
- FUN_0043E1A0 (constructor)
- FUN_0043ECF0 (wrapper)
- 5 adjustment thunks
- Any of the 4 analyzed sub-initializers

**Conclusion:** The allocation call site remains UNKNOWN.

## 6. Confidence Classification

| Question | Classification | Basis |
|----------|---------------|-------|
| Constructor has no external callers | CONFIRMED (static) | Ghidra call graph; thunks have no callers |
| Factory function found | NOT FOUND | Not in analyzed code |
| Allocation call site found | NOT FOUND | No HeapAlloc/RolClientAllocMemory call in constructor path |
| Constructor reachability | UNKNOWN | Could be reached via indirect call or unanalyzed code |
| Object allocation mechanism | UNKNOWN | No allocation call found |