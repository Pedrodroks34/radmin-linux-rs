# Phase 2.3 Stage 5 — Factory and Allocation Analysis

**Classification: STRONGLY SUPPORTED** (all callers identified via REA `procedure_callers`)

## 1. Constructor Caller Analysis

`FUN_0043E1A0` (0x43E1A0, 853 bytes, 36 blocks, `__fastcall(void *this)`) is called from:

| Caller | VA | Call Site | Relationship |
|---|---|---|---|
| FUN_0043ECF0 | 0x43ECF0 | 0x43ECF6 | Direct call |

**Result:** Only ONE caller found — `FUN_0043ECF0`. No external callers found.

## 2. FUN_0043ECF0 Caller Analysis

`FUN_0043ECF0` (0x43ECF0, 38 bytes) is called by exactly **5 adjustment thunks**:

| Thunk | VA | Call Site | Relationship |
|---|---|---|---|
| FUN_0043E85E | 0x43E85E | Tail jump | Adjustment thunk (ECX -= 0x38) |
| FUN_0043E866 | 0x43E866 | Tail jump | Adjustment thunk (ECX -= 0x40) |
| FUN_0043E86E | 0x43E86E | Tail jump | Adjustment thunk (ECX -= 0x50) |
| FUN_0043E876 | 0x43E876 | Tail jump | Adjustment thunk (ECX -= 0x98) |
| FUN_0043E881 | 0x43E881 | Tail jump | Adjustment thunk (ECX -= 0x9C) |

## 3. Adjustment Thunk Caller Analysis — CRITICAL FINDING

`procedure_callers` for all 5 adjustment thunks returns **empty** (no callers found).
`xrefs` for all 5 thunk addresses returns **0 references**.

**This means:**
- No function calls any of the 5 adjustment thunks
- The thunks are unreachable from any code path
- Since FUN_0043ECF0 is ONLY called by these 5 thunks, FUN_0043ECF0 is also unreachable
- Since FUN_0043E1A0 (constructor) is ONLY called by FUN_0043ECF0, the constructor is also unreachable

## 4. Allocator Search

Search for allocator calls in the binary:

| Search | Result |
|---|---|
| `operator new` / `malloc` imports | Not found in import directory |
| `HeapAlloc` | Not found |
| `CoTaskMemAlloc` | Not found |
| `VirtualAlloc` | Not found |
| `RtlAllocateHeap` | Not found |
| Any allocator-related import | None found |

**No allocator calls found anywhere in the binary.** The constructor does not call any allocation function.

## 5. Object Lifetime Chain

```
UNKNOWN caller → (unfound) → FUN_0043ECF0 → FUN_0043E1A0 (constructor)
                                                    │
                                                    └─► 12 sub-initializers
                                                    └─► Vptr writes (3 transitions)
                                                    │
                                                    └─► Returns this
```

Since no external caller of FUN_0043ECF0 exists, and no allocator call exists in the binary, the object construction pathway is **completely unreachable** from any statically discoverable code.

## 6. Object Lifetime

No destructor chain leading to object deallocation was found. The destructor functions (FUN_0043EED0, FUN_0043F110) exist as vtable slot 0 entries but are never called from any reachable code path.

## 7. Summary

| Question | Answer | Confidence |
|---|---|---|
| Who allocates the object? | Unknown - no allocator found | HIGH |
| Who calls FUN_0043ECF0? | Only 5 adjustment thunks | VERIFIED |
| Who calls the adjustment thunks? | Nobody - no callers found | VERIFIED |
| Is the constructor reachable? | No - only reachable via unreachable thunks | VERIFIED |
| Is there an allocator call? | No - no allocator imports found | VERIFIED |
| Is there a destructor chain? | No - destructors exist but are unreachable | VERIFIED |

**Conclusion:** The constructor and destructor code exists in the binary but forms an unreachable code island. The object is never constructed or destroyed from any statically reachable code path.

## 8. Next Stage

Stage 6: Object lifecycle analysis — examine destructor candidates and reference counting patterns that ARE reachable from other code paths.