# Phase 2.5 Stage 07 — Reference-Count Increment and Release Search

**Classification: PARTIALLY RESOLVED** (Release-like function analyzed; AddRef not found; documented search coverage)

## 1. Purpose

Investigate all accesses to `obj + 0x20` to identify the reference-count increment (AddRef) counterpart and fully understand the release/destroy semantics.

## 2. Known Accesses to obj + 0x20

| Function | Address | Operation | Atomic? | Confidence |
|----------|---------|-----------|---------|------------|
| FUN_004731E0 | 0x4731E0 | LOCK-prefixed READ of obj+0x20; `*piVar1 = *piVar1` (barrier) | YES | CONFIRMED |
| FUN_00473210 | 0x473210 | LOCK-protected STORE of 0 to obj+0x20 | YES | CONFIRMED |

**FUN_004731E0 behavior:**
- Atomically reads `obj + 0x20`
- If value != 0, calls `FUN_00473210`
- Does NOT modify the value (just reads it)

**FUN_00473210 behavior:**
- Sets `obj + 0x20` to 0 (unconditional store, not decrement)
- This is a destroy/reset, not a Release decrement

## 3. AddRef Search — Not Found

**Search performed:**
- Reviewed all 13 functions analyzed in Phase 2.4 (FUN_00440670, FUN_00475C00, FUN_004731E0, FUN_004802F0, FUN_0046AE70, FUN_004831F0, FUN_0046B9F0, FUN_00451900, FUN_0043B470, FUN_0043B4C0, FUN_0043B420, FUN_0043A9A0, thunk_FUN_004ec736)
- Reviewed FUN_00473210 (analyzed in Phase 2.5 Stage 06)
- Reviewed constructor FUN_0043E1A0 and wrapper FUN_0043ECF0
- Reviewed all 5 list cleanup functions

**Result:** No function was found that:
- Increments `obj + 0x20`
- Performs `LOCK INC` or `LOCK ADD` on `obj + 0x20`
- Performs `LOCK XADD` on `obj + 0x20`
- Performs `LOCK CMPXCHG` on `obj + 0x20`

## 4. Search Coverage Limitations

| Limitation | Explanation |
|------------|-------------|
| Only analyzed functions reviewed | 8 of 12 constructor sub-initializers not yet analyzed (FUN_0047A8A0, FUN_0043E500, FUN_00403540, FUN_004728E0, FUN_00483750, FUN_0043E680, FUN_0047BB20, FUN_00475B70, FUN_00479240) |
| No byte-level search for `INC [reg+0x20]` patterns | REA does not expose a raw byte search for instruction patterns |
| No data-flow analysis for pointer provenance | Object pointer may be in different registers or derived |
| No runtime execution | Cannot observe AddRef calls at runtime |

## 5. Alternative Interpretations of obj + 0x20

| Interpretation | Evidence For | Evidence Against |
|---------------|-------------|-----------------|
| Reference count | Atomic LOCK access in FUN_004731E0 | Set to 0 (not decremented) in FUN_00473210; no AddRef found |
| Destroy flag | FUN_00473210 sets to 0 unconditionally | FUN_004731E0 reads it conditionally |
| Initialization state | Set to 0 during destroy | Atomic access suggests shared/threaded use |
| Unrelated atomic field | FUN_004731E0 preserves GetLastError around it | LOCK prefix suggests synchronization importance |

## 6. obj + 0x24 — Second Atomic Field

**FUN_00473210 accesses obj + 0x24:**
- Atomic exchange: reads old value, writes 1
- Return value includes old value

**Possible roles for obj + 0x24:**
- Destroyed flag (set to 1 when object is being destroyed)
- Initialization flag
- Generation counter
- Owner thread ID

## 7. obj + 8 — Critical Section

**FUN_00473210 calls DeleteCriticalSection(obj + 8):**
- Critical section at obj + 8 is destroyed during object destruction
- Suggests obj + 8 is a synchronization primitive for the object

## 8. Confidence Classification

| Question | Classification | Basis |
|----------|---------------|-------|
| Release-like function exists | CONFIRMED | FUN_004731E0 + FUN_00473210 analyzed |
| AddRef function found | NOT FOUND | Searched all analyzed functions; not present |
| obj + 0x20 is a reference count | STRONGLY SUPPORTED | Atomic LOCK access pattern |
| obj + 0x20 is decremented | REFUTED | FUN_00473210 sets to 0, not decrement |
| Standard COM AddRef/Release | REFUTED | No AddRef; destroy semantics differ |
| Search coverage | PARTIAL | 8 sub-initializers not analyzed; no raw byte search |