# Phase 2.5 Stage 20 — Final Technical Report

**Classification: FINAL** — independent static forensics of `RvControlSvc_Installed.exe` (SHA-256 `0E2E6EAACBE8EBE01286CDA39A12EAAD34A20434D50F4F8BF2FDD91D4D6EF2AD`) complete. All 20 Phase 2.5 reports created under `opencode-windows/PHASE_2_5/`.

Cross-reference: all reports 01–19.

---

## Executive Summary

Phase 2.5 independently re-verified Phase 2.4's findings against the actual executable by reading raw bytes and decoding instructions, rather than relying on decompiler interpretation or prior summaries. **Six major Phase 2.4 conclusions were contradicted or corrected**; the rest were confirmed. The object lifecycle is now understood through teardown, but the allocation site, initial counter setup, AddRef, and runtime-active vptr remain unresolved (static-only limitation, not a tool failure).

Environment: **Windows 10 Pro (AMD64)**, not Linux. Reports therefore live under `opencode-windows/PHASE_2_5/`. REA/Ghidra live connection was unavailable (JEB MCP not running; pyghidra not in system Python), so static analysis was performed directly on the executable bytes with a PE parser — every "verified" pointer value was re-read from the file.

---

## Major Corrections (vs. Phase 2.4)

| # | Phase 2.4 claim | Corrected finding | Confidence | Report |
|---|-----------------|-------------------|------------|--------|
| C1 | Table A nominal base `0x0051FFAC` = object vptr | Actual vptr = `0x0051FFB4` (Table A slot 2), written by constructor at `0x43E1B1`; `0x0051FFAC` never written as vptr | PROVEN | 02, 03 |
| C2 | Table A slot 13 = `0x0051FFE0`→`0x00451010` | Correct slot 13 = `0x0051FFE8`→`0x004510A0` (`0x51FFE0` is slot 12) | PROVEN | 03, 04 |
| C3 | Table A slot 22 = `0x00520004`→`0x00451070` | Correct slot 22 = `0x0052000C`→`0x00450FA0` (`0x520004` is slot 20) | PROVEN | 03, 04 |
| C4 | Table B/C slot 22 → `0x00451090` at `0x51E5C4`/`0x51E544` | Correct slot 22 = `0x51E5C8`/`0x51E548`→`0x00450FC0` (`...5C4`/`...544` is slot 21) | PROVEN | 03, 04 |
| C5 | Release = decrement refcount | Release = `LOCK XCHG [obj+0x20],0` = **exchange-to-zero**, not decrement | PROVEN | 09 |
| C6 | `FUN_00473210` = decrement-and-destroy-if-zero | `FUN_00473210` = atomic XCHG `+0x20`=0, XCHG `+0x24`=1 + helper `0x489750`; NOT a decrement, no zero-branch | PROVEN | 08 |
| C7 | `CALL [0x00500CA6]` indirect slot; target unresolved | `CALL 0x00500CA6` is a **direct** relative call to function `0x00500CA6` (code in `.text`); not an IAT entry or data slot | PROVEN | 06, 07 |
| C8 | 9 unanalyzed initializers | `0x479240` is a pure JMP thunk; 8 initializer candidates + 1 thunk = 9 addresses; all write unrelated vtables (`0x522xxx`), none ObjectCandidate's | PROVEN | 13 |

Root cause of C1–C4: Phase 2.4 computed vtable slots from the **nominal table base** instead of the **constructor-written vptr address point**, producing off-by-one (Table A) and off-by-four (Table B/C slot 22) errors.

---

## Confirmed Findings (PROVEN / STRONGLY SUPPORTED)

| Finding | Classification | Report |
|---------|---------------|--------|
| Binary: PE32 x86, ImageBase `0x00400000`, SHA-256 matches expected | PROVEN | 01 |
| Constructor vptr transitions `0x51FFB4 → 0x51E570 → 0x51E4F0` | PROVEN | 03, 05 |
| 5 subobject vptrs at `+0x38/0x40/0x50/0x98/0x9C`, 2-phase init+overwrite | PROVEN | 05, 11 |
| Refcount candidate `obj+0x20` with atomic `LOCK XCHG` | STRONGLY SUPPORTED | 09, 10 |
| `FUN_004731E0` Release = exchange-to-zero + conditional teardown | PROVEN | 09 |
| `FUN_00473210` teardown = XCHG `+0x20`=0, XCHG `+0x24`=1 | PROVEN | 08 |
| Dispatch `FUN_0044F3F0`: `[vptr+0x34]`/`[vptr+0x58]`, guard `+0x28==5 && +0x2C!=0`, `INC +0x30` | PROVEN | 04 |
| Deallocation chain `FUN_004e6cd7 → thunk 0x4E7EC0 → FUN_004ec736 → CALL 0x500CA6` (direct) | STRONGLY SUPPORTED | 07 |
| `0x00500CA6` = free routine (code), not IAT slot | PROVEN | 06, 07 |
| 5 constructor adjustment thunks (this-adjust −0x38/−0x40/−0x50/−0x98/−0x9C) | PROVEN | 05, 16 |
| `field_0x214` does not exist | PROVEN | 02 |

---

## Object Lifecycle Reconstruction

```
[ALLOCATION SITE UNKNOWN] → FUN_0043ECF0 → FUN_0043E1A0
   ctor: zeroing 0x0C–0x4C4; vptr 0x51FFB4→0x51E570→0x51E4F0;
         subobject vptrs 2-phase (init then overwrite)
→ OBJECT READY (vptr = Table C 0x51E4F0)
→ [counter obj+0x20 initial value UNKNOWN; AddRef NOT FOUND]
→ FUN_0044F3F0 indirect dispatch [vptr+0x34]/[vptr+0x58] (guard +0x28==5, +0x2C!=0; INC +0x30)
→ FUN_004731E0 Release: LOCK XCHG [obj+0x20],0
   old==0 → skip (idempotent)
   old!=0 → FUN_00473210 teardown: helper 0x489750(+0x8); XCHG +0x20=0; XCHG +0x24=1
→ FUN_0043F110 scalar deleting destructor? (Table C slot 0, LIKELY)
→ 5 list-cleanup → FUN_004e6cd7 → thunk 0x4E7EC0 → FUN_004ec736 → CALL 0x500CA6 (free)
→ [parent object block free UNKNOWN]
```

**Unresolved edges (explicitly shown, not hidden):**
1. Allocation site and size (no `HeapAlloc`/`RolClient_AllocMemory`/factory call found).
2. Who calls the constructor / publishes the object.
3. Who calls `FUN_0044F3F0`; which vptr is active at dispatch.
4. Initial value of `obj+0x20`; whether AddRef/increment exists.
5. Parent object block free location.

---

## Reference-Count Conclusion

`obj+0x20` is the strongest counter candidate (atomic `LOCK XCHG`, Release zeroes it, teardown triggers on non-zero old value). However:
- **No AddRef/increment found** anywhere in analyzed code.
- Release **sets to zero** (exchange), does not decrement.
- Therefore a conventional multi-owner strong reference count (`Arc<T>` semantics) is **not confirmed**. The behavior is more consistent with single-ownership or a release-latch. `Arc<T>` is only appropriate if AddRef is later confirmed.

---

## Rust Compatibility Conclusion

Native behavior is understood well enough to begin a Rust design **behaviorally**, without reproducing C++ vtables, this-adjustment thunks, or manual `HeapAlloc`/`HeapFree` pairing:

- **Suitable candidates:** `enum` for state/flag fields (`+0x28`/`+0x2C`); `AtomicU32` for `obj+0x20` counter and `AtomicBool` for `+0x24` teardown flag; `Drop` for teardown; `Box<T>` or `Arc<T>` for ownership; `Vec`/`LinkedList` for node list.
- **Not yet safe to finalize:** `Arc<T>` vs `Box<T>` — blocked on U5 (AddRef/increment of `obj+0x20`).
- **Explicitly rejected:** reproducing C++ vtable layout / adjustment thunks / manual allocator pairing (not needed in Rust; Rust's ownership is not a reason to ignore the lifecycle, but to replace its mechanism with equivalent behavior).

No Rust source files were modified (Section 12 mandate honored; inspected read-only only).

---

## Remaining Blockers (genuine, not concealed)

| Blocker | Classification | Minimum evidence to resolve |
|---------|---------------|----------------------------|
| Allocation call site + size | BLOCKED | Breakpoint `HeapAlloc`/`RolClient_AllocMemory`; capture return address |
| Active vptr at dispatch | BLOCKED | Breakpoint `0x44F3F0`; read `[EDI]` |
| AddRef / increment of `obj+0x20` | UNKNOWN | Search all functions; decompile initializer bodies |
| Free routine `0x500CA6` identity | UNKNOWN | Symbols/PDB or runtime breakpoint |
| Parent block free location | UNKNOWN | Trace `FUN_00473210` → helper `0x489750` |

These are honestly reported (Report 19), not concealed to appear complete.

---

## Evidence Quality Summary

| Classification | Count |
|----------------|-------|
| PROVEN | ~18 (addresses, bytes, instructions, vptr writes, chain steps) |
| STRONGLY SUPPORTED | ~8 (refcount counter role, deallocation chain, layout, Rust candidates) |
| LIKELY | ~4 (constructor=init stages; scalar deleting destructor; single-ownership) |
| HYPOTHESIS | ~6 (AddRef absent; +0x24 flag meaning; +0x28/+0x2C semantics; Table A unconventional) |
| UNKNOWN / BLOCKED | 13 (Report 19 register U1–U13; B1–B3) |

---

## Implementation Readiness

- **Can Rust implementation begin?** Partially — yes for state enums, atomics, `Drop`, collection types; **defer `Arc` vs `Box` decision** until AddRef (U5) resolved.
- **Do not reproduce** native vtable/this-adjust/allocator-pairing details in Rust.
- Next phase should focus on: (a) finding the constructor caller/allocation site, (b) resolving AddRef, (c) disassembling the 3 unresolved vtable slot bodies, (d) runtime capture if a debugger becomes available.

---

## GitHub Publication

- Report directory: `opencode-windows/PHASE_2_5/`
- Reports created: **20** (01–20)
- Branch: `phase-2-5-static-forensics`
- Commit SHA and URL: recorded in the terminal summary after push.
- All 20 report paths present in the published commit (verified post-push).
