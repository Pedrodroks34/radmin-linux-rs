# Phase 2.6 Stage 20 — Final Technical Report

**Classification: FINAL** — independent static forensics and instruction-decoding audit of `RvControlSvc_Installed.exe` (SHA-256 `0E2E6EAACBE8EBE01286CDA39A12EAAD34A20434D50F4F8BF2FDD91D4D6EF2AD`) complete. All 20 Phase 2.6 reports created under `opencode-windows/PHASE_2_6/`.

Cross-reference: all reports 01–19.

---

## Executive Summary

Phase 2.6 performed a critical instruction-decoding audit that **invalidated two central Phase 2.5 conclusions**:

1. **`LOCK XCHG` → `LOCK XADD`**: At `0x004731F2`, bytes `F0 0F C1 32` decode as `LOCK XADD [EDX], ESI` (atomic fetch-add-zero), NOT `LOCK XCHG [EDX], ESI` (exchange-to-zero). Verified by both Capstone 5.0.7 and a manual decoder against REA raw bytes.

2. **Pointer-indirect → direct field access**: At `0x0047321D`/`0x0047322D`, bytes `8D 4E 20`/`8D 4E 24` decode as `LEA ECX,[ESI+0x20]`/`LEA ECX,[ESI+0x24]` (load ADDRESS), NOT `MOV ECX,[ESI+0x20]`/`MOV ECX,[ESI+0x24]` (load VALUE). The subsequent `XCHG [ECX],EDX` operates on direct object fields, not pointer-indirect pointees.

As a result:
- `FUN_004731E0` (Release) **atomically reads** `field_0x20` without modifying it; teardown is called iff the old pointer value is non-NULL.
- `field_0x20` is a **release-latch pointer** (non-NULL=alive, NULL=released), NOT a reference counter.
- **No AddRef/increment exists** anywhere — `Arc<T>`-style strong reference counting is rejected.
- The correct model is **single-ownership release-once latch**, best mapped to `Box<T>` in Rust.

Environment: **Windows 10 Pro x64 host** (target is PE32 x86). Reports under `opencode-windows/PHASE_2_6/`.

---

## Major Corrections (vs. Phase 2.5)

| # | Phase 2.5 claim | Corrected finding | Confidence | Report |
|---|-----------------|-------------------|------------|--------|
| C1 | `LOCK XCHG [EDX], ESI` at `0x4731F2` | `LOCK XADD [EDX], ESI` (opcode `0F C1` = XADD, `87` = XCHG) | PROVEN | 03, 04 |
| C2 | Release exchanges counter to zero | Release atomically READS pointer (XADD with 0 = no change); teardown NULLs it later | PROVEN | 04, 05 |
| C3 | `MOV ECX,[ESI+0x20]` loads value | `LEA ECX,[ESI+0x20]` loads ADDRESS (`8D` not `8B`) | PROVEN | 03, 05 |
| C4 | `MOV ECX,[ESI+0x24]` loads value | `LEA ECX,[ESI+0x24]` loads ADDRESS | PROVEN | 03, 05 |
| C5 | `XCHG [ECX]` is pointer-indirect | `XCHG [&field_0x20]` is direct field access via LEA-computed address | PROVEN | 05 |
| C6 | `field_0x20` is reference counter | `field_0x20` is a pointer (release latch); no increment found | STRONGLY SUPPORTED | 07, 09, 10 |
| C7 | External control block exists | None — all field accesses direct | STRONGLY SUPPORTED | 07, 10 |
| C8 | `CALL [0x500ca6]` indirect slot | `CALL 0x500CA6` direct to code in `.text` | PROVEN (confirms P2.5 correction) | 14 |
| C9 | `Arc<T>` justified | No — no AddRef found | STRONGLY SUPPORTED | 09, 17 |
| C10 | `FUN_00489750` unknown import | Import `[0x519138]` = `DeleteCriticalSection` (KERNEL32 ILT[12]) | PROVEN | 06 |

Root cause of C1–C5: Phase 2.5 misread opcode `0F C1` (XADD) as `87` (XCHG), and opcode `8D` (LEA) as `8B` (MOV).

---

## Confirmed Findings

| Finding | Classification | Report |
|---------|---------------|--------|
| Binary: PE32 x86, ImageBase `0x00400000`, SHA-256 verified | PROVEN | 01 |
| `LOCK XADD [&field_0x20], 0` at `0x4731F2` (atomic read, field unchanged) | PROVEN | 03, 04 |
| `LEA ECX,[ESI+0x20]` / `LEA ECX,[ESI+0x24]` (address loads) | PROVEN | 03, 05 |
| `XCHG [&field_0x20], 0` and `XCHG [&field_0x24], 1` (direct atomic writes) | PROVEN | 05 |
| `FUN_00489750` → `DeleteCriticalSection(&field_0x08)` | PROVEN | 06 |
| All field accesses direct (no pointer indirection) | PROVEN | 07 |
| Whole-program atomic scan: `LOCK XADD`/`CMPXCHG` found; no `LOCK XCHG` anywhere | PROVEN | 08 |
| No AddRef/increment of `field_0x20` anywhere | STRONGLY SUPPORTED | 09 |
| Release-once latch, idempotent | STRONGLY SUPPORTED | 10, 16 |
| Slot-13 targets return 16; slot-22 targets arg-dependent | PROVEN | 11 |
| Constructor unreachable (no external caller) | PROVEN | 12 |
| No allocator calls in object path | PROVEN | 13 |
| `0x00500CA6` = code in `.text`, calls import `[0x5192EC]` | STRONGLY SUPPORTED | 14 |

---

## Object Lifecycle Reconstruction (Corrected)

```
[ALLOCATION UNKNOWN] → FUN_0043ECF0 → FUN_0043E1A0
   ctor: zeroing; vptr 0x51FFB4→0x51E570→0x51E4F0; subobject vptrs 2-phase;
         field_0x08=CRITICAL_SECTION; field_0x20 set non-NULL (by UNKNOWN)
→ OBJECT READY
→ FUN_0044F3F0 dispatch [vptr+0x34]=16, [vptr+0x58]=arg-dependent (guard +0x28==5, +0x2C!=0; INC +0x30)
→ FUN_004731E0 Release: LOCK XADD [field_0x20],0; if old!=NULL → teardown
→ FUN_00473210 Teardown: DeleteCriticalSection(field_0x08); XCHG field_0x20=0; XCHG field_0x24=1
→ List nodes: FUN_004e6cd7 → thunk 0x4E7EC0 → FUN_004ec736 → CALL 0x500CA6 → Import[0x5192EC]
→ [PARENT BLOCK FREE UNKNOWN]
```

**Unresolved edges:** allocation site/caller, initial `field_0x20` value, AddRef (absent), active vptr at dispatch, parent block free, import `[0x5192EC]` identity.

---

## Ownership Model — Final

| Question | Answer | Classification |
|----------|--------|----------------|
| Reference counting? | **NO** — no increment found | STRONGLY SUPPORTED |
| Single-ownership release-once latch? | **LIKELY** — matches evidence | LIKELY |
| External control block? | **NO** | STRONGLY SUPPORTED |
| Release idempotent? | **YES** — NULL check skips teardown | PROVEN |
| `Arc<T>` appropriate? | **NO** — no AddRef | STRONGLY SUPPORTED |
| `Box<T>` appropriate? | **LIKELY** — single ownership | LIKELY |

---

## Rust Compatibility — Final

**Recommended model:**
```rust
struct ObjectCandidate {
    vptr: usize,                    // +0x00
    critical_section: CRITICAL_SECTION,  // +0x08 — Drop calls DeleteCriticalSection
    release_latch: AtomicPtr<c_void>,    // +0x20 — non-NULL=alive, NULL=released
    torn_down: AtomicU32,          // +0x24 — 0=alive, 1=torn-down
    // ... fields through 0x5C40
}
impl Drop for ObjectCandidate {
    fn drop(&mut self) {
        if self.release_latch.swap(null, AcqRel).is_some() {
            unsafe { DeleteCriticalSection(&mut self.critical_section); }
            self.torn_down.store(1, Release);
        }
    }
}
```
Use `Box<ObjectCandidate>` for single ownership.

**Readiness: PARTIALLY READY.** Ownership model and atomic types resolved; initialization path (who sets `field_0x20` non-NULL) unknown.

---

## Evidence Quality Summary

| Classification | Count |
|----------------|-------|
| PROVEN | ~22 (instruction decodings, chain steps, field accesses, no-LOCK-XCHG scan) |
| STRONGLY SUPPORTED | ~10 (release-once latch, no AddRef, Rust mappings, layout) |
| LIKELY | ~4 (Box<T> candidate, single-ownership, Table A unconventional) |
| HYPOTHESIS | ~6 (field_0x20 pointee type, field_0x24 readers, import `[0x5192EC]` identity) |
| UNKNOWN | 13 (U1–U13 in Report 19) |
| BLOCKED | 3 (B1–B3: allocation capture, active vptr at dispatch, runtime indirect target) |

No hypothesis presented as fact; unresolved items explicitly reported.

---

## Remaining Blockers (genuine, not concealed)

| Blocker | Classification | Minimum evidence to resolve |
|---------|---------------|----------------------------|
| Allocation call site + size | BLOCKED | Breakpoint `HeapAlloc`/`RolClient_AllocMemory`; capture return address |
| Active vptr at dispatch | BLOCKED | Breakpoint `0x44F3F0`; read `[EDI]` |
| AddRef / increment of `field_0x20` | UNKNOWN | Whole-program scan confirmed absence; if confirmed, single-ownership is final |
| Import `[0x5192EC]` identity | UNKNOWN | ILT lookup for IAT slot `0x5192EC` |
| Parent block free location | UNKNOWN | Trace Release caller; find block free |

---

## GitHub Publication

- Report directory: `opencode-windows/PHASE_2_6/`
- Reports created: **20** (01–20), all substantive, all relative Markdown links valid
- Branch: `phase-2-6-instruction-decoding-audit`
- Commit SHA: to be recorded after push
- Commit URL: to be recorded after push
- Push verification: to be performed after push
