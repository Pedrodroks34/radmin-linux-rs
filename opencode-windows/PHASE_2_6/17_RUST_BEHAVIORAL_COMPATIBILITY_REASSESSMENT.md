# Phase 2.6 Stage 17 — Rust Behavioral Compatibility Reassessment

**Classification: STRONGLY SUPPORTED** — corrected ownership model (release-once latch, single ownership, no AddRef) informs Rust mappings. `Arc<T>` is NOT justified. `Box<T>` is the leading candidate.

Cross-reference: `10_REFERENCE_COUNTER_AND_CONTROL_BLOCK_RECONSTRUCTION.md`, `09_ADDREF_AND_OWNERSHIP_ACQUISITION_INVESTIGATION.md`, `16_COMPLETE_OBJECT_LIFECYCLE_AND_OWNERSHIP_GRAPH.md`.

---

## 1. Corrected Native Behavior Summary

| Behavior | Evidence | Classification |
|----------|----------|----------------|
| Single ownership (release-once latch) | `field_0x20` pointer: non-NULL→NULL transition; no increment | STRONGLY SUPPORTED |
| Release is idempotent | `LOCK XADD(...,0)` reads pointer; `JZ` skips teardown if NULL | PROVEN |
| Teardown destroys CRITICAL_SECTION (+0x08) | `FUN_00489750` → `DeleteCriticalSection(&this->field_0x08)` | PROVEN |
| Teardown NULLs `field_0x20`, sets `field_0x24=1` | `XCHG [&field_0x20],0`; `XCHG [&field_0x24],1` | PROVEN |
| No AddRef / increment anywhere | Whole-program atomic scan: none targeting `field_0x20` | STRONGLY SUPPORTED |
| No external control block | All field accesses direct via LEA | STRONGLY SUPPORTED |
| Allocation site unknown | No `HeapAlloc`/`RolClient_AllocMemory` in object path | UNKNOWN |

---

## 2. Candidate Rust Abstractions (Reassessed)

| # | Abstraction | Native behavior represented | Preserves | Does NOT preserve | Unknown | Safe to use? |
|---|-------------|---------------------------|-----------|-------------------|---------|-------------|
| M1 | `Box<T>` | Single ownership; deterministic drop; release-once | Ownership transfer, idempotent drop, CRITICAL_SECTION cleanup via `Drop` | Concurrency (`Send`/`Sync` depends on T); the exact `field_0x20` pointer semantics | Initialization path (who sets field_0x20 non-NULL) | **YES** |
| M2 | `Arc<T>` | Strong reference counting | Automatic refcount, `Drop` at zero | **Native has NO increment (AddRef)** — `Arc::clone()` adds behavior not evidenced | None | **NO — rejected** |
| M3 | `AtomicPtr<T>` | `field_0x20` as pointer (read via atomic, write via exchange) | Atomicity of pointer field | The latch semantics (non-NULL→NULL once) need custom wrapper | Pointee type | **PARTIALLY** |
| M4 | `AtomicU32` | `field_0x24` torn-down flag | Atomic flag | Field is a pointer, not u32; using u32 misrepresents type | None | **PARTIALLY** (for field_0x24 only) |
| M5 | `AtomicBool` | `field_0x24` as bool flag | Atomic bool | Field is u32, not bool | None | **PARTIALLY** |
| M6 | `Mutex<T>` / `CriticalSection` | `field_0x08` CRITICAL_SECTION | Mutual exclusion, `Drop` calls DeleteCriticalSection | Windows-specific CRITICAL_SECTION semantics (recursive, spin count) | None | **YES** (with `windows` crate) |
| M7 | `enum` lifecycle state | `field_0x28` (state), `field_0x2C` (flag) | Typed states instead of raw u32 comparisons | Actual state semantics unknown | State meanings | **YES** |

---

## 3. Recommended Rust Model

```rust
use std::sync::atomic::{AtomicPtr, AtomicU32, Ordering};
use std::ptr::NonNull;
use windows::Win32::System::Threading::CRITICAL_SECTION;
use windows::Win32::System::LibraryLoader::DeleteCriticalSection;

struct ObjectCandidate {
    vptr: usize,                                    // +0x00
    field_0x04: *mut c_void,                        // +0x04
    critical_section: CRITICAL_SECTION,             // +0x08 — Drop deletes it
    // ... zeroing region 0x0C–0x4C4 ...
    release_latch: AtomicPtr<c_void>,               // +0x20 — non-NULL=alive, NULL=released
    torn_down: AtomicU32,                           // +0x24 — 0=alive, 1=torn-down
    state: u32,                                     // +0x28 — compared to 5
    flag: u32,                                      // +0x2C — compared to 0
    call_counter: u32,                              // +0x30 — plain (non-atomic) INC
    // ... through 0x5C40
}

impl Drop for ObjectCandidate {
    fn drop(&mut self) {
        // Teardown: only runs if latch was non-NULL
        if self.release_latch.swap(NonNull::dangling(), Ordering::AcqRel).is_some() {
            unsafe { DeleteCriticalSection(&mut self.critical_section); }
            self.torn_down.store(1, Ordering::Release);
        }
    }
}
```

**Key design decisions:**
1. `Box<ObjectCandidate>` for single ownership — matches release-once latch.
2. `AtomicPtr<c_void>` for `field_0x20` — correctly models it as a pointer, not a counter.
3. `AtomicU32` for `field_0x24` — torn-down flag.
4. `Drop` impl that conditionally runs teardown (idempotent via swap-to-NULL).
5. `CRITICAL_SECTION` in `field_0x08` with custom `Drop` calling `DeleteCriticalSection`.

---

## 4. What Is NOT Recommended

| Abstraction | Why rejected |
|-------------|--------------|
| `Arc<T>` | No AddRef/increment exists; `Arc::clone()` would add behavior not evidenced |
| `AtomicU32` for `field_0x20` | `field_0x20` is a pointer, not a counter; misrepresents type |
| `Rc<T>` | `Rc` is `!Send`/`!Sync`; `field_0x20` uses atomic ops suggesting possible cross-thread |
| Plain `u32` for `field_0x20`/`field_0x24` | Loses atomicity and pointer semantics |

---

## 5. Implementation Readiness

| Aspect | Status | Blocker |
|--------|--------|---------|
| Ownership primitive (`Box<T>` vs `Arc<T>`) | **RESOLVED** — `Box<T>` (single ownership) | None |
| Atomic field types (`AtomicPtr` vs `AtomicU32`) | **RESOLVED** — `AtomicPtr` for field_0x20 | None |
| Teardown / `Drop` semantics | **RESOLVED** — conditional, idempotent | None |
| CRITICAL_SECTION mapping | **RESOLVED** — `DeleteCriticalSection` in `Drop` | None |
| Allocation site (who creates the object?) | **UNKNOWN** | Report 19 U1/U2 |
| Initial `field_0x20` value (who sets non-NULL?) | **UNKNOWN** | Report 19 U5 |
| Parent block free | **UNKNOWN** | Report 19 U8 |

**Classification: PARTIALLY READY.** The ownership model and atomic field types are understood well enough to begin a `Box<T>`-based Rust design. The initialization path (who allocates and sets `field_0x20` non-NULL) remains unknown but does not block modeling the teardown/ownership semantics.

---

## 6. Confidence Summary

| Finding | Classification |
|---------|---------------|
| `Arc<T>` not applicable (no AddRef) | STRONGLY SUPPORTED |
| `Box<T>` is leading ownership candidate | LIKELY |
| `AtomicPtr<c_void>` for `field_0x20` | STRONGLY SUPPORTED |
| `AtomicU32`/`AtomicBool` for `field_0x24` | PARTIALLY SUPPORTED |
| `Drop` with conditional teardown | STRONGLY SUPPORTED |
| `CRITICAL_SECTION` → `DeleteCriticalSection` in `Drop` | PROVEN |
| Implementation readiness: PARTIALLY READY | — |
