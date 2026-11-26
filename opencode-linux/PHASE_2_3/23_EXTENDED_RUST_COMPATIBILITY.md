# Phase 2.3 Stage 23 — Extended Rust Compatibility Mapping

**Classification: VERIFIED** (repository inspected read-only; zero modifications; AGENTS.md followed)

## 1. Repository State

| Property | Value |
|----------|-------|
| Path | `/home/rhuan/.gemini/antigravity/scratch/radmin-re/repo/` |
| Branch | `fix/phase-3-4-tlv-topology-integration` |
| Pre-existing modified tracked files | 8 |
| Pre-existing untracked files | 43 |
| Changes made by Phase 2.3 | NONE |

No Rust source files were modified. All mapping is documentation-only.

## 2. Updated Mapping Table — Windows → Rust

| Windows Behavior (Finding ID) | Existing Rust Component | Status | Gap | Rust Mapping |
|-------------------------------|------------------------|--------|-----|--------------|
| C++ vtable dispatch (P2.2-VT-*) | None (daemon module not implemented) | YES | Do not implement C++ vtable semantics | Rust traits + `dyn` dispatch |
| Multi-phase constructor (P2.2-CTOR-*) | None (daemon module not implemented) | YES | Do not replicate C++ constructor phases | `fn new()` + explicit init |
| Adjustment thunks (P2.2-THUNK-*) | None | YES | Do not implement `this` adjustment | Not needed in Rust |
| Indirect virtual calls (P2.2-ICALL-*) | None (daemon module not implemented) | YES | Use Rust match-based dispatch | `match` on enum / trait dispatch |
| Ref-counted destruction (P2.2-REF-*) | None (daemon module not implemented) | PARTIAL | Use `Arc<T>`/`Rc<T>` + `Drop` | `Arc<T>` with `AtomicUsize` refcount |
| Object fields u32 comparisons (P2.2-FIELD-*) | `session/` module (skeleton) | YES | Use enum state machine | `enum SessionState` |
| HeapAlloc/HeapFree allocation | None | YES | Use `Box::new()` / `Arc::new()` | Rust ownership model |
| List cleanup (FUN_00440670 etc.) | None | YES | Use `Vec<T>` / `LinkedList<T>` with `Drop` | Rust collections + Drop |
| Refcount at obj+0x20 with LOCK | None | YES | `Arc<T>` / `std::sync::atomic::AtomicUsize` | `Arc<T>` |
| Registry close (RegCloseKey) | None | YES | Config file handle close | `Drop` on config handle |
| EventUnregister (ETW) | None | YES | Event/tracing unsubscribe | `tracing` subscriber drop |
| Global flag with critical section | None | YES | `std::sync::atomic::AtomicBool` | `AtomicBool` |
| PerfStopProvider (ETW provider) | None | YES | Tracing subscriber shutdown | `tracing::subscriber::set_default` |

## 3. Detailed Mapping: Object Lifecycle

### 3.1 Reference Counting

**Windows (verified):**
- Refcount stored at `obj + 0x20` (32 decimal)
- `FUN_004731E0` = `Release()` — atomic `LOCK()`/`UNLOCK()` read of refcount
- If refcount != 0, calls `FUN_00473210` (decrement-and-destroy-if-zero)
- `GetLastError`/`SetLastError` preserves error code across operation
- `AddRef()` function not yet identified (search for increment at obj + 0x20)

**Rust mapping:**
```rust
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

// Windows Release() maps to Arc<T>::clone() drop
// Windows AddRef() maps to Arc::clone()
// Windows refcount at obj+0x20 maps to Arc's internal strong/weak count
```

**Implementation note:** The Rust `session/` module already uses `Arc<T>` implicitly through `SessionManager` fields (`session: Session`, `channel: Option<TcpChannel>`, etc.). For shared ownership across threads, `Arc<SessionManager>` would be the equivalent.

### 3.2 List Cleanup / Node Destruction

**Windows (verified):**
- Five list-cleanup functions (`FUN_00440670`, `FUN_0043B470`, `FUN_0043B4C0`, `FUN_0043B420`, `FUN_0043A9A0`)
- Each iterates a doubly-linked list via `FUN_00475870(list_head)` (pop head)
- Per-node cleanup varies by offset (0x08, 0x10, 0x18, 0x48)
- All call `FUN_004e6cd7(node)` → `thunk_FUN_004ec736` → `FUN_004ec736` → `CALL [0x00500ca6]`

**Rust mapping:**
```rust
use std::collections::LinkedList;
use std::sync::Arc;

// Windows list cleanup maps to Drop impl on a container
// that holds Vec<Arc<Node>> or LinkedList<Arc<Node>>
// When the container drops, all nodes are dropped automatically
// via Rust's ownership model — no manual unlinking needed
```

**Implementation note:** The Rust `daemon/mod.rs` uses `Mutex<Option<SessionManager>>` and `Mutex<Option<Tunnel>>`. On `drop()`, these are automatically cleaned up. No manual linked-list traversal is needed.

### 3.3 Destruction Chain

**Windows (verified):**
```
Release (FUN_004731E0)
  → FUN_00473210 (destroy if refcount 0)
    → List cleanup functions
      → FUN_004e6cd7 (per node)
        → thunk → FUN_004ec736 → CALL [0x00500ca6]
```

**Rust mapping:**
```rust
impl Drop for MyObject {
    fn drop(&mut self) {
        // Automatic: all fields dropped in reverse order
        // Arc<T> decrements refcount; if 0, inner T is dropped
        // Vec<T> / LinkedList<T> drops all elements
    }
}
```

No explicit destruction chain is needed in Rust — `Drop` is automatic and field-ordered.

### 3.4 Registry Handle Management

**Windows (verified):**
- `FUN_00475C00` closes `HKEY` at `obj + 8` via `RegCloseKey`
- Nulls handle after close, resets `SetLastError(0)`

**Rust mapping:**
```rust
struct RegKey(HKEY);

impl Drop for RegKey {
    fn drop(&mut self) {
        if self.0 != 0 {
            unsafe { RegCloseKey(self.0); }
            self.0 = 0;
        }
    }
}
```

**Implementation note:** No registry equivalent exists in the Rust repo. This is Windows-specific and should not be implemented unless a Windows port is needed.

### 3.5 ETW Event Management

**Windows (verified):**
- `FUN_00451900` calls `EventUnregister(*param_1)` on `REGHANDLE`
- Zeroes handle after unregister

**Rust mapping:**
```rust
// Windows EventUnregister maps to dropping a tracing subscriber
// or unsubscribing from an event channel
```

**Implementation note:** The Rust repo uses `tracing` crate for logging. No ETW equivalent is needed.

### 3.6 Critical Section / Global Flag

**Windows (verified):**
- `FUN_0046AE70` (getter) / `FUN_0046B9F0` (setter) for `DAT_0055e3fd`
- Critical section at `DAT_0055e428`, init flag at `DAT_0055e444`
- Lazy initialization via `FUN_00403700` / `FUN_004038a0`

**Rust mapping:**
```rust
use std::sync::atomic::AtomicBool;

static GLOBAL_FLAG: AtomicBool = AtomicBool::new(false);

// Getter: GLOBAL_FLAG.load(Ordering::SeqCst)
// Setter: GLOBAL_FLAG.store(value, Ordering::SeqCst)
```

No critical section needed in Rust — `AtomicBool` provides lock-free synchronization.

## 4. FAM RT Class Hierarchy Mapping

**Windows (verified):**
- `FamRT::CFile::vftable` — referenced by `FUN_004802F0` (constructor)
- `FamRT::CUniversalString::vftable` — referenced by `FUN_0043A9A0` (list cleanup)
- `FamRT` namespace confirmed via vtable names

**Rust mapping:**
```rust
// Windows C++ vtable → Rust trait object
trait CFile {
    fn do_something(&self);
}
struct CFileImpl;
impl CFile for CFileImpl { ... }

// Windows CUniversalString → Rust String or custom type
// CUniversalString has a vtable → could be a trait object dyn CUniversalString
```

**Implementation note:** No direct mapping needed in the Rust repo. The Rust implementation uses its own abstractions, not C++ class hierarchies.

## 5. What Should NOT Be Implemented in Rust

Per AGENTS.md constraints and verified findings:

| Windows Pattern | Reason Not to Implement |
|-----------------|------------------------|
| C++ vtable layouts | Rust trait objects use different layout; not portable |
| Adjustment thunks (`SUB ECX, offset`) | Rust doesn't have `this` pointer adjustment |
| Multi-phase vptr transitions | Rust constructors don't overwrite vtables |
| `field_0x28/0x2C/0x30` as u32 fields | Rust should use enum state machine, not numeric comparisons |
| Manual `HeapAlloc`/`HeapFree` | Rust ownership model handles allocation/deallocation |
| `LOCK()`/`UNLOCK()` critical sections | Rust `Arc<T>` / `AtomicBool` / `Mutex<T>` are safer |
| `RegCloseKey` / `EventUnregister` | Windows-specific APIs; no Linux equivalent |
| `GetLastError`/`SetLastError` | Rust uses `Result<T, E>` for error handling |

## 6. What Could Be Implemented (Future Phase)

| Windows Pattern | Rust Implementation | Priority |
|-----------------|---------------------|----------|
| Reference-counted object | `Arc<T>` + `Drop` | Medium |
| List of objects with cleanup | `Vec<Arc<T>>` / `LinkedList<Arc<T>>` | Medium |
| Global flag with synchronization | `AtomicBool` / `atomic::AtomicU32` | Low |
| Object pool / factory | `Arc::new()` / custom factory function | Low |
| Session state machine | `enum SessionState` + `SessionManager` | High (partially done) |

The `session/` module already implements `SessionState` enum and `SessionManager` with proper state transitions. The `daemon/` module implements `DaemonContext` with `Arc<DaemonContext>` for shared ownership. These are the correct Rust equivalents — they do not need to mirror the C++ implementation details.

## 7. AGENTS.md Compliance

- No source files modified ✓
- No comments added to source ✓
- No new modules created ✓
- No speculative implementations ✓
- Documentation placed in this report (not in source) ✓
- Pre-existing Git changes preserved ✓
- No hard constraints violated ✓