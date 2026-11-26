# Phase 2.5 Stage 17 — Rust Behavioral Compatibility Review

**Classification: STRONGLY SUPPORTED (mappings are candidates, not equivalences)** — native behavior verified from the binary; Rust repo inspected **read-only** (no source files modified). Mappings are behavioral candidates; none are automatic equivalences.

Cross-reference: `15_COMPLETE_OBJECT_LIFECYCLE_RECONSTRUCTION.md`, `11_OBJECT_FIELD_AND_SUBOBJECT_LAYOUT.md`, `09_FUN_004731E0_AND_REFERENCE_COUNT_PAIRING.md`, `12_ALLOCATION_AND_FACTORY_CALL_GRAPH.md`.

---

## 1. Native Behavior Understood (verified / supported)

| Aspect | Verified native behavior | Evidence classification |
|--------|-------------------------|-------------------------|
| Object | `ObjectCandidate` with primary vptr at `+0x00`, 5 subobject vptrs at `+0x38/0x40/0x50/0x98/0x9C`, fields through `0x5C40` | STRONGLY SUPPORTED |
| Vptr transitions | Constructor writes `0x51FFB4 → 0x51E570 → 0x51E4F0` (3 stages, same object, same `[this+0]`) | PROVEN |
| Reference counter | `obj+0x20`; Release = `LOCK XCHG(counter,0)`; teardown if old != 0; no increment found | STRONGLY SUPPORTED (counter); no AddRef found |
| Teardown flag | `obj+0x24` set to 1 atomically by `FUN_00473210` | HYPOTHESIS |
| Dispatch guards | `FUN_0044F3F0`: `[+0x28]==5 && [+0x2C]!=0`; then `[vptr+0x34]`, `[vptr+0x58]`; `INC +0x30` | PROVEN |
| Teardown | `FUN_00473210`: helper `0x489750` on `+0x8`; XCHG `+0x20`=0; XCHG `+0x24`=1 | PROVEN |
| Deallocation | List nodes freed via `FUN_004e6cd7` → thunk → `FUN_004ec736` → direct `CALL 0x00500CA6` (free routine) | STRONGLY SUPPORTED |
| Allocation | **NOT FOUND** — no `HeapAlloc`/`RolClient_AllocMemory`/factory; constructor takes `this` in ECX | UNKNOWN |
| Adjustment thunks | 5 thunks `SUB ECX, off; JMP ctor` for subobject `this` recovery | PROVEN |
| C++ vtable semantics | Multiple-inheritance vptr transitions + adjustment thunks | PROVEN (but rejected as a Rust model) |

Key behavioral takeaways:
- Reference counting is **single-direction**: counter only goes to zero (Release/exchange-to-zero); no AddRef increment found. Most consistent with single-ownership or a release-latch, not multi-owner `Arc`-style strong+weak counting.
- Destruction is idempotent (exchange-to-zero makes double-release a no-op).
- Teardown sets a `+0x24` flag (likely destroyed/in-teardown marker) atomically.
- C++ vtable/this-adjustment is an implementation detail of multiple inheritance, not a behavior to reproduce in Rust.

---

## 2. Rust Repository Inspected (read-only, no modifications)

The Rust project (`radmin-vpn`, edition 2021) at `C:\Users\Rhuan\Documents\Projeto Padrão\radmin-linux-rs` was inspected **read-only**. Observed structure (from `Cargo.toml` and `src/`):

- Dependencies: `tokio` (async runtime), `rtnetlink` + `socket2` (TAP/tunnel/network), `openssl`/`ring` (crypto), `uuid` (peer IDs), `zeroize` (secret zeroing), `thiserror`/`anyhow` (error handling), `tracing` (logging), `serde`/`bytes` (framing).
- Modules include: `src/session/`, `src/crypto/`, `src/tunnel/`, `src/transport/`, `src/peer/`, `src/routing/`, `src/relay/`, `src/daemon/`, `src/identity/`, `src/protocol/`, `src/authentication/`, `src/cli/`, `src/config/`, `src/discovery/`, `src/nat/`.
- No source file was opened for writing, and none was modified. This report does not propose any source change.

Existing Rust abstractions potentially relevant (observed by module names only; internals not audited):
- Session / connection lifecycle modules (`src/session/`, `src/transport/`).
- Crypto / key lifecycle (`src/crypto/`).
- TAP/tunnel device (`src/tunnel/`, `rtnetlink`, `socket2`).

---

## 3. Candidate Mappings (native → Rust)

| # | Native behavior (evidence) | Candidate Rust abstraction | Preserves | Does not automatically preserve | Unknown / gap | Safe to implement? |
|---|---------------------------|---------------------------|-----------|--------------------------------|---------------|--------------------|
| M1 | Refcount at `obj+0x20`; Release = exchange-to-zero; teardown if old!=0; **no AddRef found** | `Arc<T>` (strong count) | Automatic strong refcount; `Drop` on zero | Native has **no increment** (AddRef absent) — `Arc::clone()` would add behavior not evidenced; native zero-path is idempotent latch | Whether native actually has an AddRef (inlined/unanalyzed) | **Conditionally** — only if increment behavior is confirmed; otherwise `Arc` over-models |
| M2 | Release-latch / single-ownership (counter only zeroed) | `Box<T>` + `Drop`, or `Rc<T>` (single-thread) | Single ownership; deterministic drop | Native atomic `LOCK XCHG` suggests possibly cross-thread; `Rc` is `!Send`/`!Sync` | Thread-safety of counter | **Yes** for `Box<T>`/`Drop`; `Rc` only if single-thread confirmed |
| M3 | Atomic counter / teardown flag (`+0x20`, `+0x24` atomic XCHG) | `AtomicU32` / `AtomicBool` | Atomicity, ordering | Native uses full `LOCK XCHG` (seq-cust); Rust `Atomic*` allows choosing ordering (could weaken) | Ordering requirements | **Yes** — `AtomicU32`/`AtomicBool` match atomicity |
| M4 | Teardown / destructor logic (`FUN_00473210` + helper `0x489750`) | `impl Drop for T` | Deterministic cleanup on drop | Native teardown is called conditionally (old!=0), not necessarily on every `Drop` | Whether Drop == teardown | **Yes** — `Drop` is the natural Rust equivalent |
| M5 | List of nodes freed via `0x500CA6` | `Vec<Arc<T>>` / `LinkedList<Arc<T>>` / `Vec<Box<T>>` | Owned collection; elements dropped when collection dropped | Native list cleanup may free nodes via a custom routine | Node free routine identity | **Yes** |
| M6 | C++ vtable transitions + this-adjustment thunks | **Not modeled** (enums + `match` / trait objects) | Avoids fragile vptr/this-adjust | Native multiple-inheritance layout not needed in Rust | None (by design) | **Yes** — explicitly rejected as unnecessary |
| M7 | Guards `[+0x28]==5`, `[+0x2C]!=0`, counter `+0x30` | `enum SessionState` + `u64` counter | Explicit states; typed | Native uses raw u32 comparisons | State semantics | **Yes** — clearer than raw ints |

---

## 4. Behavioral Gaps (what is NOT yet understood)

| Gap | Why it matters | Blocker? |
|-----|----------------|----------|
| Allocation site / how `this` is produced | Can't confirm heap vs stack vs embedded; Rust `Box::new`/`Arc::new` may not mirror native allocator | No (Rust chooses its own allocator) |
| AddRef / increment of `obj+0x20` | Determines `Arc` vs `Box` vs `Rc` vs single-ownership | **Yes** — decides the ownership primitive |
| Initial value of `obj+0x20` | Determines start count | No |
| `obj+0x24` reader / meaning | Teardown flag semantics | No |
| Parent object block free location | Whether `Drop` frees the block or helper does | No |
| `FUN_00489750` helper role | Part of teardown; unknown | No |
| Runtime-active vptr at dispatch | Not needed for Rust (enum dispatch) | No |

---

## 5. Implementation Readiness Assessment

**Can Rust implementation safely begin?** — **Partially, with caveats.**

- **Safe to begin:** Modeling session/connection lifecycle with `enum SessionState`, `Box<T>` or `Arc<T>` (if AddRef confirmed) + `Drop`, `AtomicU32`/`AtomicBool` for counter/flag, `Vec`/`LinkedList` for node lists. These are behavioral equivalents that do NOT require reproducing C++ vtable layouts, adjustment thunks, or manual `HeapAlloc`/`HeapFree`.
- **Not safe to finalize ownership primitive until:** AddRef/increment of `obj+0x20` is resolved (found or confirmed absent). If absent, `Box<T>`+`Drop` (single ownership) is more accurate than `Arc<T>`.
- **Do not:** reproduce native vtable layout, `this`-adjustment thunks, `LOCK XCHG` as a strict requirement (Rust atomics are sufficient), or manual `HeapAlloc`/`HeapFree` pairing.

**Rust's ownership system does NOT make the native lifecycle irrelevant** — it replaces the *mechanism* (manual refcount/vtable/this-adjust) with equivalent *behavior* (ownership, Drop, enum state), but the lifecycle stages (alloc → construct → use → release → teardown → free) must still be represented.

---

## 6. Recommendation

Proceed with a Rust design using:
- `enum` for the `+0x28`/`+0x2C` state/flag fields.
- `AtomicU32` for `obj+0x20` counter and `AtomicBool` for `obj+0x24` teardown flag (matching atomicity).
- `Drop` for teardown (`FUN_00473210` equivalent).
- `Box<T>` if single-ownership confirmed, or `Arc<T>` only after AddRef is confirmed.
- `Vec<T>`/`LinkedList<T>` for the node list freed via `0x00500CA6`-equivalent.

Defer the `Arc` vs `Box` decision until the AddRef question (Report 09/10 gap) is resolved. No Rust source files were or will be modified by this phase.
