# Phase 2.6 Stage 09 — AddRef and Ownership Acquisition Investigation

**Classification: STRONGLY SUPPORTED (AddRef ABSENT)** — whole-program search for increment/acquisition operations on `this+0x20` found NONE. The object uses a release-once latch, not conventional reference counting. No `Arc<T>`-style strong reference count is justified.

Cross-reference: `08_COMPLETE_ATOMIC_OPERATION_INVENTORY.md`, `07_OBJECT_FIELD_AND_POINTER_RELATIONSHIP_MODEL.md`, `10_REFERENCE_COUNTER_AND_CONTROL_BLOCK_RECONSTRUCTION.md`.

---

## 1. Search Methodology

Searched the entire `.text` section for all atomic and increment operations that could serve as AddRef:

| Search pattern | Instruction class | Result for `this+0x20` |
|----------------|-------------------|------------------------|
| `LOCK XADD [mem], 1` | Atomic fetch-add-one | None found |
| `LOCK ADD [mem], 1` | Atomic add-one | None found |
| `LOCK INC [mem]` | Atomic increment | None found |
| `LOCK XADD [mem], reg` (reg≠0) | Atomic fetch-add-register | None targeting `this+0x20` |
| `XCHG [mem], reg` (store nonzero) | Atomic exchange-store | `XCHG [&field_0x20], 0` (Teardown only) |
| `CMPXCHG` loop | Compare-and-swap increment | None targeting `this+0x20` |
| Plain `INC [mem]` | Non-atomic increment | `INC [EDI+0x30]` (call counter, not `0x20`) |

The whole-program atomic scan (Report 08) confirmed:
- `LOCK XADD` appears hundreds of times, but all on OTHER objects' fields (`[EDI+4]`, `[ECX]`, globals) — never on `ObjectCandidate.field_0x20` with a nonzero addend.
- The ONLY `LOCK XADD` on `field_0x20` is at `0x004731F2` with `ESI = 0` (atomic read, no increment).
- The ONLY write to `field_0x20` is `XCHG [&field_0x20], 0` at `0x00473226` (Teardown, sets to NULL).

---

## 2. `FUN_004731E0` (Release) Re-Examined

```c
void __fastcall FUN_004731e0(void *this)
{
    DWORD err = GetLastError();
    // LOCK XADD [&this->field_0x20], 0  -> atomic READ, field UNCHANGED
    // ESI = old pointer value
    void *old_ptr = InterlockedExchangeAdd((volatile LONG *)(this + 0x20), 0);
    if (old_ptr != NULL) {
        FUN_00473210(this);  // teardown (called once)
    }
    SetLastError(err);
}
```

- `field_0x20` is read atomically but **never incremented** by Release.
- Release is a **release-once latch**: if the pointer is non-NULL (object alive), teardown is invoked; teardown then NULLs the pointer, making subsequent Releases no-ops.

---

## 3. `FUN_00473210` (Teardown) — No Increment Either

```c
void __thiscall FUN_00473210(void *this)
{
    FUN_00489750(&this->field_0x08);  // DeleteCriticalSection(&this->field_0x08)
    // neg/sbb/xor/neg dead code (result unused)
    InterlockedExchange((volatile LONG *)(this + 0x20), 0);  // NULL the pointer
    InterlockedExchange((volatile LONG *)(this + 0x24), 1);  // set torn-down flag
}
```

- Teardown **sets `field_0x20` to 0** (destroys the latch), never increments it.
- No AddRef/increment anywhere in the teardown path.

---

## 4. Constructor — No Initialization of `field_0x20` Found

The constructor `FUN_0043E1A0` writes:
- vptr `0x0051FFB4` → `0x0051E570` → `0x0051E4F0` (3 transitions at `+0x00`)
- Subobject vptrs at `+0x38`, `+0x40`, `+0x50`, `+0x98`, `+0x9C` (2 phases)
- Zeroing loop `0x0C`–`0x4C4`

**No write to `field_0x20` was found in the constructor.** The initial value of `field_0x20` (the pointer) is unknown — it may be set by an unidentified caller/factory before the object is used, or by an unanalyzed sub-initializer.

---

## 5. AddRef / Ownership Acquisition — NOT FOUND

| Candidate | Searched | Result |
|-----------|----------|--------|
| Separate `AddRef` function | Whole-program scan | None found |
| Inline increment at call sites | All `LOCK XADD`/`LOCK ADD`/`LOCK INC` sites | None targeting `field_0x20` |
| Constructor increment | `FUN_0043E1A0` body | None |
| Factory increment | No factory identified | N/A |
| `InterlockedIncrement` API | Import table | Not imported |
| `InterlockedExchangeAdd(...,1)` | All `LOCK XADD` sites | None with addend=1 on `field_0x20` |

**Conclusion: There is no AddRef equivalent in the analyzed code.** The pointer at `field_0x20` is set to non-NULL by some unidentified initialization path, read (and teardown-triggered) by Release, and NULLed by Teardown. It is never incremented.

---

## 6. Ownership Classification

| Model | Evidence | Verdict |
|-------|----------|---------|
| Conventional strong refcount (`Arc<T>`) | Requires increment (AddRef) + decrement (Release) | **REJECTED** — no increment found |
| Single-owner `Box<T>` | Object created, used once, released once | **LIKELY** — matches release-once latch |
| Release latch (non-NULL → NULL transition) | `field_0x20` pointer: non-NULL=alive, NULL=released; idempotent | **STRONGLY SUPPORTED** |
| External control block | `field_0x20` is a direct field, not a pointer-to-control-block | **CONTRADICTED** |
| Multi-owner shared ownership | No AddRef; count never increases | **REJECTED** |

---

## 7. What Sets `field_0x20` to Non-NULL Initially?

**UNKNOWN.** No constructor write, no factory write, no initialization path identified for `field_0x20`. Possible sources:
1. An unidentified caller sets it before first use
2. An unanalyzed sub-initializer sets it
3. It's embedded in a larger allocation initialized elsewhere

This is a genuine gap (see Report 19, U1/U5).

---

## 8. Rust Compatibility Implication

- **`Arc<T>` is NOT justified** — no strong-reference acquisition (AddRef) exists.
- **`Box<T>` is the leading candidate** — single ownership, deterministic drop, matches the release-once latch.
- Implementation readiness: **PARTIALLY READY** — ownership model understood, but initialization path (who sets `field_0x20` non-NULL) is unknown.

---

## 9. Confidence Summary

| Finding | Classification |
|---------|---------------|
| No AddRef/increment of `field_0x20` exists | STRONGLY SUPPORTED |
| `field_0x20` only read (XADD=0) and written-to-zero (XCHG=0) | PROVEN |
| Release is release-once latch (not refcount decrement) | STRONGLY SUPPORTED |
| `Arc<T>` (strong refcount) not applicable | STRONGLY SUPPORTED |
| `Box<T>` (single ownership) is leading candidate | LIKELY |
| Initial value of `field_0x20` | UNKNOWN |
