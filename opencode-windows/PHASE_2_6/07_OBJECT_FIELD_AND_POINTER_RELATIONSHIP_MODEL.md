# Phase 2.6 Stage 07 — Object Field and Pointer Relationship Model

**Classification: STRONGLY SUPPORTED** — all field accesses verified by Capstone + Manual + REA. Phase 2.5's "pointer-indirect" claim is withdrawn; all accesses are direct object-field accesses via LEA.

Cross-reference: `03_INDEPENDENT_X86_INSTRUCTION_DECODING_AUDIT.md`, `04_FUN_004731E0_CORRECTED_INSTRUCTION_AND_SEMANTICS.md`, `05_FUN_00473210_POINTER_INDIRECTION_ANALYSIS.md`, `06_FUN_00489750_COMPLETE_HELPER_ANALYSIS.md`.

---

## 1. Verified Object Field Layout (ObjectCandidate)

| Offset | Width | Name | Type | Access pattern | Atomic? | Writers | Readers | Confidence | Likely role |
|--------|-------|------|------|----------------|---------|---------|---------|------------|-------------|
| `0x00` | 4 | vptr | vtable pointer | `MOV [EDI], imm32` (ctor ×3); `MOV EAX,[EDI]` (dispatch) | No | Ctor (3×) | `FUN_0044F3F0` | PROVEN | Primary vtable pointer |
| `0x04` | 4 | field_0x04 | pointer | — | No | Ctor | None confirmed | VERIFIED | Subobject pointer (per Phase 2.4) |
| `0x08` | 4 | field_0x08 | CRITICAL_SECTION | `LEA ECX,[ESI+0x08]` → push → `DeleteCriticalSection` | N/A (sync obj) | Ctor | `FUN_00489750` | STRONGLY SUPPORTED | Synchronization critical section |
| `0x0C`–`0x4C4` | — | zeroing region | — | Zeroing loop | — | Ctor | — | CONFIRMED | Zeroed during construction |
| `0x20` | 4 | field_0x20 | pointer (release latch) | `LEA EDX,[EDI+0x20]` → `LOCK XADD [EDX],0`; `LEA ECX,[ESI+0x20]` → `XCHG [ECX],0` | YES | Release (XADD read), Teardown (XCHG=0) | Release (TEST old) | STRONGLY SUPPORTED | Non-NULL=alive, NULL=released |
| `0x24` | 4 | field_0x24 | DWORD flag | `LEA ECX,[ESI+0x24]` → `XCHG [ECX],1` | YES | Teardown (XCHG=1) | None confirmed | STRONGLY SUPPORTED | Torn-down flag (set to 1) |
| `0x28` | 4 | field_0x28 | state | `CMP [EDI+0x28], 5` | No | Unknown (17 claimed by P2.4) | Dispatch guard | HYPOTHESIS | State (compared to 5) |
| `0x2C` | 4 | field_0x2C | flag | `CMP [EDI+0x2C], 0` | No | Unknown (7 claimed by P2.4) | Dispatch guard | HYPOTHESIS | Handle/flag (compared to 0) |
| `0x30` | 4 | field_0x30 | call counter | `INC [EDI+0x30]` | No | `FUN_0044F3F0`; init-to-0 by others | None confirmed | STRONGLY SUPPORTED | Call counter |
| `0x5C40` | — | init extent | — | — | — | Ctor | — | VERIFIED | Last initialized offset |

---

## 2. Direct vs. Indirect Access — All Direct

Phase 2.5 Report 05 incorrectly claimed `FUN_00473210` used pointer-indirect access (`MOV ECX,[ESI+0x20]` then `XCHG [ECX],EDX`). The verified instructions are all **direct field accesses via LEA**:

| Instruction | VA | What it loads | Access type |
|-------------|-----|---------------|-------------|
| `LEA EDX, [EDI+0x20]` | `0x4731ED` | Address `&this->field_0x20` | Direct (address-of) |
| `LOCK XADD [EDX], ESI` | `0x4731F2` | DWORD at `this->field_0x20` | Direct (atomic) |
| `LEA ECX, [ESI+0x20]` | `0x47321D` | Address `&this->field_0x20` | Direct (address-of) |
| `XCHG [ECX], EDX` | `0x473226` | DWORD at `this->field_0x20` | Direct (atomic exchange) |
| `LEA ECX, [ESI+0x24]` | `0x47322D` | Address `&this->field_0x24` | Direct (address-of) |
| `XCHG [ECX], EDX` | `0x473230` | DWORD at `this->field_0x24` | Direct (atomic exchange) |

**There is no pointer indirection.** `LEA` computes an address; it does not dereference. `ECX` after `LEA ECX,[ESI+0x20]` equals `ESI + 0x20` (the field address), not the value stored at that field.

---

## 3. Pointer Relationship Graph

```
ObjectCandidate (base = `this` = ECX/EDI/ESI depending on function)
│
├── +0x00  vptr  → .rdata vtable (0x51FFB4 / 0x51E570 / 0x51E4F0)
│               [written by ctor 3×; read by dispatch FUN_0044F3F0]
│
├── +0x04  field_0x04 (subobject pointer — unconfirmed reader)
│
├── +0x08  field_0x08 = CRITICAL_SECTION
│           [destroyed by DeleteCriticalSection via FUN_00489750]
│           [helper called with &this->field_0x08]
│
├── +0x20  field_0x20 = pointer (release latch)
│           [READ by Release: LOCK XADD(...,0) → old value in ESI]
│           [WRITTEN by Teardown: XCHG(...,0) → set to NULL]
│           [Non-NULL = alive; NULL = released]
│
├── +0x24  field_0x24 = DWORD flag (torn-down = 1)
│           [WRITTEN by Teardown: XCHG(...,1) → set to 1]
│
├── +0x28  field_0x28 = state candidate (cmp 5 — dispatch guard)
├── +0x2C  field_0x2C = flag candidate (cmp 0 — dispatch guard)
├── +0x30  field_0x30 = call counter (++ in dispatch)
│
└── +0x5C40  = last initialized field offset
```

**No external control block, no pointer-to-pointer, no indirect field access.** All fields are direct members of `ObjectCandidate`.

---

## 4. Corrected Field Semantics

| Field | Corrected semantics | Evidence | Phase 2.5 error |
|-------|-------------------|----------|-----------------|
| `+0x20` | Release-latch pointer (non-NULL=alive) | `LOCK XADD(...,0)` reads it; `XCHG(...,0)` nulls it; `TEST/JZ` checks NULL | Claimed it was an integer counter exchanged to zero |
| `+0x24` | Torn-down flag (set to 1) | `XCHG(...,1)` sets it | Claimed it was set to 1 (same, but via wrong indirection) |
| `+0x08` | CRITICAL_SECTION (destroyed in teardown) | `DeleteCriticalSection(&this->field_0x08)` | Not previously identified |
| `+0x28` | State (compared to 5) | `CMP [EDI+0x28],5` | Same (hypothesis) |
| `+0x2C` | Flag (compared to 0) | `CMP [EDI+0x2C],0` | Same (hypothesis) |
| `+0x30` | Call counter | `INC [EDI+0x30]` | Same |

---

## 5. Confidence Summary

| Finding | Classification |
|---------|---------------|
| All field accesses are direct (via LEA), not pointer-indirect | PROVEN |
| `+0x08` is CRITICAL_SECTION destroyed by `DeleteCriticalSection` | STRONGLY SUPPORTED |
| `+0x20` is release-latch pointer | STRONGLY SUPPORTED |
| `+0x24` is torn-down flag | STRONGLY SUPPORTED |
| `+0x28`/`+0x2C` state/flag fields | HYPOTHESIS |
| `+0x30` call counter | STRONGLY SUPPORTED |
| External control block exists | CONTRADICTED (none found) |
| Pointer-indirect field access exists | CONTRADICTED (withdrawn) |
