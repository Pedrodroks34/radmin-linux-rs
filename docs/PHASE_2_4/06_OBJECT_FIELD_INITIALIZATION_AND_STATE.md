# Phase 2.4 Stage 06 — Object Field Initialization and State

**Classification: PARTIALLY RESOLVED** (writers/readers identified statically; semantic meaning largely hypothesized)

## 1. Field Summary Table

| Offset | Name | Type | Writers | Readers | Confidence | Semantic |
|--------|------|------|---------|---------|------------|----------|
| 0x00 | field_0x00 | Vtable pointer | Constructor (3×) | FUN_0044F3F0 (MOV EAX,[EDI]) | STRONGLY SUPPORTED | vptr |
| 0x04 | field_0x04 | Subobject pointer | Constructor | — | VERIFIED | Subobject ptr |
| 0x0C | field_0x0C | Zeroed then released | Zeroing loop | — | VERIFIED | Zeroed field |
| 0x20 | field_0x20 | Handle-like value | Multiple | — | HYPOTHESIS | Handle/flag |
| 0x28 | field_0x28 | State field | 17 sites, 15 functions | FUN_0044F3F0 (CMP to 5) | HYPOTHESIS | State (compared to 5) |
| 0x2C | field_0x2C | Handle/flag field | 7 sites, 7 functions | FUN_0044F3F0 (CMP to 0) | HYPOTHESIS | Handle/flag (compared to 0) |
| 0x30 | field_0x30 | Call counter | FUN_0044F3F0 (INC), FUN_00410E80, FUN_00410F60 | FUN_0044F3F0 | HYPOTHESIS | Counter (incremented) |
| 0x38 | field_0x38 | Subobject vtable pointer | Constructor | — | STRONGLY SUPPORTED | Subobject A vptr |
| 0x40 | field_0x40 | Subobject vtable pointer | Constructor | — | STRONGLY SUPPORTED | Subobject B vptr |
| 0x50 | field_0x50 | Subobject vtable pointer | Constructor | — | STRONGLY SUPPORTED | Subobject C vptr |
| 0x98 | field_0x98 | Subobject vtable pointer | Constructor + overwrite | — | STRONGLY SUPPORTED | Subobject D vptr |
| 0x9C | field_0x9C | Subobject vtable pointer | Constructor + overwrite | — | STRONGLY SUPPORTED | Subobject E vptr |
| 0x1D38 | field_0x1D38 | Unknown | — | — | UNKNOWN | — |
| 0x1E28–0x1E50 | field_0x1E28–0x1E50 | Candidate refcount | — | — | UNKNOWN | Possible refcount |
| 0x5C40 | field_0x5C40 | Initialization extent | Constructor | — | VERIFIED | Last initialized offset |

## 2. Field_0x28 — State Field

**Guard condition in FUN_0044F3F0:** `CMP [EDI+0x28], 5` at 0x44F4EE

**Writers:** 17 write sites across 15 functions (from Phase 2.3 Report 04)

**Initial value:** UNKNOWN — no writer found in constructor (FUN_0043E1A0)

**Confirmed writes:** field_0x28 is written by many functions but the constructor does not initialize it. The initial value before any write is unknown.

**Confirmed reads:** FUN_0044F3F0 reads field_0x28 and compares to 5.

## 3. Field_0x2C — Handle/Flag Field

**Guard condition in FUN_0044F3F0:** `CMP [EDI+0x2C], 0` at 0x44F4F4

**Writers:** 7 write sites across 7 functions (from Phase 2.3 Report 04)

**Initial value:** UNKNOWN — no writer found in constructor

**Confirmed reads:** FUN_0044F3F0 reads field_0x2C and compares to 0.

## 4. Field_0x30 — Call Counter

**Operation in FUN_0044F3F0:** `INC [EDI+0x30]` at 0x44F4FE

**Writers:**
- FUN_0044F3F0 (increment, 0x44F4FE)
- FUN_00410E80 (initialize to 0, 0x410EBD)
- FUN_00410F60 (initialize to 0, 0x410F9D)

**Initial value:** 0 (set by FUN_00410E80 or FUN_00410F60)

**Confirmed reads:** FUN_0044F3F0 increments field_0x30 but does not appear to read its value for branching.

## 5. Field_0x214 — NOT FOUND

**Search result:** No `MOV [EDI+0x214]` or equivalent write found anywhere in the binary. Alternative encodings also searched.

**Conclusion:** field_0x214 does not appear to exist in this object, or is never written. The previous claim of a write at 0x42173B was not confirmed.

## 6. Reference Count Candidate (obj + 0x20)

**FUN_004731E0** performs atomic `LOCK()`/`UNLOCK()` read of `obj + 0x20`:

```c
void __fastcall FUN_004731e0(int param_1)
{
  dwErrCode = GetLastError();
  piVar1 = (int *)(param_1 + 0x20);  // refcount at obj + 0x20
  LOCK();
  iVar2 = *piVar1;                   // atomic read
  *piVar1 = *piVar1;                 // no-op write (compiler barrier)
  UNLOCK();
  if (iVar2 != 0) {
    FUN_00473210(param_1);           // decrement and destroy if zero
  }
  SetLastError(dwErrCode);
}
```

**This suggests obj + 0x20 is a reference count**, but:
- The field is at offset 0x20, not 0x1E28–0x1E50 as previously hypothesized
- No AddRef (increment) function has been identified
- FUN_00473210 (decrement/destroy) has not been analyzed

## 7. Subobject Vtable Pointers

| Offset | Initial Value | Overwritten Value | Confidence |
|--------|--------------|-------------------|------------|
| 0x38 | 0x520014 | 0x51BE00 | STRONGLY SUPPORTED |
| 0x40 | 0x520020 | 0x51BE0C | STRONGLY SUPPORTED |
| 0x50 | 0x520034 | 0x51BE20 | STRONGLY SUPPORTED |
| 0x98 | 0x520050 | 0x51E810 | STRONGLY SUPPORTED |
| 0x9C | 0x5200E8 | 0x51E7F8 | STRONGLY SUPPORTED |

All 5 subobject vptrs are written by the constructor and then overwritten during a second construction phase.

## 8. Semantic Naming — RESTRICTED

Per evidence standards, the following names are NOT assigned because evidence does not support them:
- `state` for field_0x28 (only compared to 5, no semantic meaning confirmed)
- `handle` for field_0x2C (only compared to 0, no semantic meaning confirmed)
- `counter` for field_0x30 (incremented, but purpose unknown)
- `session_id` for any field (no evidence)
- `refcount` for obj + 0x20 (atomic access suggests it, but not confirmed)

Neutral names (field_0xXX) are used throughout.

## 9. Confidence Classification

| Question | Classification | Basis |
|----------|---------------|-------|
| Field offsets exist | CONFIRMED | Instruction operands verified |
| field_0x28 compared to 5 | CONFIRMED | Raw bytes at 0x44F4EE |
| field_0x2C compared to 0 | CONFIRMED | Raw bytes at 0x44F4F4 |
| field_0x30 incremented | CONFIRMED | Raw bytes at 0x44F4FE |
| field_0x214 exists | REFUTED | No write found anywhere |
| obj + 0x20 is refcount | STRONGLY SUPPORTED | LOCK/UNLOCK atomic access in FUN_004731E0 |
| field_0x28 initial value | UNKNOWN | No constructor write found |
| field_0x2C initial value | UNKNOWN | No constructor write found |
| field_0x30 initial value | CONFIRMED | 0 (FUN_00410E80/FUN_00410F60) |
| Semantic meaning of any field | HYPOTHESIS | No confirming evidence |