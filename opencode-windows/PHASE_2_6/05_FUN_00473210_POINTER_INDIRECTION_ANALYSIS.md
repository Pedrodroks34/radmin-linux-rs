# Phase 2.6 Stage 05 — FUN_00473210 Pointer Indirection Analysis

**Classification: PROVEN / CONTRADICTED (vs. Phase 2.5)** — `FUN_00473210` uses `LEA` (load address) not `MOV` (load value), then `XCHG` on the loaded address. The operations are direct atomic field writes (`this+0x20 = 0`, `this+0x24 = 1`), NOT pointer-indirect exchanges on pointees. Phase 2.5's "MOV loads a pointer" claim is withdrawn.

Cross-reference: `03_INDEPENDENT_X86_INSTRUCTION_DECODING_AUDIT.md`, `04_FUN_004731E0_CORRECTED_INSTRUCTION_AND_SEMANTICS.md`, `06_FUN_00489750_COMPLETE_HELPER_ANALYSIS.md`.

---

## 1. Complete Disassembly (verified by Capstone + Manual + REA)

VA `0x00473210`, file offset `0x00072610` (`.text`), 36 bytes, `__thiscall` (ECX = `this`).

| VA | Raw bytes | Instruction | Meaning |
|----|-----------|-------------|---------|
| `0x00473210` | `56` | `PUSH ESI` | Prologue |
| `0x00473211` | `8B F1` | `MOV ESI, ECX` | `this = ECX` |
| `0x00473213` | `8D 4E 08` | `LEA ECX, [ESI+0x08]` | `ECX = &this->field_0x08` |
| `0x00473216` | `E8 35 65 01 00` | `CALL 0x00489750` | Call helper with `&this->field_0x08` |
| `0x0047321B` | `F7 D8` | `NEG EAX` | Negate helper return |
| `0x0047321D` | `8D 4E 20` | `LEA ECX, [ESI+0x20]` | **CRITICAL — `ECX = &this->field_0x20` (ADDRESS)** |
| `0x00473220` | `1B C0` | `SBB EAX, EAX` | Sign mask from carry (dead code — result unused) |
| `0x00473222` | `33 D2` | `XOR EDX, EDX` | `EDX = 0` |
| `0x00473224` | `F7 D8` | `NEG EAX` | Mask computation (dead code — result unused) |
| `0x00473226` | `87 11` | `XCHG [ECX], EDX` | **`*(&this->field_0x20) = 0` — atomic, EDX = old** |
| `0x00473228` | `BA 01 00 00 00` | `MOV EDX, 1` | `EDX = 1` |
| `0x0047322D` | `8D 4E 24` | `LEA ECX, [ESI+0x24]` | **CRITICAL — `ECX = &this->field_0x24` (ADDRESS)** |
| `0x00473230` | `87 11` | `XCHG [ECX], EDX` | **`*(&this->field_0x24) = 1` — atomic** |
| `0x00473232` | `5E` | `POP ESI` | Epilogue |
| `0x00473233` | `C3` | `RET` | Return |

All instructions decoded identically by Capstone 5.0.7, manual decoder, and confirmed by REA `read_bytes`.

---

## 2. The Pointer-Indirection Problem — RESOLVED

Phase 2.5 Report 08 claimed:
```asm
MOV ECX, [ESI+0x20]    ; loads the VALUE at field_0x20 into ECX
XCHG [ECX], EDX        ; exchanges memory at the address held in ECX
```

**This is incorrect.** The actual instruction at `0x0047321D` is:

```asm
LEA ECX, [ESI+0x20]    ; loads the ADDRESS &this->field_0x20 into ECX
XCHG [ECX], EDX        ; exchanges DWORD at &this->field_0x20 with EDX
```

| Claim | Phase 2.5 | Actual (verified) | Status |
|-------|-----------|-------------------|--------|
| Opcode at `0x47321D` | `MOV ECX, [ESI+0x20]` (`8B ...`) | `LEA ECX, [ESI+0x20]` (`8D 4E 20`) | **CONTRADICTED** |
| What ECX holds | Value `*(this+0x20)` | Address `&this->field_0x20` | **CONTRADICTED** |
| `XCHG [ECX], EDX` target | `*(*(this+0x20))` (pointer-indirect) | `*(this+0x20)` (direct field) | **CONTRADICTED** |
| `field_0x20` is | A pointer to an atomic | An atomic DWORD field | **CONTRADICTED** |

`LEA` computes an address; it does **not** dereference memory. `ECX` after `LEA ECX, [ESI+0x20]` equals `ESI + 0x20`, i.e., the address of `this->field_0x20`. `XCHG [ECX], EDX` then atomically exchanges the DWORD **at that address** with EDX — a direct field write.

---

## 3. Exact Effective Addresses

| Instruction | VA | Base register | Register origin | Effective address | Actual region |
|-------------|-----|---------------|-----------------|-------------------|---------------|
| `LEA ECX, [ESI+0x08]` | `0x473213` | ESI | `this` (set at `0x473211`) | `&this->field_0x08` | Object field (helper arg) |
| `LEA ECX, [ESI+0x20]` | `0x47321D` | ESI | `this` (unchanged) | `&this->field_0x20` | Object field (zeroed) |
| `XCHG [ECX], EDX` | `0x473226` | ECX | Loaded from `0x47321D` | `this->field_0x20` | Object field (= 0) |
| `LEA ECX, [ESI+0x24]` | `0x47322D` | ESI | `this` (unchanged) | `&this->field_0x24` | Object field (set to 1) |
| `XCHG [ECX], EDX` | `0x473230` | ECX | Loaded from `0x47322D` | `this->field_0x24` | Object field (= 1) |

**Trace of ECX:**
1. `0x473213`: `ECX = &this->field_0x08` → passed to helper `FUN_00489750`
2. `0x47321D`: `ECX = &this->field_0x20` → overwritten, used by `XCHG` at `0x473226`
3. `0x47322D`: `ECX = &this->field_0x24` → overwritten, used by `XCHG` at `0x473230`

**Trace of EDX:**
1. `0x473222`: `EDX = 0` → used by `XCHG` at `0x473226` (sets field_0x20 to 0, receives old value)
2. `0x473228`: `EDX = 1` → used by `XCHG` at `0x473230` (sets field_0x24 to 1)

**Trace of EAX:**
1. `0x473216`: EAX = return from `FUN_00489750`
2. `0x47321B`-`0x473224`: `NEG`/`SBB`/`XOR`/`NEG` computes a sign mask but the result is **never stored or branched on** — dead code (compiler artifact)
3. EAX is not meaningfully returned

---

## 4. Corrected Pseudocode

```c
void __thiscall FUN_00473210(void *this)
{
    int helper_result;
    LONG old_0x20;
    LONG old_0x24;

    // Call helper with address of field_0x08
    helper_result = FUN_00489750(&this->field_0x08);

    // neg/sbb/xor/neg sequence: computes a sign mask from helper_result,
    // but the mask is never stored or used — dead code
    // (result of second NEG is discarded)

    // Atomic exchange: field_0x20 = 0, old value → EDX (then overwritten)
    old_0x20 = InterlockedExchange((volatile LONG *)(this + 0x20), 0);
    // EDX still holds old_0x20 at this point

    // EDX = 1 (overwrites old_0x20)
    // Atomic exchange: field_0x24 = 1
    old_0x24 = InterlockedExchange((volatile LONG *)(this + 0x24), 1);
    // old_0x24 discarded
}
```

---

## 5. Field Semantics

| Field | Offset | Width | Operation in FUN_00473210 | Atomic? | Value written | Role |
|-------|--------|-------|---------------------------|---------|---------------|------|
| `field_0x20` | `0x20` | 4 bytes | `XCHG [&field], 0` | YES (XCHG mem = implicit LOCK) | 0 | Pointer nulled (release latch cleared) |
| `field_0x24` | `0x24` | 4 bytes | `XCHG [&field], 1` | YES (XCHG mem = implicit LOCK) | 1 | Torn-down flag set |

**`field_0x20` is a pointer/DWORD field, not a pointer-to-pointer.** It is:
- Read atomically by `FUN_004731E0` via `LOCK XADD(..., 0)` (fetch-add-zero, unchanged)
- Set to NULL (0) by `FUN_00473210` via `XCHG` (atomic)

**`field_0x24` is a DWORD flag field:**
- Set to 1 by `FUN_00473210` via `XCHG` (atomic)
- No confirmed reader in analyzed code

---

## 6. Dead Code in FUN_00473210

The sequence at `0x47321B`–`0x473224`:
```asm
neg eax        ; EAX = -helper_result, sets CF if helper_result != 0
sbb eax, eax   ; EAX = EAX - EAX - CF = -1 if CF, else 0
xor edx, edx   ; EDX = 0
neg eax        ; EAX = -(-1) = 1 if CF, else -0 = 0; result discarded
```

The final `NEG EAX` result (0 or 1) is **never used** — EDX is immediately overwritten with 0 at `0x473222`, then with 1 at `0x473228`. This is dead code, likely a compiler artifact from an optimized-away conditional. It does not affect program behavior.

---

## 7. Confidence Summary

| Finding | Classification |
|---------|---------------|
| `LEA ECX, [ESI+0x20]` not `MOV` | PROVEN |
| `LEA ECX, [ESI+0x24]` not `MOV` | PROVEN |
| `XCHG [ECX], EDX` operates on direct field `this+0x20` | PROVEN |
| `XCHG [ECX], EDX` operates on direct field `this+0x24` | PROVEN |
| `field_0x20` set to 0 atomically | PROVEN |
| `field_0x24` set to 1 atomically | PROVEN |
| `neg/sbb/xor/neg` is dead code | STRONGLY SUPPORTED |
| `field_0x20` is a pointer (not counter) | STRONGLY SUPPORTED |
| Helper `FUN_00489750` role | UNKNOWN (body analyzed in Report 06) |
