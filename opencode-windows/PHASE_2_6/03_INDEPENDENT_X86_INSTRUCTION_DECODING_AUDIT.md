# Phase 2.6 Stage 03 — Independent X86 Instruction Decoding Audit

**Classification: PROVEN** — every critical instruction decoded by two independent methods (Capstone 5.0.7 and a manual opcode decoder), with results cross-checked against REA/Ghidra raw-byte reads. Phase 2.5's `LOCK XCHG` interpretation is **withdrawn**; the actual instruction is `LOCK XADD`.

---

## 1. Decoder Methods Used

| Method | Tool | Version | Role |
|--------|------|---------|------|
| Decoder 1 | Capstone | 5.0.7 | Primary independent x86 decoder |
| Decoder 2 | Manual opcode decoder | Custom | Cross-verification of opcode bytes |
| Ground truth | REA/Ghidra 12.2 `read_bytes` | 12.2 | Raw byte source (verified SHA-256 `0e2e6ea...`) |

All reads from REA `read_bytes` return `confidence: "observed"`, `authority: "shipped-artifact"`, from the verified target `RvControlSvc_Installed_0E2E6EAA.exe`.

---

## 2. Critical Single-Instruction Audit

Each instruction below was decoded at its exact VA by both decoders. "MATCH" means both decoders produce the same mnemonic (normalized). Raw bytes are from REA `read_bytes`.

### 2.1 FUN_004731E0 — The XADD vs XCHG Question

| VA | Raw bytes | Capstone (Decoder 1) | Manual (Decoder 2) | Match? | Correct interpretation |
|----|-----------|----------------------|--------------------|--------|------------------------|
| `0x004731E0` | `53` | `push ebx` | `push ebx` | MATCH | Prologue |
| `0x004731E1` | `56` | `push esi` | `push esi` | MATCH | Prologue |
| `0x004731E2` | `57` | `push edi` | `push edi` | MATCH | Prologue |
| `0x004731E3` | `8b f9` | `mov edi, ecx` | `mov edi, ecx` | MATCH | `this = ecx` |
| `0x004731E5` | `ff 15 80 92 51 00` | `call dword ptr [0x519280]` | `call [0x519280]` | MATCH | `GetLastError()` |
| `0x004731EB` | `8b d8` | `mov ebx, eax` | `mov ebx, eax` | MATCH | Save error code |
| `0x004731ED` | `8d 57 20` | `lea edx, [edi + 0x20]` | `lea edx, [edi + 0x20]` | MATCH | `edx = &this->field_0x20` |
| `0x004731F0` | `33 f6` | `xor esi, esi` | `xor esi, esi` | MATCH | `esi = 0` |
| **`0x004731F2`** | **`f0 0f c1 32`** | **`lock xadd dword ptr [edx], esi`** | **`lock xadd [edx], esi`** | **MATCH** | **LOCK XADD [&this->field_0x20], 0** |
| `0x004731F6` | `85 f6` | `test esi, esi` | `test esi, esi` | MATCH | Test old value |
| `0x004731F8` | `74 07` | `jz 0x00473201` | `jz 0x00473201` | MATCH | Skip if old == 0 |
| `0x004731FA` | `8b cf` | `mov ecx, edi` | `mov ecx, edi` | MATCH | `ecx = this` |
| `0x004731FC` | `e8 0f 00 00 00` | `call 0x00473210` | `call 0x00473210` | MATCH | Call teardown |
| `0x00473201` | `53` | `push ebx` | `push ebx` | MATCH | Restore error |
| `0x00473202` | `ff 15 60 92 51 00` | `call dword ptr [0x519260]` | `call [0x519260]` | MATCH | `SetLastError()` |
| `0x00473208` | `5f` | `pop edi` | `pop edi` | MATCH | Epilogue |
| `0x00473209` | `5e` | `pop esi` | `pop esi` | MATCH | Epilogue |
| `0x0047320A` | `5b` | `pop ebx` | `pop ebx` | MATCH | Epilogue |
| `0x0047320B` | `c3` | `ret` | `ret` | MATCH | Return |

### 2.2 FUN_00473210 — Pointer Indirection Question

| VA | Raw bytes | Capstone (Decoder 1) | Manual (Decoder 2) | Match? | Correct interpretation |
|----|-----------|----------------------|--------------------|--------|------------------------|
| `0x00473210` | `56` | `push esi` | `push esi` | MATCH | Prologue |
| `0x00473211` | `8b f1` | `mov esi, ecx` | `mov esi, ecx` | MATCH | `this = ecx` |
| `0x00473213` | `8d 4e 08` | `lea ecx, [esi + 8]` | `lea ecx, [esi + 8]` | MATCH | `ecx = &this->field_0x08` |
| `0x00473216` | `e8 35 65 01 00` | `call 0x00489750` | `call 0x00489750` | MATCH | Call helper |
| `0x0047321B` | `f7 d8` | `neg eax` | `neg eax` | MATCH | Negate helper result |
| **`0x0047321D`** | **`8d 4e 20`** | **`lea ecx, [esi + 0x20]`** | **`lea ecx, [esi + 0x20]`** | **MATCH** | **`ecx = &this->field_0x20` (ADDRESS, not value)** |
| `0x00473220` | `1b c0` | `sbb eax, eax` | `sbb eax, eax` | MATCH | Sign mask from carry |
| `0x00473222` | `33 d2` | `xor edx, edx` | `xor edx, edx` | MATCH | `edx = 0` |
| `0x00473224` | `f7 d8` | `neg eax` | `neg eax` | MATCH | Mask: 0 or -1 |
| **`0x00473226`** | **`87 11`** | **`xchg dword ptr [ecx], edx`** | **`xchg [ecx], edx`** | **MATCH** | **`*(&this->field_0x20) = 0` (atomic XCHG, edx = old)** |
| `0x00473228` | `ba 01 00 00 00` | `mov edx, 1` | `mov edx, 1` | MATCH | `edx = 1` |
| **`0x0047322D`** | **`8d 4e 24`** | **`lea ecx, [esi + 0x24]`** | **`lea ecx, [esi + 0x24]`** | **MATCH** | **`ecx = &this->field_0x24` (ADDRESS)** |
| **`0x00473230`** | **`87 11`** | **`xchg dword ptr [ecx], edx`** | **`xchg [ecx], edx`** | **MATCH** | **`*(&this->field_0x24) = 1` (atomic XCHG)** |
| `0x00473232` | `5e` | `pop esi` | `pop esi` | MATCH | Epilogue |
| `0x00473233` | `c3` | `ret` | `ret` | MATCH | Return |

**Key correction:** Phase 2.5 Report 08 claimed `MOV ECX, [ESI+0x20]` (loading the VALUE at field_0x20). The actual instruction is `LEA ECX, [ESI+0x20]` (loading the ADDRESS of field_0x20). This means `XCHG [ECX], EDX` operates on the field directly — but it's an atomic exchange that **sets field_0x20 to 0** (not a counter decrement). `field_0x24` is set to 1.

---

## 3. The Decoded `F0 0F C1 32` at `0x004731F2`

| Property | Value |
|----------|-------|
| Raw bytes | `F0 0F C1 32` |
| Opcode `0F C1 /r` | `XADD r/m32, r32` (Intel SDM) |
| Prefix `F0` | LOCK (atomic) |
| ModR/M `0x32` | mod=00, reg=011 (ESI), r/m=010 ([EDX]) |
| Decoded | `LOCK XADD [EDX], ESI` |
| Phase 2.5 claim | `LOCK XCHG [EDX], ESI` |
| Phase 2.5 claim status | **CONTRADICTED — WITHDRAWN** |

### XADD semantics (Intel SDM)

`XADD dest, src`:
```
temp = dest
dest = dest + src
src = temp   (returns old dest)
```

With `src = ESI = 0`:
- `dest = dest + 0 = dest` — **the memory location is UNCHANGED**
- `ESI = old dest` — ESI receives the previous value

So `LOCK XADD [&this->field_0x20], 0`:
1. Atomically reads the DWORD at `this+0x20` into ESI
2. Writes the same value back (no change)
3. Returns the old value in ESI

**This is an atomic READ (fetch-add-zero), NOT an exchange-to-zero.** The field at `this+0x20` is NOT modified by this instruction.

The subsequent `TEST ESI, ESI` checks whether the old value was zero. If non-zero, teardown (`FUN_00473210`) is called.

---

## 4. Decoder Comparison Summary

| Instruction | VA | Decoder 1 (Capstone) | Decoder 2 (Manual) | REA bytes | Agreement | Phase 2.5 correct? |
|-------------|----|---------------------|--------------------|-----------|-----------|-------------------|
| `lock xadd [edx], esi` | `0x4731F2` | `lock xadd dword ptr [edx], esi` | `lock xadd [edx], esi` | `f0 0f c1 32` | YES | **NO — was XCHG** |
| `lea ecx, [esi+0x20]` | `0x47321D` | `lea ecx, [esi + 0x20]` | `lea ecx, [esi + 0x20]` | `8d 4e 20` | YES | **NO — was MOV** |
| `xchg [ecx], edx` | `0x473226` | `xchg dword ptr [ecx], edx` | `xchg [ecx], edx` | `87 11` | YES | YES (mnemonic) |
| `lea ecx, [esi+0x24]` | `0x47322D` | `lea ecx, [esi + 0x24]` | `lea ecx, [esi + 0x24]` | `8d 4e 24` | YES | **NO — was MOV** |
| `xchg [ecx], edx` | `0x473230` | `xchg dword ptr [ecx], edx` | `xchg [ecx], edx` | `87 11` | YES | YES (mnemonic) |
| `cmp [edi+0x28], 5` | `0x44F4EE` | `cmp dword ptr [edi + 0x28], 5` | `cmp [edi + 0x28], 5` | `83 7f 28 05` | YES | YES |
| `call [eax+0x34]` | `0x44F501` | `call dword ptr [eax + 0x34]` | `call [eax + 0x34]` | `ff 50 34` | YES | YES |
| `call [eax+0x58]` | `0x44F50D` | `call dword ptr [eax + 0x58]` | `call [eax + 0x58]` | `ff 50 58` | YES | YES |

**All 37 critical instructions decoded by both methods agree.** No mismatches when starting at correct instruction boundaries.

---

## 5. Corrected `FUN_004731E0` Pseudocode

```c
void __fastcall FUN_004731e0(void *this)
{
    DWORD err;
    void *ptr;

    err = GetLastError();                    // [0x519280]
    ptr = InterlockedExchangeAdd((volatile LONG *)(this + 0x20), 0);
                                             // LOCK XADD [&this->field_0x20], 0
                                             // field UNCHANGED; ptr = old value
    if (ptr != NULL) {
        FUN_00473210(this);                  // teardown
    }
    SetLastError(err);                       // [0x519260]
}
```

**Corrected interpretation:** `this+0x20` holds a **pointer** (not a counter). `LOCK XADD(..., 0)` atomically reads the pointer without modifying it. If the pointer is non-NULL, teardown is invoked. Teardown then sets `this+0x20` to NULL via `XCHG` and sets `this+0x24` to 1 via `XCHG`.

---

## 6. Confidence

| Finding | Classification | Basis |
|---------|---------------|-------|
| `0x4731F2` = `LOCK XADD [EDX], ESI` | PROVEN | Capstone + Manual + REA bytes all agree |
| `0x47321D` = `LEA ECX, [ESI+0x20]` | PROVEN | Capstone + Manual + REA bytes all agree |
| `0x473226` = `XCHG [ECX], EDX` (ECX = &field_0x20) | PROVEN | Capstone + Manual + REA bytes all agree |
| `0x47322D` = `LEA ECX, [ESI+0x24]` | PROVEN | Capstone + Manual + REA bytes all agree |
| `0x473230` = `XCHG [ECX], EDX` (ECX = &field_0x24) | PROVEN | Capstone + Manual + REA bytes all agree |
| Phase 2.5 "LOCK XCHG" claim | CONTRADICTED | Actual opcode `0F C1` = XADD, `87` = XCHG |
| Phase 2.5 "MOV ECX, [ESI+0x20]" claim | CONTRADICTED | Actual opcode `8D` = LEA (address load) |
| `this+0x20` is a pointer (not counter) | STRONGLY SUPPORTED | XADD reads it; XCHG zeroes it |
