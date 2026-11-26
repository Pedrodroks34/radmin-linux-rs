# Phase 2.6 Stage 08 — Complete Atomic Operation Inventory

**Classification: STRONGLY SUPPORTED** — whole-program scan for atomic instructions completed; the critical `LOCK XADD` at `0x004731F2` verified by Capstone + Manual + REA. No `LOCK XCHG` exists at `0x004731F2` (Phase 2.5 claim withdrawn).

Cross-reference: `03_INDEPENDENT_X86_INSTRUCTION_DECODING_AUDIT.md`, `04_FUN_004731E0_CORRECTED_INSTRUCTION_AND_SEMANTICS.md`, `05_FUN_00473210_POINTER_INDIRECTION_ANALYSIS.md`.

---

## 1. Scan Methodology

Scanned the entire `.text` section (VA `0x00401000`–`0x005184EF`, file offset `0x00000400`–`0x00011BA0`) for atomic instruction patterns:

| Pattern | Instruction | Search result |
|---------|-------------|---------------|
| `F0 0F C1` | `LOCK XADD r/m32, r32` | Found (many) |
| `F0 0F C0` | `LOCK XADD r/m8, r8` | Not found |
| `F0 87` | `LOCK XCHG r/m32, r32` | Not found (XCHG-mem is implicitly locked) |
| `0F C1` (no LOCK) | `XADD r/m32, r32` | Found (many) |
| `0F C0` (no LOCK) | `XADD r/m8, r8` | Found 1 (`0x4FC8BE`) |
| `0F B0` | `CMPXCHG r/m8, r8` | Not found |
| `0F B1` | `CMPXCHG r/m32, r32` | Found (many) |
| `F0 FF /0` | `LOCK INC r/m32` | Found 2 (`0x500042`, `0x507D8F`) |
| `F0 FE /0` | `LOCK INC r/m8` | Not found |

Total raw pattern matches: 6295 (includes adjacent overlapping matches for `F0 0F C1` / `0F C1` pairs; unique atomic sites ~3100).

**No `LOCK XCHG` instruction exists anywhere in `.text`.** XCHG-with-memory instructions (`87 /r`) are implicitly locked on x86 and appear without a `F0` prefix.

---

## 2. Atomic Operations in the Target Object Path

Only the instructions in the object's release/teardown path are relevant to our analysis:

| VA | Instruction | Operand analysis | Function | Role |
|-----|-------------|------------------|----------|------|
| `0x004731F2` | `LOCK XADD [EDX], ESI` | `EDX = &this->field_0x20`, `ESI = 0` | `FUN_004731E0` (Release) | **Atomic READ (fetch-add-zero) of `this+0x20`. Field UNCHANGED. ESI = old pointer.** |
| `0x00473226` | `XCHG [ECX], EDX` | `ECX = &this->field_0x20`, `EDX = 0` | `FUN_00473210` (Teardown) | Atomic exchange: `this->field_0x20 = 0` (NULL the pointer) |
| `0x00473230` | `XCHG [ECX], EDX` | `ECX = &this->field_0x24`, `EDX = 1` | `FUN_00473210` (Teardown) | Atomic exchange: `this->field_0x24 = 1` (set torn-down flag) |

### Key observation: `LOCK XADD [EDX], ESI` with ESI = 0

`XADD(dest, src)` semantics: `temp = dest; dest = dest + src; src = temp.`

With `src = 0`: `dest = dest` (unchanged), `src = old dest.`

This is an **atomic fetch** (read-with-memory-barrier), NOT a modification. The field at `this+0x20` is read but not written by `FUN_004731E0`.

The actual modification of `this+0x20` (setting it to 0) happens in `FUN_00473210` via `XCHG [&this->field_0x20], 0`.

---

## 3. Other Atomic Sites (not in object path)

Hundreds of `LOCK XADD [EDI+4], ...` and `CMPXCHG` sites exist throughout the binary (mostly `0x4Cxxxx`–`0x517xxx` range), belonging to other objects/libraries (likely ATL or a custom refcount implementation). None of these access `this+0x20` of `ObjectCandidate`. Examples:

| VA | Instruction | Note |
|-----|-------------|------|
| `0x4C81E2` | `LOCK XADD [ECX+4], ...` | Other object's field_0x04 |
| `0x4DD7EA` | `LOCK XADD [0x5A7420], ...` | Global atomic variable |
| `0x5172E8` | `LOCK XADD [0x59A8D4], ...` | Global atomic variable |
| `0x500042` | `LOCK INC [EAX]` | Locked increment |

None of these are part of the `ObjectCandidate` release/teardown path.

---

## 4. XCHG-with-Memory (Implicitly Locked)

XCHG with a memory operand is implicitly LOCKed on x86 (no `F0` prefix needed). In the object path:

| VA | Instruction | Effective address |
|-----|-------------|-------------------|
| `0x00473226` | `XCHG [ECX], EDX` where ECX=`&this->field_0x20` | `this->field_0x20` |
| `0x00473230` | `XCHG [ECX], EDX` where ECX=`&this->field_0x24` | `this->field_0x24` |

Both are full atomic exchanges (acquire+release semantics).

---

## 5. Atomic Field Summary for ObjectCandidate

| Field | Offset | Atomic operations | Operations |
|-------|--------|-------------------|------------|
| `field_0x20` | `0x20` | `LOCK XADD(...,0)` (read), `XCHG(...,0)` (write) | Release reads; Teardown nulls |
| `field_0x24` | `0x24` | `XCHG(...,1)` (write) | Teardown sets to 1 |
| `field_0x30` | `0x30` | `INC` (NOT locked) — plain increment | Dispatch increments; non-atomic |

**`field_0x30` uses a plain (non-locked) `INC`**, suggesting single-threaded access or relaxed semantics for the call counter. Only `field_0x20` and `field_0x24` use atomic operations.

---

## 6. No `LOCK XCHG` Anywhere

Critically, **no `LOCK XCHG` instruction exists in the entire `.text` section.** Phase 2.5's claim that `0x4731F2` was `LOCK XCHG [EDX], ESI` is impossible — the opcode `0F C1` is XADD, and `0F 87` would be XCHG. The bytes `F0 0F C1 32` unambiguously decode as `LOCK XADD [EDX], ESI`.

---

## 7. Confidence Summary

| Finding | Classification |
|---------|---------------|
| Whole-program atomic scan completed | PROVEN |
| `LOCK XADD [EDX], ESI` at `0x4731F2` (ESI=0, atomic read) | PROVEN |
| `XCHG [&this->field_0x20], 0` at `0x473226` | PROVEN |
| `XCHG [&this->field_0x24], 1` at `0x473230` | PROVEN |
| No `LOCK XCHG` anywhere in `.text` | PROVEN |
| `field_0x30` uses non-locked `INC` | PROVEN |
| Other atomic sites belong to unrelated objects | STRONGLY SUPPORTED |
