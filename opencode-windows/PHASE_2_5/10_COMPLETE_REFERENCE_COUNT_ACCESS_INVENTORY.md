# Phase 2.5 Stage 10 — Complete Reference-Count Access Inventory

**Classification: STRONGLY SUPPORTED (partial)** — all accesses verified by raw-bytes disassembly are catalogued below. This is a **complete inventory of accesses found in the analyzed functions**, but not a whole-program exhaustive search (unanalyzed sub-initializers and unreferenced code may contain additional accesses). The search methodology is documented so it is reproducible.

Cross-reference: `08_FUN_00473210_COMPLETE_ANALYSIS.md`, `09_FUN_004731E0_AND_REFERENCE_COUNT_PAIRING.md`, `11_OBJECT_FIELD_AND_SUBOBJECT_LAYOUT.md`, `14_DESTRUCTION_AND_DEALLOCATION_ANALYSIS.md`.

---

## 1. Search Methodology (reproducible)

Every access below was located by:
1. Disassembling the candidate function at its verified VA (file offset via PE section table).
2. Decoding instruction bytes to confirm the memory operand (`[reg+disp32]`/`[reg+disp8]`), width, prefix (`LOCK`), and operation (`XCHG`, `INC`, `CMP`, `MOV`).
3. Mapping the register to an object base via `__thiscall`/`__fastcall` convention (ECX/EDX/EDI/ESI = `this`).

Reproduction: disassemble each function VA listed; confirm the instruction bytes match; the object expression is the register used as `this` at that call site. Normalize object expressions: `[EDI+0x20]` and `[ESI+0x20]` refer to the same logical field **only if** EDI and ESI both hold the same primary object pointer at that program point (verified in `FUN_004731E0`→`FUN_00473210` where EDI==ESI==this).

Whole-program binary search for `0x20` displacements was not performed (no instruction-pattern search tool available in the static environment); the inventory is therefore complete **within analyzed functions** and marked accordingly.

---

## 2. Complete Access Inventory

| # | VA | Function | Instruction | Object expression | Field offset | Operation | Width | Atomic? | Interpretation |
|---|-----|----------|-------------|-------------------|--------------|-----------|-------|---------|----------------|
| A1 | `0x004731ED` | `FUN_004731E0` (Release) | `LEA EDX, [EDI+0x20]` | EDI = `this` | 0x20 | Address-of | 4 | — | Compute address of field 0x20 |
| A2 | `0x004731F2` | `FUN_004731E0` (Release) | `LOCK XCHG [EDX], ESI` | `[EDI+0x20]` | 0x20 | Atomic exchange with 0 | 4 | **YES** (XCHG mem is implicitly LOCKed) | Release: `InterlockedExchange(&obj->f0x20, 0)`; old value → ESI |
| A3 | `0x004731F5` | `FUN_004731E0` (Release) | `TEST ESI, ESI` | ESI = old f0x20 | 0x20 | Test (read) | 4 | — | Branch: if old==0 skip teardown |
| A4 | `0x0047321D` | `FUN_00473210` (teardown) | `MOV ECX, [ESI+0x20]` | ESI = `this` | 0x20 | Read (for XCHG target addr) | 4 | — | Load address of f0x20 into ECX |
| A5 | `0x00473226` | `FUN_00473210` (teardown) | `XCHG [ECX], EDX` | `[[ESI+0x20]]` → `[this+0x20]` | 0x20 | Atomic exchange with 0 | 4 | **YES** (XCHG mem implicitly LOCKed) | `InterlockedExchange(&obj->f0x20, 0)`; old → EDX (overwritten) |
| A6 | `0x0044F4EE` | `FUN_0044F3F0` (dispatch) | `CMP [EDI+0x28], 5` | EDI = `this` | 0x28 | Compare (read) | 4 | — | Guard: field_0x28 == 5 |
| A7 | `0x0044F4F4` | `FUN_0044F3F0` (dispatch) | `CMP [EDI+0x2C], 0` | EDI = `this` | 0x2C | Compare (read) | 4 | — | Guard: field_0x2C != 0 |
| A8 | `0x0044F4FE` | `FUN_0044F3F0` (dispatch) | `INC [EDI+0x30]` | EDI = `this` | 0x30 | Increment | 4 | No (plain INC, not LOCK) | Call counter `field_0x30++` |
| A9 | `0x00473228`–`0x00473230` | `FUN_00473210` | `MOV EDX,1; MOV ECX,[ESI+0x24]; XCHG [ECX],EDX` | `this+0x24` | 0x24 | Atomic exchange with 1 | 4 | **YES** | Set f0x24 = 1 (teardown flag) |

---

## 3. Accesses by Field Offset

### field_0x20 (reference-count candidate)
- **Writes:** A2 (`LOCK XCHG ... = 0` in Release), A5 (`XCHG ... = 0` in teardown). Both set to 0 atomically. **No increment write found.**
- **Reads:** A1 (address computation), A3 (old value test), A4 (address computation).
- **Atomic:** Yes (both writes are `XCHG` with memory operand = implicitly LOCKed on x86).
- **Initializer:** NOT found in constructor. Initial value UNKNOWN.
- **Interpretation:** Strongly supported as the reference counter / release latch, but zeroed (never incremented) in analyzed code → full refcount semantics unproven.

### field_0x28 (state candidate)
- **Reads:** A6 (`CMP [EDI+0x28], 5` in `FUN_0044F3F0`).
- **Writes:** None found in analyzed functions. Phase 2.4 reported 17 writers across 15 functions but none in the constructor.
- **Initial value:** UNKNOWN.
- **Interpretation:** State field compared to 5 (guard for indirect dispatch). Semantic unknown.

### field_0x2C (flag/handle candidate)
- **Reads:** A7 (`CMP [EDI+0x2C], 0` in `FUN_0044F3F0`).
- **Writes:** None found in analyzed functions.
- **Initial value:** UNKNOWN.
- **Interpretation:** Handle/flag compared to 0 (guard). Semantic unknown.

### field_0x30 (call counter candidate)
- **Writes:** A8 (`INC [EDI+0x30]` in `FUN_0044F3F0`).
- **Initialization:** Set to 0 by `FUN_00410E80` (VA `0x410EBD`) and `FUN_00410F60` (VA `0x410F9D`) per Phase 2.4 report `06` (not independently re-disassembled in this phase — inherited as STRONGLY SUPPORTED from Phase 2.4).
- **Reads:** None confirmed (incremented but never read for branching in `FUN_0044F3F0`).
- **Atomic:** No (plain `INC`, not `LOCK INC`).
- **Interpretation:** Call counter; non-atomic increment suggests single-threaded access or relaxed semantics.

### field_0x24 (teardown flag candidate)
- **Writes:** A9 (`XCHG [this+0x24], 1` in teardown).
- **Reads:** None confirmed.
- **Atomic:** Yes.
- **Interpretation:** Set to 1 during teardown; likely a destroyed/in-teardown flag.

---

## 4. Atomic Instruction Summary

| VA | Function | Instruction | Field | Atomicity basis |
|----|----------|-------------|-------|-----------------|
| `0x004731F2` | `FUN_004731E0` | `F0 0F C1 32` = `LOCK XCHG [EDX],ESI` | 0x20 | Explicit `LOCK` + XCHG-with-memory |
| `0x00473226` | `FUN_00473210` | `87 11` = `XCHG [ECX],EDX` (ECX=*[ESI+0x20]) | 0x20 | XCHG with memory operand is **implicitly LOCKed** on x86 |
| `0x00473230` | `FUN_00473210` | `87 11` = `XCHG [ECX],EDX` (ECX=*[ESI+0x24]) | 0x24 | XCHG with memory operand is implicitly LOCKed |

No `LOCK INC`, `LOCK DEC`, `LOCK XADD`, `CMPXCHG`, or `XCHG` (register-register) found. `LOCK XCHG [mem],0` on x86 has full-sequential-consistency acquire+release semantics (strongest).

---

## 5. AddRef / Release Pairing Determination

| Question | Answer | Evidence |
|----------|--------|----------|
| Do AddRef and Release operate on the same counter? | **Cannot confirm** | Release confirmed on `obj+0x20`. AddRef not found. No increment of `obj+0x20` anywhere in analyzed code. |
| Is there an AddRef function? | **NOT FOUND** | Searched analyzed functions; none increments `obj+0x20`. May be inlined or in unanalyzed sub-initializers. |
| Same counter for inc and dec? | **N/A (no inc found)** | Only `obj+0x20` decrement-side (exchange-to-zero) confirmed. |

---

## 6. Counter-Semantics Hypotheses

| Hypothesis | Support | Gap |
|------------|---------|-----|
| Strong reference count (`obj+0x20`) | Atomic access; teardown on zero | **No increment/AddRef found** — count never rises, so not multi-owner |
| Single-release latch (0→nonzero at create, taken to 0 by Release) | Fits exchange-to-zero + teardown-if-nonzero | Initial write to nonzero not found in constructor |
| Internal lifetime / usage count | Fits atomic + teardown pattern | Missing increment |
| Unrelated state field (coincidental atomic) | Possible but unlikely given teardown-on-zero | Atomic ops strongly suggest lifetime significance |

**Conclusion:** `obj+0x20` is the strongest counter candidate (PROVEN location and atomic access), but its exact semantic (strong refcount vs. latch vs. usage count) is **UNRESOLVED** because no increment path was found. Competing hypotheses documented; none can be eliminated statically.

---

## 7. Limitations / Not Exhaustively Searched

- Whole-program instruction-pattern search (e.g., all `lock xchg` / `add [reg+0x20]`) was not performed — no static pattern-search tool available in this environment. Unanalyzed sub-initializers (`FUN_0047A8A0`, `FUN_0043E500`, `FUN_00403540`, `FUN_004728E0`, `FUN_00483750`, `FUN_0043E680`, `FUN_0047BB20`, `FUN_00475B70`, `FUN_00479240`, `FUN_004E70A5`) may contain additional `obj+0x20`/`obj+0x28`/`obj+0x2C`/`obj+0x30` accesses.
- Other offsets (e.g., the hypothesized `0x1E28–0x1E50` refcount region from Phase 2.4) were not accessed in any analyzed function and remain UNVERIFIED.
