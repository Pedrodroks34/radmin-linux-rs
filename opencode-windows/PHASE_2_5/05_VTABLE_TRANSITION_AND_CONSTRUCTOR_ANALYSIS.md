# Phase 2.5 Stage 05 — Vtable Transition and Constructor Analysis

**Classification: PROVEN / HYPOTHESIS** — constructor vptr writes verified by raw bytes; the *meaning* of the three-transition sequence is a hypothesis because the constructor has no identified external caller and the runtime-active vptr is unknown.

Cross-reference: `03_VTABLE_ADDRESS_POINT_CORRECTION.md`, `04_VTABLE_SLOT_TARGET_RESOLUTION.md`, `12_ALLOCATION_AND_FACTORY_CALL_GRAPH.md`, `15_COMPLETE_OBJECT_LIFECYCLE_RECONSTRUCTION.md`.

---

## 1. Verified Vptr Writes in the Constructor

All three writes are `MOV [EDI], imm32` (`C7 07 <imm32 LE>`), with ECX/EDI = `this`. File offsets from PE mapping (`.text`, raw pointer `0x00000400`, RVA = VA − 0x400000).

| VA | Instruction | Raw bytes | Immediate (vptr value) | File offset | Table | Slot of value |
|----|-------------|-----------|------------------------|-------------|-------|---------------|
| `0x0043E1B1` | `MOV [EDI], 0x51FFB4` | `C7 07 B4 FF 51 00` | `0x0051FFB4` | `0x0003D5B3` | Table A | slot 2 |
| `0x0043E4C8` | `MOV [EDI], 0x51E570` | `C7 07 70 E5 51 00` | `0x0051E570` | `0x0003D8CA` | Table B | slot 0 |
| `0x0043E4E8` | `MOV [EDI], 0x51E4F0` | `C7 07 F0 E4 51 00` | `0x0051E4F0` | `0x0003D8EA` | Table C | slot 0 |

Confirmed: the instruction at each VA writes exactly the immediate shown (little-endimmediate stored `B4 FF 51 00` = `0x0051FFB4`, etc.).

---

## 2. All Cross-References to the Vptr Addresses

The three vptr *values* (`0x0051FFB4`, `0x0051E570`, `0x0051E4F0`) appear as immediates only in the three constructor writes above. A search for writes *to* the memory locations holding these values (i.e., stores of these constants) found no other writers — they are constructor-time immediate writes only.

The *addresses* `0x0051FFB4`/`0x0051E570`/`0x0051E4F0` (as data locations in `.rdata`) hold the vtable tables themselves. Cross-references to those table addresses:
- `0x0051FFB4` is read by `FUN_0044F3F0` via `MOV EAX,[EDI]` (loads vptr from object) only when the object's vptr field happens to equal `0x0051FFB4` — not a direct code reference to the address `0x0051FFB4` as data.
- No code references `.rdata` table addresses by absolute immediate except the constructor writes above (which write the table *addresses* into object memory).

No destructor writes to the object's vptr field (`[EDI+0]`) were found in the analyzed destruction path (`FUN_004731E0` → `FUN_00473210` → cleanup → `FUN_004e6cd7` → `FUN_004ec736`). So no destruction-time vptr transition is evidenced.

---

## 3. Constructor Subobject Vtable Writes (two phases)

### Phase 1 (initial subobject vptrs), all `MOV [EDI+off], imm32`:

| VA | Offset | Value | Subobject | File offset |
|----|--------|-------|-----------|-------------|
| `0x0043E1B7` | +0x38 | `0x520014` | Subobject A | `0x0003D5B7` |
| `0x0043E1BE` | +0x40 | `0x520020` | Subobject B | `0x0003D5BE` |
| `0x0043E1C5` | +0x50 | `0x520034` | Subobject C | `0x0003D5C5` |
| `0x0043E1CC` | +0x98 | `0x520050` | Subobject D | `0x0003D5CC` |
| `0x0043E1D6` | +0x9C | `0x5200E8` | Subobject E | `0x0003D5D6` |

### Phase 2 (subobject vtable overwrites):

| VA | Offset | Value | File offset |
|----|--------|-------|-------------|
| `0x0043E49A` | +0x9C | `0x51E7F8` | `0x0003D89A` |
| `0x0043E4A4` | +0x98 | `0x51E810` | `0x0003D8A4` |
| `0x0043E4AE` | +0x38 | `0x51BE00` | `0x0003D8AE` |
| `0x0043E4B5` | +0x40 | `0x51BE0C` | `0x0003D8B5` |
| `0x0043E4BC` | +0x50 | `0x51BE20` | `0x0003D8BC` |

All five subobject vptrs are written twice, confirming a two-phase construction where subobject vtables are rebound partway through.

---

## 4. Transition Sequence Investigation

Reported sequence: `0x0051FFB4 → 0x0051E570 → 0x0051E4F0`.

Investigated interpretations:

| Interpretation | Evidence for | Evidence against | Verdict |
|----------------|--------------|------------------|---------|
| Constructor-time vptr transitions (same object, progressive initialization) | Three sequential `MOV [EDI], ...` writes in `FUN_0043E1A0`; subobject vptrs also rewritten in phase 2 | Constructor has no identified external caller; cannot confirm the writes execute in this order at runtime or which is "final" | **LIKELY** (constructor-time, same object) |
| Different inheritance subobjects | Each write targets `[EDI+0]` (the *primary* vptr), not different offsets; different offsets would be `[EDI+0x38]` etc. | All three writes hit the same address `[EDI+0]`; not subobjects | **CONTRADICTED** (same primary vptr, rewritten sequentially) |
| Different classes/interfaces | Same `this` (EDI), same field `[EDI+0]` | No evidence of multiple `this` pointers | **UNLIKELY** |
| Initialization stages | Fits sequential writes within one constructor | — | **LIKELY** |
| Destruction-time transitions | No writes to `[EDI+0]` found in destruction path | — | **CONTRADICTED** |
| Incorrect interpretation of unrelated writes | Raw bytes confirm all three writes are real `MOV [EDI], imm32` | — | **CONTRADICTED** (writes are real) |

**Best-supported interpretation:** Constructor-time primary-vptr transitions on a single object, most likely representing initialization stages (base class → intermediate → most-derived class), consistent with the subobject vptrs also being rewritten in a second phase. The three values correspond to Table A (initial), Table B (intermediate), Table C (final).

**Confidence:** LIKELY — the writes are PROVEN, but the semantic "stage" interpretation cannot be confirmed without a runtime trace or an identified caller of the constructor.

---

## 5. Constructor Call Chain and Reachability

| Function | VA | Callers | Caller type |
|----------|-----|---------|-------------|
| `FUN_0043E1A0` (primary ctor) | `0x0043E1A0` | `FUN_0043ECF0` only | Direct |
| `FUN_0043ECF0` (ctor wrapper) | `0x0043ECF0` | 5 adjustment thunks | Direct |
| Thunk `0x0043E85E` | | none | — |
| Thunk `0x0043E866` | | none | — |
| Thunk `0x0043E86E` | | none | — |
| Thunk `0x0043E876` | | none | — |
| Thunk `0x0043E881` | | none | — |

The entire construction chain has **no identified external caller**. The 5 adjustment thunks adjust `this` by −0x38/−0x40/−0x50/−0x98/−0x9C then `JMP FUN_0043ECF0`, indicating multiple-inheritance subobject construction entry points — but nothing calls the thunks.

**Implication:** The constructor (and therefore the vptr transitions) is statically unreachable from any known entry point. The runtime trigger for construction is UNKNOWN. This blocks determining which vptr is active when `FUN_0044F3F0` runs.

---

## 6. Alternative Explanations Considered and Rejected

1. **"Three different objects"** — Rejected: all three writes use the same `EDI` (`this`) and the same field `[EDI+0]`. One object, sequential vptr rewrites.
2. **"The writes are dead code / never execute"** — Cannot be rejected or confirmed statically; the constructor is unreachable from known callers, so whether it ever runs is UNKNOWN.
3. **"vptr transitions happen during destruction"** — Rejected: no `[EDI+0]` writes in the destruction path (`FUN_004731E0`/`FUN_00473210`/cleanup/`FUN_004e6cd7`).
4. **"Table A base `0x0051FFAC` is the real vptr"** — Rejected: constructor never writes `0x0051FFAC`; it writes `0x0051FFB4`. (Corrected in Report 03.)

---

## 7. Confidence

| Question | Classification | Basis |
|----------|---------------|-------|
| Three constructor vptr writes exist | PROVEN | Raw bytes at 3 addresses |
| Values written: 0x51FFB4, 0x51E570, 0x51E4F0 | PROVEN | Immediate operands decoded |
| Sequence is constructor-time (not destruction) | PROVEN | Writes in `FUN_0043E1A0`; none in destruction path |
| Same object / same primary vptr field `[EDI+0]` | PROVEN | All three write `[EDI+0]` |
| Interpretation = progressive initialization stages | LIKELY | Fits evidence; no runtime confirmation |
| Which vptr is active at `FUN_0044F3F0` runtime | UNKNOWN | Constructor unreachable; no runtime trace |
| Subobject vptrs rewritten in phase 2 | PROVEN | 5 overwrite writes verified |
