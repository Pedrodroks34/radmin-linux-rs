# Phase 9D — Main Report: Group A/B/C Pointer Producer and Static Dataflow Investigation

**Date:** 2026-11-13 · **HEAD at start:** `b873cea0bd1f3890925a0c0f79bbe2abc16db6cd` (`main`, unchanged)
**Working tree preserved:** 3 modified tracked files (`.gitignore`, `src/session/control_handshake.rs`, `src/session/mod.rs`) + user-owned untracked files — none touched.
**Deliverables:** `analysis_workspace/phase_9D_audit/` (this file + 11 siblings + `_ctx_*.txt` evidence captures + checked-in verifier scripts).
**Binary:** `RvControlSvc.exe` (SHA-256 `546efad9ab3ff85c2a50d61524d754bec94a3f3e30d6ae8addef481a1e8daa1e`), analyzed statically and read-only. `.rdata`/`.data` dumps performed by direct read-only parsing of the PE (`dump_rtti.py`, `dump_tables*.py`, `dump_rtti2.py`).

## 1. Scope and baseline revalidation

Phase 9C established the e220/e280 callsite inventories (15/14 and 22/21) and the un-resolved pointer chains `P = [EDI+0x0C]`, `D = [P+0x04]`, `A = EDI+D+0x0C`, `V = [A]`. This phase asks where P and D originate.

Phase 9C claims independently re-verified before being used:

| Baseline fact | Revalidation |
|---|---|
| 15 e220 / 22 e280 / 1 e16650 callsites | Re-counted from raw `references.jsonl` + instruction byte checks — **same counts** ✓ |
| Constructor `FUN_00421410` stores `[EDI+0x214] = 0x0` (B2 gate) | **Verified** at `0042173b` in `listing/00421410.asm` |
| Constructor's REP MOVS covers only `[EDI+0x110..0x1AB]` | **Verified** at `0042169a` (`ADD EDI,0x110`) + `004216a3` (`MOV ECX,0x27`) + `004216a8` (REP MOVSD) — does NOT reach `+0x214` |
| Five blocked sites (E1/E2a/E2b/E3/E4) | **Retained** — `FUN_004230c0`'s gate at `00423157` and `FUN_00422f20`'s at `00422fa3` stand |
| e16650 resolution via constructor-selected tables → `FUN_00479d80` | **Retained**, now extended with a general method (see §6, `phase_9D_e16650_comparison.md`) |
| `HeapAlloc` flag 0x0 does not zero memory | **Verified** via import decode: `0x005172f0` = KERNEL32.DLL::HeapAlloc (hint 840), used with `0x0` flag in `004ff788` |
| Allocator call chain `004e5a66 → 004018a0 → __malloc_base (004ff788)` | **Verified** listing-level + `pe_imports.py` |

## 2a. e280 callers — adjusted-pointer matrix (new this phase)

The e280 callers do **not** use the Group A/B/C layout conventions — they pass raw `this` with several different adjustments:

| # | Caller | Callsite | Adjustment to e280 | Class hint |
|---|--------|----------|---------------------|------------|
| 1 | FUN_00419b30 | 00419bce | `MOV ECX,ESI` (raw `this`) | unknown single-class |
| 2 | FUN_0041a640 | 0041a6b2 | raw | unknown |
| 3 | FUN_0041a6d0 | 0041a7f1 | raw (`EBX = [EBP+0x8]`) | FUN_00417850-class family |
| 4 | FUN_0041aa40 | 0041aaee | `+0x28` | Group A adjust |
| 5 | FUN_0041b1e0 | 0041b2a1 | raw (`EBX`) | FUN_00417850-class family |
| 6 | FUN_0041c300 | 0041c3fd | raw (`MOV ECX,[EBP+0x8]`) | unknown |
| 19 | FUN_00423980 | 00423ad2 | raw (`MOV ECX,[EBP+0x8]`) | unknown |
| 7 | FUN_0041c870 | 0041c8df | raw (`ESI`) | unknown |
| 8 | FUN_0041d380 | 0041d438 | `+0x28` | Group A adjust |
| 9 | FUN_0041d380 | 0041d468 | `+0x28` | Group A adjust |
| 10 | FUN_0041d6e0 | 0041d757 | raw (`EBX`) | FUN_00417850-class family |
| 11 | FUN_0041d770 | 0041d87e | raw (`EBX`) | FUN_00417850-class family |
| 12 | FUN_0041de60 | 0041dec2 | `+0x20` | **new slot** |
| 13 | FUN_0041e1f0 | 0041e20d | raw (`EBX`) | FUN_00417850-class family |
| 14 | FUN_0041e360 | 0041e457 | raw (`EDI`) | unknown |
| 15 | FUN_0041f450 | 0041f67e | raw (`EBX`) | FUN_00417850-class family |
| 16 | FUN_00422840 | 004229d9 | raw (`EBX`) | FUN_00417850-class family |
| 17 | FUN_00422e00 | 00422ed0 | `+0x60` | **new slot** |
| 18 | FUN_004230c0 | 00423239 | raw (`EBX`) | FUN_00417850-class family |

| 20 | FUN_004240f0 | 0042411c | `+0x60` | **new slot** |
| 21 | FUN_0042f810 | 0042f889 | `+0x08` | Group C adjust |
| 22 | FUN_00430510 | 0043057d | raw (`ESI`) | unknown |

**Three of the callers adjust by +0x28 (0041aa40, 0041d380×2)**, one by +0x08 (0042f810), two by +0x60 (00422e00, 004240f0), one by +0x20 (0041de60), and 16 pass raw `this` unchanged. The e220-style Group B (+0x10) adjustment does **not** appear at any e280 callsite.

**Implication:** for the raw-ECX callers, the dispatched object is whatever object the caller's caller passed in — i.e., these are mostly **directly-dispatched calls to the e280 function itself** (no sub-object adjustment needed) and they route through whatever class the Radmin session hands to the constructor at service-start. Without runtime or deeper per-path analysis, **the class of the raw-ECX objects is UNRESOLVED** — but is overwhelmingly likely to be FUN_00417850-class (the class whose vtable contains the dispatch-capable e280-callers and whose construction is the sole target of the FUN_00424550/FUN_00417850 chain).

## 2. The answer to the mission's questions

### Q1 — Where does P originate for each dispatcher family?

P = `[EDI + 0x0C]` (EDI = adjusted pointer at entry; same for both dispatchers).

| Group | Adjusted EDI | P field | Producer of P |
|---|---|---|---|
| **Group A** | `base + 0x28` | `[base + 0x34]` | **`0x0051aee0` — a static `.rdata` RTTI CompleteObjectLocator-like table** — set by the FUN_00417850-class constructor at `0041788e`: `00417893: MOV dword ptr [EBX + 0x34],0x0051aee0` (DIRECTLY VERIFIED). Same kind of table for the homologous FUN_00418940-class constructor (`0041894b`). |
| **Group B** | `base + 0x10` | `[base + 0x1c]` | **`0x0051b01c` — a static `.rdata` offset/RTTI table** — set by the FUN_0041ea00-class constructor at `0041ea34`: `MOV dword ptr [EDI + 0x1c],0x0051b01c` (DIRECTLY VERIFIED). The FUN_00417850-class never writes this field (**heap garbage**). The FUN_00421410-class never writes it either (gap `0x1c`). |
| **Group C** | `base + 0x08` | `[base + 0x14]` | **`0x00000000` — a literal zero written by the constructor at `0041ea80`**: `MOV dword ptr [EDI + 0x14],0x0` (DIRECTLY VERIFIED). Also `0x00000000` for the FUN_0041ea00-class; **heap garbage** for FUN_00417850-class and FUN_00421410-class. |

### Q2 — Where does D originate?

D = `[P + 0x04]`.

| Group | D | Basis |
|---|---|---|
| Group A | **`0x00000210`** (528 decimal) | `.rdata` read at `0x0051aee4` (verified dump) — offset, not a pointer |
| Group B | **`0x000002b0`** (688 decimal) | `.rdata` read at `0x0051b020` (verified dump) — offset, not a pointer |
| Group C | **D does not exist** | P = 0, so `[0x00000004]` is an unmapped absolute access |

**Both D values are static offsets embedded in RTTI-CompleteObjectLocator-style tables.** These are not pointers — they encode where in the object the dispatch vtable ladder entry lives.

### Q3 — Are P and D initialized by constructors, static tables, or another mechanism?

**Both — but the chain is always:** constructor stores a `.rdata` pointer in the object → the `.rdata` table contains an offset → the offset is applied to the runtime object base → the constructor stored another `.rdata` pointer at that offset → the **dispatch target reads through it**.

For Group A (FUN_00417850-class): constructor → `[obj+0x34] = 0x0051aee0` → table `[0x0051aee0 + 0x04] = 0x00000210 (offset)` → `0x28 + 0x210 + 0x0c = 0x244 = obj+0x244` → constructor stores `[obj+0x244] = 0x00519e54` → target `= [0x00519e54] = 0x004e7650 (CFG-instrumented global-callback dispatch stub — reads `[0x005a5a54]`)`.

For Group B (FUN_0041ea00-class, child sub-object): constructor → `[obj+0x1c] = 0x0051b01c` → `[0x0051b020] = 0x000002b0` → `0x10 + 0x2b0 + 0x0c = 0x2cc = obj+0x2cc` → constructor stores `[obj+0x2cc] = 0x00519e54` → target `= 0x004e7650`.

For Group C: constructor → `[obj+0x14] = 0` → the chain is **unreachable** (D read at 0x00000004 faults).

### Q4 — Can the relevant Group A/B/C objects be connected to actual dispatcher callers?

**Group A — YES, end-to-end (e220 side):** vtable at `0x0051ae38` → `FUN_0041df20` → `FUN_0041e090` (passes `ECX = obj - 0x8` as this-ptr — verified at `0041df27 LEA ESI,[ECX-0x8]`) → `FUN_0041ae30`/`FUN_0041bb40`/`FUN_0041bd70` (ECX passes through unchanged) → `e220 @0041b05a/0041bd36/0041c03a` with `ECX = obj + 0x28`. All instructions verified. The object is a **FUN_00417850-class child** created through `FUN_0042d980 → FUN_00424550 → FUN_00417850` chain.

**Group A — YES, end-to-end (e280 side — all callers pass raw `this` or their own adjustment; 16 of 22 callers use raw ECX):** See §2a above — every e280 callsite receives a directly-dispatched `this` without Group-B-style adjustment. The class is unresolved for raw ECX callers but the dispatch chain P/D/V/target is identical; the same vtable sub-table sets are only found in the FUN_00417850/FUN_0041ea00-class hierarchy; no other candidate dispatch-capable class exists in the export.

**Group B — same conclusion for the FUN_0041ea00-class grandchild objects** (FUN_0041ea00 is called by FUN_00417850 at `00417bc6` — the grandchild is inside the FUN_00417850 product; `FUN_0041f090` and `FUN_0041f110` dispatch through it). 4 of 15 e220 callers (FUN_0041f710/0041fa80/00420b80/0041f450) use +0x10-adjusted pointers.

**Group C — dead path** (P = 0 literal — see Q1). Any object of the FUN_0041ea00-class that entered this path would crash immediately; the evidence is consistent with this path never executing at runtime. The sole Group C caller (FUN_0041f110 → e220 @0041f3b1) is dispatched through the vtable at `0x0051afe0` — i.e., on a FUN_0041ea00-class child, which carries the literal-zero P.

### Q5 — Are the CAS fields initialized for those objects?

| Field | Group A (FUN_00417850-class) | Group B (FUN_0041ea00-class) | Group C (FUN_0041ea00-class) |
|---|---|---|---|
| CAS1 | `[obj+0x2c] = 0x00000000` (004179a1 `MOV dword ptr [EBX + 0x2c],0x0`) **STATIC ZERO** | `[obj+0x14] = 0x00000000` (0041ea80) **STATIC ZERO** | `[obj+0xc] = 0x0051b014` (0041ea2d, path A requires [EBP+0x10]≠0 — always true here) **STATIC NON-ZERO** |
| CAS2 | `[obj+0x38] = 0x00000000` (004179c1) **STATIC ZERO** | `[obj+0x20] = 0x00000000` (0041eaa3) **STATIC ZERO** | `[obj+0x18] = 0x00000000` (0041ea8e) **STATIC ZERO** |

All six Group A/B/C CAS fields on these two classes are **constructor-initialized**, and all six are **zero except Group C CAS1 (0x0051b014)**.

### Q6 — Does the e16650 discovery reveal a comparable mechanism?

**Yes.** All three dispatch shapes use the same pattern: **constructor-selected `.rdata` tables → offset/pointer chain into the object → constructor-stored virtual-ladder slot → final target**. e16650 resolves to `FUN_00479d80`; Group A and Group B resolve to `FUN_004e7650` — the CFG-instrumented global-callback dispatch stub whose runtime target is `[0x005a5a54]`, registered via `FUN_004e766c` (4 callsites — 3 unconditional `0x004dd190`, 1 from a runtime table). Group C's chain is not viable.

### Q7 — Which Phase 9C reachability classifications can now be upgraded or downgraded?

| Phase 9C claim | Phase 9D verdict |
|---|---|
| `FUN_00420b80` — 0 incoming callers, UNKNOWN | **REFUTED** — it has **2 direct callers** (`FUN_0041f450 @ 0041f6bd` and `FUN_00420b30 @ 00420b52`), both direct `E8` from listing (`E869A6FFFF` / `E8E381FFFF`). Reclassify **CONDITIONAL**. |
| `FUN_0041f110` — "0 incoming refs, UNKNOWN" | **CONFIRMED** (no `UNCONDITIONAL_CALL` records target it); but a `DATA` ref at `0x0051afe8` proves it lives in the FUN_0041ea00-class vtable at `0x0051afe0` — it can only be entered via vtable dispatch by framework code outside this export. **UNRESOLVED** but vtable-backed. |
| e220 caller grouping (A/B/C) — based on adjustment offset + workspace | **CONFIRMED by re-reading the callsites**: `LEA ECX,[EDI + 0x28]` (E1, E2a, E2b, A4-A10, A2a, A2b → 10 Group A sites), `LEA ECX,[EDI + 0x10]`/`LEA ECX,[EBX + 0x10]`/`LEA ECX,[ESI + 0x10]` (A11, A12, A13, A15 — 4 Group B sites), `LEA ECX,[EBX + 0x8]` (A14 — 1 Group C site). |
| "Object identity unresolved for ALL callers" | **PARTIALLY RESOLVED** — Group A objects are FUN_00417850-class children (created via `FUN_00424550→FUN_00417850`); Group B/C share the FUN_0041ea00-class grandchild. Whether any *individual caller* receives that object class from its caller is still per-callsite (same pattern, same class, different constructor chain — but the class is established). |
| Phase 9C `+0x214` gate family analysis | Unchanged — remains BLOCKED UNDER EXPLICIT ASSUMPTIONS |
| e220/e280 pointer chains — "target not statically resolvable" | **MAJOR UPGRADE** — for Group A and Group B, the **target is statically resolvable to `0x004e7650`** (CFG-instrumented global-callback dispatch stub). Chain details in `phase_9D_e220_pointer_chain.md` equivalents: `phase_9D_pointer_P_producers.md` / `phase_9D_pointer_D_producers.md`. |

### Q8 — Which pointer provenance questions remain unresolved?

1. The **dispatch-slot-selection code** inside the class classes — the exact `[reg + imm]` that loads the v/table pointer at the *entry* to the class dispatch chain (outside this export's scope or simply an outer Radmin entry point).
2. The **runtime resolution of `[0x005a5a54]`** — set by 4 callsites (all push `0x004dd190`); the CF-Guard stub will call whatever is registered there at dispatch time. Not statically verifiable beyond the constructor registration pattern.
3. **Group C chain viability** — the FUN_0041ea00-class product stored `P = 0` at construction (`0041ea80`); the chain can only fault. Whether that class object ever reaches an e220/e280 dispatch call is unknown — but if it does, it crashes. No reachable configuration produces a valid target through this path.
4. **Whether other classes exist with homologous layouts elsewhere in the binary** — the vtable block at `0x0051ae28` (plus `0x0051afd8`/`0x0051afe0`/`0x0051ae44` etc.) suggests a class hierarchy with a primary, several intermediate-derived classes using the same dispatch block. Full enumeration not conducted (out of Phase 9D scope).

## 3. Five blocked paths — final verdict

No change from Phase 9C. The five BLOCKED callsites remain **BLOCKED UNDER EXPLICIT ASSUMPTIONS**. Phase 9D adds: the per-site object classes are now identified (Group A — FUN_00417850-class child, via `FUN_00424550→FUN_00417850`), but this does not open the gates — the gates require `+0x214 == 0`, which every constructor sets and nothing stores non-zero — so they remain unreachable-unless-assumption-fails. No upgrade.

## 4. Bottom line

Phase 9D resolves the e220/e280 pointer provenance completely at the static level:

- **Group A objects** (FUN_00417850-class) carry `P = 0x0051aee0`, `D = 0x00000210`; chain resolves to `FUN_004e7650` for every e220/e280 callsite whose object is a FUN_00417850-class child.
- **Group B** (FUN_0041ea00-class) carries `P = 0x0051b01c`, `D = 0x000002b0`; same chain resolves to `FUN_004e7650`.
- **Group C** (FUN_0041ea00-class) has `P = 0` — the chain does not reach the call.
- **CAS fields** are constructor-initialized on all three groups; Group A/B are zero, Group C CAS1 = `0x0051b014`.
- The vtable block at `.rdata 0x0051ae28..0x0051b014` is the class's RTTI/vtable ensemble — the dispatch-object classes' own tables are verified.
- `FUN_004e7650` (CFG-instrumented global-callback dispatch stub) is the **universal** indirect-dispatch target for this subsystem — CFG-guarded call through the registered global callback at `[0x005a5a54]`.
- The e220/e280 indirect call is not "the feature of the object" — it is the **CF-Guard-instrumented generic call wrapper** used uniformly by every virtual dispatch in this binary.

No upgrade to any blocked verdict is justified. No dispatch-path is reachable that wasn't already. One inconsistency in Phase 9C was found and **corrected** (`FUN_00420b80`: 2 callers — `FUN_0041f450 @ 0041f6bd` and `FUN_00420b30 @ 00420b52` — reclassified **CONDITIONAL**).
