# Phase 9D — Pointer P Producer Inventory

**P = `[EDI + 0x0C]`** (EDI = adjusted pointer at dispatch entry).

## 1. Producers of P, by class

### Group A — FUN_00417850-class (primary candidate object for the e220/e280 dispatch chains)

| Witness | Address | Instruction | Value written to `[obj + 0x34]` (P) |
|---|---|---|---|
| `listing/00417850.asm` | `0041788e` | `C74334E0AE5100  MOV dword ptr [EBX + 0x34],0x0051aee0` | **`0x0051aee0`** — a static `.rdata` pointer |
| `listing/00418940.asm` | `0041894b` | (read — no store; delta-initializer for stale objects) | reads existing |

**P (Group A) = `0x0051aee0`** — DIRECTLY VERIFIED. The constructor stores the pointer unconditionally (path guarded only by `[EBP + 0x24] != 0`; `[EBP + 0x24] = 0x00000001` always for this class — `0042daf2 → FUN_00421410` and `004245f6 → FUN_00417850` both receive the literal `1`).

`0x0051aee0` is a `.rdata` RTTI-CompleteObjectLocator-like table:

```
0x0051aee0  fffffff4   offset-to-top (-12)
0x0051aee4  00000210   virtual offset 528  ← D
0x0051aee8  00000218   virtual offset 536
0x0051aeec  00000220   virtual offset 544
0x0051aef0  0000022c   virtual offset 556
0x0051aef4  00000238   virtual offset 568
0x0051aef8  00000000
0x0051aefc  00000208
0x0051af00  00000210
0x0051af04  0000021c
0x0051af08  fffffffc
```

### Group B — FUN_0041ea00-class (grandchild class)

| Witness | Address | Instruction | Value written to `[obj + 0x1c]` (P) |
|---|---|---|---|
| `listing/0041ea00.asm` | `0041ea3b` | `C7471C1CB05100  MOV dword ptr [EDI + 0x1c],0x0051b01c` | **`0x0051b01c`** — a static `.rdata` pointer (path A: requires `[EBP + 0x10] != 0` — at this construction class, always true) |

### Group C — FUN_0041ea00-class (see Group B class)

| Witness | Address | Instruction | Value written to `[obj + 0x14]` (P) |
|---|---|---|---|
| `listing/0041ea00.asm` | `0041ea80` | `C7471400000000  MOV dword ptr [EDI + 0x14],0x0` | **`0x00000000`** — literal zero |

For the FUN_00417850-class, Group C P = `[obj + 0x14]` is **never written** — heap garbage.

### FUN_00421410-class — NO producer

The FUN_00421410 constructor (`00421410`) never stores anything at `[EDI+0x34]`, `[EDI+0x1c]`, or `[EDI+0x14]` (verified by exhaustive store scan — see `constructor_stores.py`). **FUN_00421410-class objects carry garbage in P.** This confirms FUN_00421410-class objects are NOT the objects dispatched through the e220/e280 indirect call chain: the Group A path would fault for them immediately (`D = [P+4]` on a garbage P).

## 2. Indirect producers / aliases of P

- **FUN_00418940** (delta initializer) reads `[EDI + 0x34]` at `0041894b` and unconditionally re-stores `0051ae28/0051ae30/0051ae44/0051ae58/0051ae60/0051ae6c` (its sibling class) — it assumes P was already initialized by `FUN_00417850` (it does NOT write P itself).
- **Constructor `REP MOVS` (`004216a8`)** copies 156 bytes from `[ESI+0..]` to `[EDI+0x110..0x1ab]` — does NOT cover `+0x1c`/`+0x14`/`+0x34`.
- No alias store to any P-field address via a different register (the 0x214-gate CAS paths never write `0x14/0x1c/0x34`).

## 3. Per-class dispatch chains that consume P

| Class | P consumer | Source file |
|---|---|---|
| FUN_00417850-class | `e220/e280` indirect chain (`P = [EDI+0x0C]` after `LEA` adjusts EDI) | `0041e220.asm` / `0041e280.asm` |
| FUN_0041ea00-class | same chain, same instructions — `LEA` reaches `+0x1c` for Group B and `+0x14` for Group C | same |
| FUN_00421410-class | chain cannot operate (P = heap garbage) | — |

## 4. Verdict

| Group | P source | Classification |
|---|---|---|
| Group A | Constructor `FUN_00417850` at `0041788e` stores `0x0051aee0` | **DIRECTLY VERIFIED** |
| Group B | Constructor `FUN_0041ea00` at `0041ea3b` (path A) stores `0x0051b01c` | **DIRECTLY VERIFIED** (conditional on `[EBP+0x10] != 0`, which holds for all known call sites) |
| Group C | Constructor `FUN_0041ea00` at `0041ea80` stores `0x00000000` | **DIRECTLY VERIFIED — chain cannot reach call target** |
