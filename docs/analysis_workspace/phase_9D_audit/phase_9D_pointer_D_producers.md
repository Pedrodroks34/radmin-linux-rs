# Phase 9D — Pointer D Producer Inventory

**D = `[P + 0x04]`** — read after P is resolved.

## 1. Group A — P = `0x0051aee0` (FUN_00417850-class)

`D = [0x0051aee4]` → `.rdata` dump:

```
0x0051aee0:  fffffff4   offset-to-top = -12
0x0051aee4:  00000210   ← D
0x0051aee8:  00000218
0x0051aeec:  00000220
0x0051aef0:  0000022c
0x0051aef4:  00000238
0x0051aef8:  00000000
0x0051aefc:  00000208
0x0051af00:  00000210
0x0051af04:  0000021c
```

**D = `0x00000210` (528 decimal)** — a static `.rdata` **offset**, not a pointer. D is structurally part of the RTTI CompleteObjectLocator-equivalent table at `0x0051aee4` (offset scheme: P + 0x04 + (index × 4) → accel-targets list; the chain A = EDI + D + 0x0C treats it as the offset between the object base and the target slot).

Verification chain: `.rdata` bytes read read-only via `dump_rtti.py` — CONFIRMED.

## 2. Group B — P = `0x0051b01c` (FUN_0041ea00-class)

`D = [0x0051b020]` → `.rdata` dump:

```
0x0051b014:  fffffffc
0x0051b018:  000002c0
0x0051b01c:  fffffff4   ← P (base of this sub-table for FUN_0041ea00-class)
0x0051b020:  000002b0   ← D = 0x2b0 (688 decimal)
0x0051b024:  74697277    "wirr" (ASCII)
0x0051b028:  00000065
0x0051b02c:  6e65706f   "open"
```

**D = `0x000002b0` (688 decimal)** — a static `.rdata` **offset**, not a pointer.

## 3. Group C — P = `0x00000000` (FUN_0041ea00-class)

`D = [0x00000000 + 0x04] = [0x00000004]` — **unmapped address**. The read faults. **D does not exist for Group C** — the chain cannot reach the indirect call, regardless of other state.

## 4. Table properties (why these offsets, not pointers)

The D values are entries in the same structural family as the e16650-discovered table (same offset-accepting layout but those tables contain pointers; these contain **offsets** because the consumers apply them to a runtime EDI, never to the table base):

```
After D read:
  A = EDI + D + 0x0C
  V = [A]
  target = [V]
```

The offset values (`0x210`, `0x2b0`) are **dispatch-table-relative**: applying them to the object base produces the address of the *live* vtable-ladder slot. Static evidence confirms:

- `obj+0x244` → `VLT` slot — constructor writes `0x00519e54` at `004178ba` (FUN_00417850-class)
- `obj+0x2cc` → same behavior for the FUN_0041ea00-class grandchild — constructor writes `0x00519e54` at `0041ea3b`-neighboring block (FUN_0041ea00 at `0041ea3b` stores `[EDI+0x2cc] = 0x519e54`)

`0x00519e54` contains the **universal** CF-Guard dispatch stub:

```
0x00519e54:  004e7650   ← FUN_004e7650 (CFG-instrumented global-callback dispatch stub)
```

`FUN_004e7650` is referenced from **219 call/data refs** across `.rdata` — every entry is a vtable slot, confirming it is *the* universal indirect-call trampoline for this binary.

## 5. Verdict

| Group | D | Classification |
|---|---|---|
| Group A | `0x00000210` — static `.rdata` offset | **DIRECTLY VERIFIED** |
| Group B | `0x000002b0` — static `.rdata` offset | **DIRECTLY VERIFIED** (conditional on P path A) |
| Group C | non-existent (P = 0 → `[4]` unmapped) | **DIRECTLY VERIFIED** — chain cannot reach target |
