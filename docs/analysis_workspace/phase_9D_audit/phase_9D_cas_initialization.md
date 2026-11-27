# Phase 9D — CAS Initialization Matrix

For each dispatcher-class × CAS field pair: explicit init, zeroed-allocation, struct-copy, static, missing, or identity-unresolved.

## Class 1 — FUN_00417850-class (Group A direct dispatch object)

| Field | Offset | Classification | Evidence |
|---|---|---|---|
| Adjusted EDI | `obj + 0x28` | **EXPLICIT** — `MOV dword ptr [EBX + 0x28],0x0051a984` (temp `004179af`) → overwritten `0x0051ae58` at `00417a0f` | `listing/00417850.asm:004179af,00417a0f` |
| CAS1 | `obj + 0x2c` | **EXPLICIT STATIC ZERO** — `MOV dword ptr [EBX + 0x2c],0x0` | `004179a1` |
| P | `obj + 0x34` | **EXPLICIT STATIC** — `0x0051aee0` | `0041788e` |
| CAS2 | `obj + 0x38` | **EXPLICIT STATIC ZERO** — `MOV dword ptr [EBX + 0x38],0x0` | `004179c1` |
| CAS1 witness | `obj + 0x30` | **EXPLICIT STATIC ZERO** — `MOV dword ptr [EBX + 0x30],0x0` | `004179a8` |
| Sub-vtable | `obj + 0x44` | **EXPLICIT STATIC** — `0x0051aef8` | `00417895` |
| Ladder slot | `obj + 0x244` | **EXPLICIT STATIC** — `0x00519e54` | `004178ba` |

**Group A CAS state at creation: CAS1 = 0, CAS2 = 0. Static — not from allocation clearing.**

## Class 2 — FUN_0041ea00-class (Group B/C sub-object)

| Field | Offset | Classification | Evidence |
|---|---|---|---|
| Adjusted EDI | `obj + 0x10` | **EXPLICIT STATIC** — `0x0051b004` (final), `0x0051a984` (temp) | `0041ea87 / 0041eab7` |
| CAS1 | `obj + 0x14` | **EXPLICIT STATIC ZERO** — `MOV dword ptr [EDI + 0x14],0x0` | `0041ea80` |
| P | `obj + 0x1c` | **EXPLICIT STATIC** — `0x0051b01c` | `0041ea3b` (path A) |
| CAS2 | `obj + 0x20` | **EXPLICIT STATIC ZERO** — `MOV dword ptr [EDI + 0x20],0x0` | `0041eaa3` |
| CAS1 alt | `obj + 0xc` | **EXPLICIT STATIC** — `0x0051b014` (non-zero, path A!) | `0041ea2d` |
| CAS2 alt | `obj + 0x18` | **EXPLICIT STATIC ZERO** | `0041ea8e` |
| Ladder slot | `obj + 0x2cc` | **EXPLICIT STATIC** — `0x00519e54` | `0041ea3b`-block |
| Sub-init fence | `obj + 0x118/0x11c/0x2c0/0x2b4` | **EXPLICIT STATIC ZERO** or `0x0051afc0 → 0x0051afcc` | `0041eb58..0041ebb8` |

**Group B CAS state at creation: CAS1 = 0, CAS2 = 0.**
**Group C CAS state at creation: CAS1 = 0x0051b014 (non-zero, path A), CAS2 = 0.**

## Class 3 — FUN_00421410-class (+0x214-gate dispatch parent)

| Field | Offset | Classification | Evidence |
|---|---|---|---|
| +0x214 | `obj + 0x214` | **EXPLICIT STATIC ZERO** — `MOV dword ptr [EDI + 0x214],0x0` | `0042173b` (single direct store) |
| +0x218 | `obj + 0x218` | **EXPLICIT STATIC ZERO** | `00421745` |
| +0x1b0 | `obj + 0x1b0` | sub-init — FUN_00479510 | indirect |
| +0x1c8 | `obj + 0x1c8` | sub-init — FUN_00479510 | indirect |
| +0x20c | `obj + 0x20c` | XADD-CAS locked RMW | sets bit 0 to 1 via CAS in factory  |
| +0x238 | `obj + 0x238` | **EXPLICIT STATIC BYTE ZERO** | `00417d42` region (FUN_00421410-class only) |
| +0x2c/A | n/a | Not written by this class (only 0x214-family) | — |

**Group A/B/C-like fields in FUN_00421410-class objects are NEVER initialized — by design, these objects are never dispatched into the e220/e280 indirect chain. They route through FUN_00422ce0 (envelope dispatcher).**

## Cross-reference for Group A CAS1/CAS2 relative to Phase-9C blocked-path analysis

The blocked paths (E1/E2a/E2b via B1/B2) have all CAS conditions **explicitly pre-initialized to zero at construction** — meaning the +0x214 gate is the *entire reason* they never dispatch. With the +0x214 gate removed or bypassed:

1. The system would hit e220's CAS1 and CAS2 with: CAS1 result = 0 (stored to [this+0x14]... wait no. e220 CAS1 stores arg1 at [this+0x04] and sets [this+0x04]=6 if it was 0. The FIRST dispatch:
   - CAS1: [this+0x04] == 0 → CAS succeeds → [this+0x04] := arg1, proceed.
   - CAS2: [this+0x10] == 0 → CAS succeeds → [this+0x10] := 1 → dispatch proceeds.
   - Target = V = `FUN_004e7650` — reached.
   - Behavior: the handler registered at [0x005a5a54] (currently `0x004dd190`) is invoked.

2. The **very next dispatch** for the same object calls e220 CAS1 again — this time `[this+0x04] != 0` → skip CAS success path; caller reads [this+0x10]==0 still (unchanged) → continues to work block.

So the dispatcher supports 2 invocations per object: 1 full dispatch + 1 pre-completed. Subsequent calls are no-ops (the gate refuses).

## Zero-byte destinations

`REP MOVS` in FUN_00421410 (constructor 2): copies `[ESI+0..156]` to `[EDI+0x110..0x1ac)`. Does **not** cover any Group A/B/C field. Does not zero +0x214. Verifies: bulk copy does not touch the dispatch-relevant fields.

## Verdict

| Class | All CAS fields initialized? | Dispatch-blockable? |
|---|---|---|
| FUN_00417850-class | **YES** — all static or zero-initialized by constructor before any code runs | No — full dispatch proceeds on first invocation |
| FUN_0041ea00-class | **YES** — CAS1 = 0 (path A), CAS2 = 0 | No — full dispatch proceeds |
| FUN_00421410-class | **YES** — only +0x214 is set to zero by constructor (used as global gate) | **YES** — +0x214 gate remains closed; every gate family routes through it or no other path exists |
