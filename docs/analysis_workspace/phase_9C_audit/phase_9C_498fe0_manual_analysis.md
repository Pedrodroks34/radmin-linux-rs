# Phase 9C — `FUN_00498fe0`: the decompiler timeout, analyzed manually

**File:** `ghidra_export/listing/00498fe0.asm` — **20,878 instruction lines**, `body=[00498fe0..004ad1d7]`, size **82,424 bytes** — the largest function in the export (next largest: 7,380 / 5,382 / 5,311 / 4,467).
`functions.jsonl`: `calling_convention: "unknown"`, `decompile_status: "failed"`, `decompile_error: "Exception while decompiling 00498fe0: process: timeout\n"`, `decompiled_code: null`.

## 1. What the binary contains (manual reading)

A single monolithic **"install-and-register everything"** megafunction — a switch with ~40 cases, each of which:

- tests one bit of a flag global at `0x005988cc` / `0x005a4348` / `0x005a494c` / `0x005a4f50` (`TEST AL|EAX, 0x1`, `0x2`, `0x4`, `0x8`, `0x10`, `0x20`, `0x40`, `0x80`, `0x100`, `0x200`, …),
- if already set: skip;
- else: OR the bit into the flag at `0x005…`,
- call `004e74f0` (event/message registration — takes `(0x30, 0, string_id at 0x005a4xxx)`),
- then call `004aebe0` with a `(0x7, 0x1322-0x135e range, string id)` signature — a **registry write** with type/name/value triples (names at `0x005a5xxx`-ish addresses, value strings at `0x00551xxx`).

End-of-function: at `004ac34d`, `0x00549138` is loaded (`MOV ECX,[0x00549138]`) — a global pointer object — and `CALL 0x004aec60` / `0x004aec80` / `0x004aec70` in a loop — enumerating child elements. The function terminates normally at `004ad1d0 RET` (all paths end at one of two RETs: `004ac1c7` / `004ace1f` / `004ad1d0`).

Direct global dependencies include: `0x005988cc`, `0x005a4348`, `0x005a494c`, `0x005a4f50` (flag pairs), `0x00549138` (object pointer), `0x005a5xxx` string blob (names), `0x00551xxx` string blob (values), `0x0050af50` / `0x0053xxxx` patterns. It does **not** touch `.rdata` vtables, `0x0055BF80`/`0x0055BF84`, `0x00519dac`/`0x0051b254`, `+0x214`, `+0x4`-CAS fields, or any dispatcher entry point.

## 2. Caller footprint

- 2,155 `CALL` sites inside the function. Targets by frequency:
  `1075 × 0x004e74f0` · `744 × 0x004aec20` (via pattern) · `331 × 0x004aebe0` · `4 × 0x004aec60/70/80` · `1 × 0x00489280`.
- **Exactly one external caller** of `FUN_00498fe0`: `FUN_004891d0` (verified via `references.jsonl` — the single `"to":"00498fe0"` record, `UNCONDITIONAL_CALL`).
- Callers of `FUN_00498fe0` cannot reach the dispatcher family through it (zero inventory overlap).

## 3. Does the timeout affect the dispatcher investigation?

**No — with instruction-level proof.**

| Question | Answer |
|---|---|
| Does it call/reference `FUN_0041e220` / `FUN_0041e280` / `FUN_00416650`? | **0 references** to any of the three (and to `FUN_0041a6d0`, `FUN_0041e1f0`, `FUN_00422f20`, `FUN_004230c0`, `FUN_00422ce0`, `FUN_0041f110`, `FUN_00420b80`) |
| Does it reference `+0x214`? | **0** |
| Does it reference `0x0055BF80` / `0x0055BF84`? | **0** |
| Does it reference the constructor `FUN_00421410`? | **0** |
| Does it contain the blocked gates `00422fa3` / `00423157`? | **no** (those live in different functions, all verified above) |
| Is it reachable from any dispatcher caller path? | **no** — caller inventory: 1 external caller, not in the dispatch tree |
| Could it affect the object-initialization analysis? | **no** — it has no constructors/destructors of dispatch objects; it only registers strings |
| Could it affect callback/vtable analysis? | **no** — no indirect or direct dispatcher indirection |

Grep evidence (file `00498fe0.asm`): `0041e220` 0 · `0041e280` 0 · `00416650` 0 · `0041a6d0` 0 · `004230c0` 0 · `00422f20` 0 · `00422e00` 0 · `00422840` 0 · `00419e20` 0 · `00421410` 0 · `0055bf80` 0 · `0055bf84` 0 · `00519dac` 0 · `0051b254` 0 · `0x214` 0.

## 4. What the timeout means operationally

- The decompiler exceeded its analysis budget (80–90 KB × ~2,150 calls, one single function — pathological for the Ghidra 12.2 decompiler pipeline).
- **The assembly listing is complete and usable** — the listing exists for every instruction and every reference record in `references.jsonl`; nothing is missing except the C pseudocode.
- The one affected field of `functions.jsonl` — `decompiled_code: null`, `signature: null`, `calling_convention: "unknown"` — means: treat the function as opaque for callsite-argument analysis. The inventory in `phase_9C_callsite_inventory.md` did not use its pseudocode; no dispatcher conclusion depended on it.
- Manual reconstruction of 2,155 calls is technically possible but: (a) the paths are orthogonal to the dispatcher subsystem; (b) it would not change any verdict in this phase; (c) the function's own callers are sealed to registry/event-log setup.

## 5. Bottom line

**`FUN_00498fe0` is irrelevant to the dispatcher investigation.** Its decompiler timeout is a size artifact, not a correctness problem; the assembly is complete, self-consistent, and fully cross-referenced, and it contains zero dispatcher-related signal. It should be reclassified as "out of scope (registry/event-log installer, 82 KB monolith)" rather than "unknown function". Nothing in the earlier phases' claims depends on it, and nothing in Phase 9C's conclusions changes if it is never decompiled.

**Recommended disposition:** leave it flagged as `decompile_status: failed`; if future phases decide to decompile it, use `analyzeHeadless` with a raised `analysis.timeout` or split the function analysis — but only for registry-completeness questions, never for dispatcher verification.
