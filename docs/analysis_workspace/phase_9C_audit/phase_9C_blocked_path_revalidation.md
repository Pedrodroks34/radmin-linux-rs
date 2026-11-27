# Phase 9C — Blocked Path Revalidation (the five BLOCKED callsites)

**Ambiguity note.** "Phase 8Z" does not exist in this export (latest is 8X); the prior audit labels the following five call sites BLOCKED via the two `+0x214` gates (B1 = `FUN_00422f20`, B2 = `FUN_004230c0`). All five are revalidated here. There is no fourth/fifth candidate hidden elsewhere: re-scan of `references.jsonl` for targets `0041e220`/`0041e280` confirms exactly these five sites are preceded by the two gates (`00419e9b` B1; `0041a739`, `0041a768`, `0041a7f1`, `00423239` B2).

| ID | Site | Dispatcher | Gate | Path |
|---|---|---|---|---|
| E1 | `00419e9b` | e220 (`FUN_0041e220`) | B1 | `FUN_00422ce0` → `00422f20` →(CAS `00422fa3`) `00423030` → `FUN_00419e20` → `00419e9b` |
| E2a | `0041a739` | e220 | B2 | `FUN_00422ce0` → `004230c0` →(CAS `00423157`) `004231f7` → `FUN_0041a6d0` → `0041a739` |
| E2b | `0041a768` | e220 | B2 | same → `FUN_0041a6d0` → `0041a768` |
| E3 | `0041a7f1` | e280 (`FUN_0041e280`) | B2 | same → `FUN_0041a6d0` → `0041a7f1` |
| E4 | `00423239` | e280 | B2 | `FUN_00422ce0` → `004230c0` →(CAS `00423157`) →…→ `00423239` |

## 1. The gates, instruction-level

### B1 — `FUN_00422f20` (`listing/00422f20.asm`)

```
00422f99  LEA EDX,[EDI + 0x214]          ; EDI = ECX (this) at 00422f4b
00422f9f  XOR ECX,ECX
00422fa1  XOR EAX,EAX
00422fa3  F00FB10A  CMPXCHG.LOCK dword ptr [EDX],ECX
00422fa7  TEST EAX,EAX
00422fa9  0F8490000000  JZ 0x0042303f    ; field==0 → failure path (FUN_00419e20 NOT called)
00422faf  MOV EAX,dword ptr [EBX + 0x14]
…
00423018  F00FB10A  CMPXCHG.LOCK dword ptr [EDX],ECX   ; second CAS on same field? EDX=&[EBP-0x14] now (see 00423013)
00423030  E8EB6DFFFF  CALL 0x00419e20                  ; the blocked call site
```

`00422f4b`: `MOV EDI,ECX` — the gate's object is the caller-supplied `this`.
`00422f52 JZ 0x00423090` — bail if `EBX == 0`.
Callers: exactly one in the whole export — `FUN_00422ce0` at `00422d35` (verified: `xref.py callers 00422f20` → 1 site; identical for `004230c0` → 1 site).

### B2 — `FUN_004230c0` (`listing/004230c0.asm`)

```
004230eb  MOV ESI,ECX                    ; ESI = this
004230ed  MOV EBX,dword ptr [EBP + 0x8]  ; EBX = arg1
004230f0  TEST EBX,EBX
004230f2  JZ 0x0042326d                  ; arg1==0 → bail
…
0042314d  LEA EDX,[ESI + 0x214]          ; EDX = &[ESI+0x214]
00423153  XOR ECX,ECX
00423155  XOR EAX,EAX
00423157  F00FB10A  CMPXCHG.LOCK dword ptr [EDX],ECX
00423162  JZ 0x004232e2                  ; field==0 → failure path (FUN_0041a6d0/FUN_0041e280 NOT called)
```
Callers: exactly one — `FUN_00422ce0` at `00422d42`.
Additional gates on the same execution (all read `EBP-0x14`, the swapped copy of the field): `004231b1 JZ → 004232e2`, `004231ea JZ → 0042323e`, and `00423216 JZ → 0042328b` / `0042321d JZ → 0042328b`.

## 2. Exhaustive write inventory for `+0x214` (whole export, all 6,904 listings)

Greped `0x214\b` across `ghidra_export/listing/*.asm`. **Every** instruction touching the `+0x214` field, classified:

| Site (file) | Instruction | Effect on `[X+0x214]` |
|---|---|---|
| `00421410.asm:0042173b` | `MOV dword ptr [EDI + 0x214],0x0` | **only direct store; writes 0** |
| `00421990.asm:00421a9d` / `00421aa3` | `LEA EAX,[EDI+0x214]` ; `XCHG dword ptr [EAX],ECX` (ECX=0) | writes **0** (atomic clear) |
| `00422150.asm:004221f0` / `00422203` | `LEA EDX,[EDI+0x214]` ; `CMPXCHG.LOCK [EDX],ECX` (EAX=0,ECX=0) | writes **0** (CAS-with-0) |
| `004224f0.asm:004225ae` / `004225b9`,`004225c5` | `ADD EDX,0x214` (EDX=[EBP-0x10]) ; `CMPXCHG.LOCK [EDX],ECX` ×2 (EAX=0) | writes **0** |
| `00422e00.asm:00422e81` / `00422e89`,`00422e95` | same shape | writes **0** |
| `00422840.asm:004228f2`,`004229a5`,`00422a4f` / `004228fc`,`00422935`,`00422a57`,`00422a93` | `LEA ESI,[EBX+0x214]` ; CMPXCHG×4 (zero acc) | writes **0** |
| `00422f20.asm:00422f99` / `00422fa3`,`00422fb9` | `LEA EDX,[EDI+0x214]` ; CMPXCHG×2 | writes **0** |
| `004230c0.asm:0042314d` / `00423157`,`0042316c` | `LEA EDX,[ESI+0x214]` ; CMPXCHG×2 | writes **0** |
| `004230c0.asm:00423190` | `LEA EAX,[ESI+0x214]` ; passed to `CALL 0x0041ee90` | `FUN_0041ee90` does CAS(`[ESI+0x214]`, 0) then XCHG of the **local** — writes **0** (see below) |
| `00423550.asm:004235d2`,`004235dd` | `LEA EAX/EDX,[EDI+0x214]` | address materialization only (no store visible in the matched lines; not a store) |
| `00423980.asm:00423a5d`,`00423a9a` | `LEA EDX,[EDI+0x214]` ×2 | address materialization |
| `00424140.asm:00424181` | `LEA EDX,[ESI+0x214]` | address materialization |
| `00424230.asm:00424260`,`00424277` | `LEA EDX/EBX,[ESI+0x214]` | same |
| `00424310.asm:0042434e` | `LEA EDX,[ESI+0x214]` | same |
| `004243f0.asm:0042447e` | `LEA EDX,[ESI+0x214]` | same |
| `00422260.asm:0042244e`,`004224a8` | `LEA ESI/ECX,[EDI+0x214]` | address materialization |
| `00422ce0.asm` | — | **no `+0x214` reference** |
| `*.asm` (`PUSH 0x214` ×6, in `004871b0`,`00486b70`,`0047dff0`,`0047dc60`,`004617a0`,`0045cc10`) | `PUSH 0x214` | **constant push, not a memory access** |

**Result: no instruction in the export stores a non-zero value into `[X+0x214]`.** The prior audit's statement "only write is MOV [EDI+0x214],0 at 0042173b" is incomplete but its conclusion (no nonzero write) is **CONFIRMED at instruction level**.

### `FUN_0041ee90` (callees' effect on the field)

```
EDX = arg1 (= &[ESI+0x214] — the caller's pushed pointer)
EBX = ECX  (= &[EBP-0x14] — caller's local)
0041ee9f  CMPXCHG.LOCK [EDX], ESI (ESI=0)     ; CAS([field], 0); EDI = old field
0041eea9  if EDI: INC.LOCK [EDI+0x4]
0041eead  XCHG dword ptr [EBX], EDI           ; local ← old field
0041eedb  RET 0x4
```
The field receives **0** from this helper (via the CAS with zero accumulator when field==0: dst←ESI(0); when field≠0: no write). It never receives a non-zero stored value from here either. The swapped `local` (EBP-0x14) carries the old field value forward into the CAS chain.

### Bulk-copy check

`FUN_00421410` at `0042169a ADD EDI,0x110` then `004216a3 MOV ECX,0x27` (39 dwords) `004216a8 REP MOVSD` (`F3A5 MOVSD.REP ES:EDI,ESI`) — copies `[ESI, ESI+0x9C)` to `[EDI+0x110, EDI+0x1AC)`. **Does NOT reach `+0x214`.** No `REP MOVS`/`STOS`/`CMPS` site in the export targets an object at a range covering `+0x214` (the other F3A5 sites are `004151cc`, `00421410`, `004216a8`, `0042c381`, `0043f8cc` — none of them is a memcpy into the dispatch object's 0x214 region; the one in `FUN_00421410` is the construction copy, proven above to stop at 0x1AB).

### Pool/reuse check

The single object-creation site (`0042daf2` in `FUN_0042d980`) allocates **0x258** bytes through `FUN_004e5a66 → FUN_004018a0 → __malloc_base (FUN_004ff788 → HeapAlloc(0x005a61a0, 0, 0x258)` — flag **0x0**, memory **NOT zeroed**). Fresh fields are undefined until the constructor runs; the constructor zeroes `+0x214` (`0042173b`) **unconditionally** on every completed construction (the function has exactly one RET, at `00421777`; the zero-store is not under a condition). **Every dispatch object in this binary therefore has `+0x214 == 0` immediately after construction** — direct verification of the initializer's gate contract.

### Alias / callback / external check

- No alias store to `+0x214` exists (inventory above).
- No callback exported from this binary writes it; the binary exports nothing (`pe_imports.py`: entry 0 of the import table is null; `.edata` is empty).
- `RVROLCLIENT.DLL`/`SHELPER.DLL` opaque to this export — **cannot be excluded statically** (see assumptions).
- Message dispatcher (`FUN_00422ce0`) dispatches to the gates; no path inside it writes `+0x214`.
- `.rdata` contains no pointer-to-`+0x214`-writer (any such pointer would be a data reference to a function VA; the constructor's referenced tables were inspected — `0x00521710` is all-zero data + `0x000000c0 0x46000000` + two repeated GUID-like patterns `dcb00000 4a9b570f 9f19698d 3b72a5db` / `dcb00c01 4a9b570f 9f19698d 3b72a5db` — the MOVUPS constant copied into `[EDI+0x21c..0x22c)` is NOT code).

## 3. Gate identity (which object is gated)

| Gate | Object register | Source of register | Same allocation as constructor? |
|---|---|---|---|
| B1 `00422fa3` | `EDI` = `48BF`←`ECX` (`00422f4b MOV EDI,ECX`) | this | the dispatch object created at `0042daf2` and message-dispatched via `FUN_00422ce0` — **same class family** (the gate and the constructor share the `+0x1c8/+0x1e0/+0x1e4/+0x1e8/+0x1f0/+0x20c/+0x214/+0x218/+0x21c` offsets and the `XADD [x+0x24]`/`INC.LOCK [x+0x4]` idiom) — STRONGLY_SUPPORTED |
| B2 `00423157` | `ESI` = `ECX` (`004230eb`) | this (same pattern) | same — STRONGLY_SUPPORTED |

The message dispatcher `FUN_00422ce0` receives `ESI = ECX` (this) from its caller; its two gate cases call `FUN_00422f20`/`FUN_004230c0`. So the gated object is the object created by the `FUN_0042d980 → FUN_00421410` chain (only creation site, 1 call) — **identity STRONGLY_SUPPORTED**.

## 4. The verdicts

| ID | Classification | Basis |
|---|---|---|
| E1 | **BLOCKED UNDER EXPLICIT ASSUMPTIONS** | gate B1 verified; assumptions A1–A3 below |
| E2a | **BLOCKED UNDER EXPLICIT ASSUMPTIONS** | gate B2 verified |
| E2b | **BLOCKED UNDER EXPLICIT ASSUMPTIONS** | same gate, same object |
| E3 | **BLOCKED UNDER EXPLICIT ASSUMPTIONS** | same gate; additionally requires `[EBP-0x14] != 0` (004231b1) and `[EBP-0x14] != 0` (004231ea) and `AL != 0` skip (0042320b not taken) and `EAX != 0` (00423216) — same zero-field chain |
| E4 | **BLOCKED UNDER EXPLICIT ASSUMPTIONS** | same gate; same extra local-flag chain as E3 |

**Not one of the five can be labeled PROVEN BLOCKED.** No instruction-level contradiction exists (the gates' branches are exactly as reported), but the gate itself is data-dependent and the object's state is not provable from within the export alone.

## 5. Explicit assumptions required for BLOCKED

- **A1 (construction):** Every dispatch-object instance whose gate is reached was created via the single creation path (`FUN_0042d980` @ `0042daf2` → `FUN_00421410`), and `FUN_00421410` completes (it has no conditional early return before the `+0x214` store). → **STRONGLY_SUPPORTED** (single call site; direct store on unconditional path).
- **A2 (no external writer):** No code outside this binary (`RVROLCLIENT.DLL`, `SHELPER.DLL`, another process, shellcode, debugger, or out-of-process mutation of the object's memory) writes `+0x214 != 0`. The export cannot prove absence — **UNKNOWN**.
- **A3 (object identity):** The `ESI`/`EDI` at the gate denotes the same allocation decorated by `FUN_00421410` — supported by identical construction-time offsets and single-creation-path evidence. → **STRONGLY_SUPPORTED** (conditional on A1).

If A1 fails (an object reaches the gate without that constructor), the field contains heap garbage; the CAS at the gate may *pass* (non-zero garbage) — i.e. the path would become **reachable**, not blocked. If A2 fails, the field can become non-zero at any time; paths become reachable. Neither can be excluded from the export alone.

**Additional observation (stronger than BLOCKED for reachability of payload):** even when a gate passes, the dispatch CAS chain re-tests `[adjusted+0x4] == 0` (`0041e231 CMPXCHG [ESI],EDX`, `0041e252 CMPXCHG [ECX],EDX` with EAX=0) with **heap-garbage** sub-object fields (HeapAlloc does not zero; nothing in the export initializes `[base+0x2c]` / `[base+0x34]` / `[base+0x38]`). Under any non-zero-garbage distribution the probability that fresh objects pass CAS1/CAS2 is negligible — but this is a statistical argument, not proof, and it applies to **all** conditionally-reachable callers equally. It is stated here only to note that "BLOCKED under assumptions" is the *most optimistic* static classification, not a certainty of reachability for any path.

## 6. What this phase replaces

- "PROVEN BLOCKED / unreachable" (`phase_8V`, `phase_8W`, `phase_8X` conclusions) → **WITHDRAWN** (not supported).
- "BLOCKED" (Phase 8X per-caller tables) → **DOWNGRADED** to BLOCKED UNDER EXPLICIT ASSUMPTIONS.
- "Only write is MOV [EDI+0x214],0 at 0042173b" (`phase_8V_214_writers.md`) → **CORRECTED** to: no instruction in the export stores non-zero into `[X+0x214]` (all writes are 0 or CAS-with-0); the conclusion survives, the evidence statement was incomplete.
- "JZ at 00423162 is always taken" (8V) → **CONDITIONAL** — holds iff A1∧A2 (the gate itself is sound; the conclusion is data-dependent).

## 7. Minimum evidence to settle this permanently

One instrumented run (authorized dynamic session per the Phase-10.20 plan): breakpoint on `00423157` and `00422fa3`, dump `[ESI+0x214]` / `[EDI+0x214]` across dispatcher passes. A single read of `0x214 != 0` falsifies the blocked classification; persistence of `0` across the full test matrix keeps it conditional (A2 remains unprovable statically). Until then: **BLOCKED UNDER EXPLICIT ASSUMPTIONS**.
