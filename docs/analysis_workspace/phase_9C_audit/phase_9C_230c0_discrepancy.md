# Phase 9C — FUN_004230c0: the alleged e280 call at 00423239, resolved

## 1. The claim under dispute

Prior phases produced three mutually inconsistent statements:

| Source | Statement |
|---|---|
| `relatorio_parte8R_caller_table.md` §5.2 #18 (Phase 8R) | `00423239` `FUN_004230c0` — "**CONFIRMED** reproduces wrapper" — `PUSH EDI`, `PUSH EDX`, `MOV ECX, EBX`, `CALL 0x0041e280` |
| `phase_8X_audit/phase_8X_e280_object_states.md` (Phase 8X) | `FUN_004230c0 | 00423239 | EBX | Unknown | **BLOCKED**` |
| `phase_8W_audit/phase_8W_reachability_graph.md` (Phase 8W) | edge `FUN_004230c0 → N2` at `00423239` labeled "**CONDITIONAL**" in §"Direct Calls to FUN_0041e280" but the same edge listed "**BLOCKED**" in §"Blocked Path Edges" |
| `phase_8V_audit/phase_8V_230c0_analysis.md` (Phase 8V) | "FUN_004230c0 never passes a non-zero pointer from +0x214 to FUN_0041a6d0…" (gate-blocking framing) |

The mission asks: does `FUN_004230c0` directly call `FUN_0041e280`, does it only call `FUN_0041a6d0` (which then calls e280), was `00423239` misattributed, or did reports confuse a parent path with a direct callsite?

## 2. Instruction-level evidence (DIRECTLY VERIFIED)

`listing/004230c0.asm` (the complete function; no missing segments):

```
0042314d  LEA EDX,[ESI + 0x214]          ; EDX = &[this + 0x214]           gate base
00423153  XOR ECX,ECX
00423155  XOR EAX,EAX                    ; accumulator = 0
00423157  F00FB10A  CMPXCHG.LOCK dword ptr [EDX],ECX
0042315b  TEST EAX,EAX
0042315d  SETNZ AL
00423160  TEST AL,AL
00423162  0F847A010000  JZ 0x004232e2    ; if [this+0x214]==0 → jump to failure path
00423190  LEA EAX,[ESI + 0x214]
00423196  PUSH EAX
00423197  LEA ECX,[EBP + -0x14]
0042319a  CALL 0x0041ee90                ; callee: CAS([ESI+0x214], 0) vs [EBP-0x14] — swaps them
…
004231ec  XOR ECX,ECX
004231ee  XOR EAX,EAX
004231f0  CMPXCHG.LOCK dword ptr [EDX],ECX   ; second CAS on the LOCAL flag (EDX = &[EBP-0x14], set at 004231a1/004231df) — not on [ESI+0x214]
004231f4  PUSH EBX
004231f5  MOV ECX,EAX                        ; ECX = old local value (CAS result)
004231f7  E8D474FFFF  CALL 0x0041a6d0        ; direct call — carries the local flag value as ECX
…
00423211  LEA EBX,[ESI + 0x60]             ; EBX = this + 0x60
00423214  TEST EAX,EAX
00423216  JZ  0x0042328b                   ; bail if CAS result was 0
00423218  LEA ECX,[EAX + 0x28]
0042321f  MOV EAX,dword ptr [ECX]          ; EAX = [obj+0x28]
00423221  FF10        CALL dword ptr [EAX] ; indirect CALL through [obj+0x28]
00423223  MOV ESI,EAX
00423225  MOV ECX,ESI
00423227  CALL 0x00415f80                  ; 1st helper
0042322c  MOV ECX,ESI
0042322e  MOV EDI,EAX                      ; ret1 (EAX) → EDI
00423230  CALL 0x00415f80                  ; 2nd helper
00423235  PUSH EDI
00423236  PUSH EDX                         ; ret2 (EDX) → arg
00423237  MOV ECX,EBX                      ; ECX = this + 0x60
00423239  E842B0FFFF  CALL 0x0041e280      ; DIRECT call to FUN_0041e280
```

(At `004231f0`, `EDX = &[EBP-0x14]` (set at `004231a1` / refreshed at `004231df`); the `004231f0` CAS therefore operates on the **local stack flag**, not on `[ESI+0x214]`. The only `+0x214` CAS in this function is the gate at `00423157`; the `0042316c` CAS immediately after the branch is the same field with the same zero accumulator, its result unused.)

`references.jsonl` records confirm both edges:

```
{"direction":"incoming_to_function_entry","from":"004231f7","to":"0041a6d0","reference_type":"UNCONDITIONAL_CALL","is_call":true,"from_function":"FUN_004230c0","to_function":"FUN_0041a6d0"}
{"direction":"incoming_to_function_entry","from":"00423239","to":"0041e280","reference_type":"UNCONDITIONAL_CALL","is_call":true,"from_function":"FUN_004230c0","to_function":"FUN_0041e280"}
```

And inside the callee (`listing/0041a6d0.asm`):

```
0041a704  LEA EDX,[EDI + 0xe8]             ; CAS gate on the object's own +0xe8 field
0041a739  E8E23A0000  CALL 0x0041e220      ; DIRECT call — site #2 of the e220 inventory
0041a768  E8B33A0000  CALL 0x0041e220      ; DIRECT call — site #3
0041a7e8  CALL 0x00415f80                 ; 1st helper
0041a7ee  PUSH EDI ; 0041a7ef PUSH EDX ; 0041a7f1 E88A3A0000 CALL 0x0041e280   ; DIRECT call — site #3 of the e280 inventory
```

## 3. Resolution of the four hypotheses

| Hypothesis | Verdict |
|---|---|
| 1. `FUN_004230c0` directly calls `FUN_0041e280` | **TRUE — DIRECTLY VERIFIED.** `00423239` = `E842B0FFFF CALL 0x0041e280`; `CALL` target `0x0041e280`; references.jsonl carries the edge. |
| 2. It only calls `FUN_0041a6d0`, which then calls e280 | **FALSE** as an exclusive description. The path through `FUN_0041a6d0` exists and is real (`004231f7` → `0041a7f1`), **and** the direct site at `00423239` exists in the same fall-through. Both are direct, both verified. |
| 3. `00423239` was misattributed | **FALSE.** The instruction, its bytes, its target, and its references all corroborate each other. |
| 4. Reports confuse a parent path with a direct callsite | **PARTLY TRUE.** The confusion was never about the parent path vs. the site; it was **existence vs. reachability**. 8R logged the site ("CONFIRMED"), 8X/8W downgraded its **reachability** (via the `+0x214` gate) to "BLOCKED", and 8W's own graph then contradicted its table ("CONDITIONAL" vs "BLOCKED" for the same edge). No report ever produced evidence that the instruction does not exist; none could, because it does. |

## 4. `0041a7f1` — the "alleged e280 call"

- `0041a7f1` is **inside `FUN_0041a6d0`**, not inside `FUN_004230c0`: bytes `E88A3A0000` = `CALL 0x0041e280`. **DIRECTLY VERIFIED** in both the listing and `references.jsonl`.
- Reports that described "the e280 call at 0041a7f1" are describing the **callee's** direct call — not a call by `FUN_004230c0`.
- The relationship to the CMPXCHG at `00423157`: `0041a7f1` is reachable through (a) entering `FUN_004230c0` at `004230c0` with `EBX != 0` (`004230f2 JZ 0042326d`), (b) `[ESI+0x214] != 0` at `00423157` (else `JZ → 004232e2`), (c) the local `[EBP-0x14]` CAS chain, (d) returning through the `0041a770–0041a7f1` path inside `FUN_0041a6d0`. It is the **indirect path** from 230c0 to e280; `00423239` is the **direct** one.
- Both are unreachable through the gate under the same assumptions; neither instruction is absent, misplaced, or duplicated.

## 5. Gate semantics at `00423157` (verified)

```
0042314d  8D9614020000  LEA EDX,[ESI + 0x214]
00423153  33C9          XOR ECX,ECX
00423155  33C0          XOR EAX,EAX        ; accumulator = 0
00423157  F00FB10A      CMPXCHG.LOCK dword ptr [EDX],ECX
0042315b  85C0          TEST EAX,EAX        ; ZF=1 iff [ESI+0x214]==0
0042315d  0F95C0        SETNZ AL            ; AL = (ZF==0)?1:0  → AL=1 iff field was non-zero
00423160  84C0          TEST AL,AL
00423162  0F847A010000  JZ 0x004232e2       ; field==0 → failure cleanup path
```

- If `[ESI+0x214] == 0`: `CMPXCHG` writes ECX (0) into the field, EAX stays 0, ZF=1 → `SETNZ AL` yields AL=0 → `JZ` taken → skip to `004232e2` (failure). **The e280 call sites do not execute.**
- If `[ESI+0x214] != 0`: EAX←old field (non-zero), ZF=0 → AL=1 → `JZ` not taken → work block executes.
- Note the asymmetry vs the earlier claim: the gate is "if field is non-zero, proceed" — i.e., a **non-zero sentinel check**, not an "always-zero" check by itself. The "always-zero" part comes from the field being initialized to 0 once at construction and never again written non-zero — see `phase_9C_blocked_path_revalidation.md`.
- The `0042316c` second `CMPXCHG.LOCK [EDX],ECX` re-does the same operation immediately afterwards with the same accumulator; its result is unused by any branch (dead, atomic-RMW-with-0).

## 6. What actually differs between the reports

| Aspect | 8R caller table | 8W reachability graph | 8X object states | Phase 9C |
|---|---|---|---|---|
| Existence of `00423239` | yes | yes | yes | **yes — DIRECTLY VERIFIED** |
| Classification | CONFIRMED (reachability n/a) | "CONDITIONAL" (graph) / "BLOCKED" (table) | BLOCKED | **BLOCKED UNDER EXPLICIT ASSUMPTIONS** |
| What was proven | bytes, refs | nothing new | "no nonzero write found" | explicit assumption list; the branch and the write inventory are now both airtight |
| Residual risk | none for existence | none | the "always-0" premise is unproven (external agents) | documented in `phase_9C_blocked_path_revalidation.md` §5 |

## 7. Conclusion

- `00423239` is **not** misattributed, **not** a parent path, and **not** a duplicate of the `FUN_0041a6d0` path. It is a genuine, direct, `E8` call from `FUN_004230c0` to `FUN_0041e280`.
- The previous phases did not disagree on the existence of the instruction — they disagreed on whether it can ever execute, and on how to label it. That disagreement is resolved here: the instruction exists (DIRECTLY VERIFIED) and is **blocked under explicit assumptions** (A1–A3 in `phase_9C_blocked_path_revalidation.md`); it is **not proven unreachable**.
- `0041a7f1` is in `FUN_0041a6d0` — a callee of `FUN_004230c0` — and is equally verified. `0041a7f1` is **not** "the e280 call of `FUN_004230c0`"; both sites coexist.
- `FUN_004230c0` is an e280 caller by exactly two paths (via `FUN_0041a6d0` and directly at `00423239`), both gated by `[this+0x214] != 0`.
