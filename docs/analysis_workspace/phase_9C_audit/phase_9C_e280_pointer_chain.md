# Phase 9C — Pointer Chain B: `FUN_0041e280` indirect call at `0041e2ee`

**Target instruction:** `0041e2ee  FF12  CALL dword ptr [EDX]` (`listing/0041e280.asm`)
**NOTE:** `FUN_0041e280` and `FUN_0041e220` share the *same dispatch skeleton*; they differ in the argument-mixing prologue and in the CAS2 replacement semantics. This chain is documented standalone — it is **not** a copy of the e220 chain, though the dereference sequence after the CAS gates is identical in shape.

## 1. Full instruction trace

```
0041e283  8B7D0800             CMP dword ptr [EBP + 0x8],0x0     ; arg1 != 0?
0041e287  53                   PUSH EBX
0041e288  56                   PUSH ESI
0041e289  8B750C               MOV ESI,dword ptr [EBP + 0xc]     ; ESI := arg2
0041e28d  57                   PUSH EDI
0041e28d  8BF9                 MOV EDI,ECX                       ; EDI := this = ECX (caller)
0041e28f  7508                 JNZ 0x0041e299                    ; arg1 != 0 → BL=1
0041e291  85F6                 TEST ESI,ESI                      ; arg2 == 0?
0041e293  7504                 JNZ 0x0041e299                    ; arg2 != 0 → BL=1
0041e295  32DB                 XOR BL,BL                         ; BL := 0 (both args zero)
0041e297  EB02                 JMP 0x0041e29b
0041e299  B301                 MOV BL,0x1                        ; BL := 1
0041e29b  8D5704               LEA EDX,[EDI + 0x4]               ; EDX := &[this+0x04]
0041e29e  B93F420F00           MOV ECX,0xf423f                   ; CAS1 replacement sentinel
0041e2a3  33C0                 XOR EAX,EAX
0041e2a5  F00FB10A             CMPXCHG.LOCK dword ptr [EDX],ECX  ; CAS1: [this+0x04] vs 0
0041e2a9  BA01000000           MOV EDX,0x1                       ; CAS2 replacement = 1 (kept in EDX)
0041e2ae  85C0                 TEST EAX,EAX
0041e2b0  751A                 JNZ 0x0041e2cc                    ; if old [this+0x04] != 0 skip
0041e2b2  84DB                 TEST BL,BL
0041e2b4  B905000000           MOV ECX,0x5                       ; default = 5
0041e2b9  0F45CE               CMOVNZ ECX,ESI                    ; ECX := (BL != 0) ? arg2 : 5
0041e2bc  8D7704               LEA ESI,[EDI + 0x4]               ; ESI := &[this+0x04] (again)
0041e2bf  8D4604               LEA EAX,[ESI + 0x4]               ; EAX := &[this+0x08]
0041e2c2  8708                 XCHG dword ptr [EAX],ECX          ; [this+0x08] ↔ (BL? arg2 : 5)
0041e2c4  8BC2                 MOV EAX,EDX                       ; EAX := 1
0041e2c6  0F454508             CMOVNZ EAX,dword ptr [EBP + 0x8]  ; EAX := (BL != 0) ? arg1 : 1
0041e2ca  8706                 XCHG dword ptr [ESI],EAX          ; [this+0x04] ↔ (BL? arg1 : 1)
0041e2cc  8D4F10               LEA ECX,[EDI + 0x10]              ; ECX := &[this+0x10]
0041e2cf  33C0                 XOR EAX,EAX
0041e2d1  F00FB111             CMPXCHG.LOCK dword ptr [ECX],EDX  ; CAS2: [this+0x10] vs 0 → store 1
0041e2d5  85C0                 TEST EAX,EAX
0041e2d7  751E                 JNZ 0x0041e2f7                    ; if old [this+0x10] != 0 skip
0041e2d9  FF1580725100         CALL dword ptr [0x00517280]        ; GetLastError (IAT 0x00517280; verified PE → KERNEL32.DLL::GetLastError, hint 0x264=612)
0041e2df  8B4F0C               MOV ECX,dword ptr [EDI + 0xc]      ; P := [this+0x0C]
0041e2e2  8BF0                 MOV ESI,EAX                        ; ESI := GetLastError (saved)
0041e2e4  8B4904               MOV ECX,dword ptr [ECX + 0x4]      ; D := [P + 0x04]
0041e2e7  83C10C               ADD ECX,0xc                        ; ECX := D + 0x0C
0041e2ea  03CF                 ADD ECX,EDI                        ; A  := D + 0x0C + EDI
0041e2ec  8B11                 MOV EDX,dword ptr [ECX]            ; V  := [A]
0041e2ee  FF12                 CALL dword ptr [EDX]               ; CALL [V]
0041e2f0  56                   PUSH ESI
0041e2f1  FF1560725100         CALL dword ptr [0x00517260]        ; SetLastError (IAT 0x00517260; verified PE → KERNEL32.DLL::SetLastError, hint 0x534=1332)
0041e2f7  5F ; 5E ; 5B ; 5D ; C20800 RET 0x8
```

## 2. Pointer expression (in order of dereference)

| Step | Register | Expression |
|---|---|---|
| 1 | `EDI` | `this` — caller-supplied `ECX`; adjusted sub-object (Group A: `base+0x28`, Group B `base+0x10`, Group C `base+0x08`) |
| 2 | `ECX` / `P` | `P = [EDI + 0x0C]` |
| 3 | `ECX` / `D` | `D = [P + 0x04]` |
| 4 | `ECX` / `A` | `A = EDI + D + 0x0C` |
| 5 | `EDX` / `V` | `V = [A]` |
| 6 | target | `[V]` |

Identical in shape to Chain A: `target = *(*(EDI + *(P+4) + 0x0C))` with `P = *(EDI + 0x0C)`.

## 3. Differences from Chain A (must not be merged)

| Aspect | e220 (Chain A) | e280 (Chain B) |
|---|---|---|
| Argument semantics | arg1 → raw swap value (`XCHG [ESI+4], arg1`-ish); constant `0x6` | blends arg1/arg2/`5`/`1` via `BL` (`CMOVNZ` chains) |
| CAS1 replacement | `0xf423f` | `0xf423f` |
| CAS2 replacement | `0x1` | `0x1` |
| CAS1-success `[this+0x8]` write | arg1 (raw) | `BL ? arg2 : 5` |
| CAS1-success `[this+0x4]` write | arg1 (raw) | `BL ? arg1 : 1` |
| CAS1 failure (old≠0) | skip block, same as e220 ✓ | same |
| `RET` semantics | `RET 0x4` | `RET 0x8` |
| Argument count | 1 `[EBP+0x8]` | 2 `[EBP+0x8]`, `[EBP+0xc]` |
| SetLastError/GetLastError flow | identical | identical |

## 4. Provenance and resolvability

- `EDI` — adjusted sub-object pointer; statically only per-group.
- `P = [EDI+0x0C]` — **no producer in the export attributed to dispatch objects** (verified the full constructor store list; `[EDI+0x0C]` never initialized). Runtime pointer — unresolvable statically.
- `D = [P+0x04]` — runtime pointer — unresolvable statically.
- `V`, `target` — depend on D — unresolvable statically.
- Both `GetLastError`/`SetLastError` slots are static and verified against the PE import directory (not the export's own resolution).
- The object passed as `EDI` for the **Group A** dispatchers is `base+0x28`; `base+0x28`-family CAS1/CAS2 fields (`base+0x2c` CAS1? no — Group A CAS1 is `base+0x2C` i.e. `EDI+0x04` with EDI=base+0x28 → field at base+0x2C ✓ consistent with Phase-8 Group A table, with CAS2 at base+0x38, P at base+0x34).

## 5. Gates and reachability

- CAS2 gate at `0041e2d1` (`jnz 0041e2f7`) — if `[this+0x10] != 0`, skip work block.
- CAS1 gate at `0041e2a5` (`jnz 0041e2cc`) — if `[this+0x04] != 0`, skip the conditional CAS1-success block (but CAS2 still runs).
- Heap-garbage note: `[this+0x04]`/`[this+0x10]` are undefined for fresh HeapAlloc objects (allocator flag 0x0); CAS behavior on garbage is undetermined — per-instance UNKNOWN, statistically likely non-zero → dispatch skipped. **This is not provable statically; EVERY conditional caller shares it.**

## 6. Writers / producers

- Writers to `[reg+0x0C]` (as a class): 403 sites, dominated by `[EBP+0x0C]` frame slots; none provably attributes to a dispatch object (no dataflow isolation possible in this export).
- Writers to `[reg+0x04]` (as a class): scale similar; the only in-export store into an adjusted-dispatcher's N2-adjacent field in the CAS family is the dispatch CAS1-success block itself (`0041e2ca XCHG [ESI],EAX`), writing the blended constant — this writes `[this+0x04]`, not `P`.
- `P` and `D`: **no attributed writer found** — not proven never (out-of-export writers excluded); treat as UNRESOLVED.

## 7. Assessment

- The chain is **mechanically complete** and transferable verbatim between e220/e280 **only** after substituting the argument-prologue — but the mission-level lesson is that the two functions share the dereference sequence while differing in the state transitions; they must not be merged into one model.
- Target: **not statically resolvable**.
- All conditionally-reachable e280 callers inherit the gates and the heap-garbage caveat; Phase 8X's "22 callsites, 21 unique callers" holds.
