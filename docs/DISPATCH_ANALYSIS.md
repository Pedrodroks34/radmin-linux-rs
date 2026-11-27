# Dispatch Analysis — Consolidated Report (Phase 2.5 + Phase 9C/9D audits)

**Compiled by:** Docs subagent (task 1.8)
**Source set:** 38 files mapped to `DISPATCH_ANALYSIS` in `analysis_workspace/compaction/mapping.tsv`
**Scope:** All dispatcher-family findings across Phase 2.5 (16 reports) and the Phase 9C / Phase 9D audits (11 reports each).

## Method and scope note

Two distinct binaries appear in the source corpus, and they are kept separate in this consolidation:

- **Phase 9C / Phase 9D:** `RvControlSvc.exe`, SHA-256 `546efad9ab3ff85c2a50d61524d754bec94a3f3e30d6ae8addef481a1e8daa1e`, Ghidra export `ghidra_export/` (6,904 listings, 355,346 instructions, 152,681 references), ImageBase `0x00400000`. This is the binary whose dispatcher family (`FUN_0041e220`, `FUN_0041e280`, `FUN_00416650`, e220/e280/e16650 chains, Group A/B/C object classes, `+0x214` gates) is documented here.
- **Phase 2.5:** `RvControlSvc_Installed.exe`, SHA-256 `0e2e6eaacbe8ebe01286cda39a12eaad34a20434d50f4f8bf2fdd91d4d6ef2ad`, a different PE (vptr transitions `0x51FFB4 → 0x51E570 → 0x51E4F0`, `FUN_0043E1A0`/`FUN_0044F3F0`/`FUN_00473210`). Its findings are a separate static analysis and are marked as such where they appear.

Every fact below is traced to at least one source file; no packet fields, ports, algorithms, key sizes, server addresses, or IP ranges were invented. Where Phase 9C/9D corrected earlier Phase 8 reports, the correction is recorded in §Corrections and in the Provenance note (see `RECONCILIATION.md` for the full discrepancy trail).

---

## 1. vptr / dispatch state

### 1.1 Dispatcher family functions (Phase 9C/9D binary)

| Function | Role | Status |
|---|---|---|
| `FUN_0041e220` | Dispatcher Chain A; indirect `CALL dword ptr [EDX]` at `0041e26f` | 15 callsites / 14 unique callers; target **not statically resolvable** |
| `FUN_0041e280` | Dispatcher Chain B; indirect `CALL dword ptr [EDX]` at `0041e2ee` | 22 callsites / 21 unique callers; target **not statically resolvable** |
| `FUN_00416650` | Dispatcher Chain C; indirect `CALL dword ptr [EDX+0x0C]` at `0041693f` | 1 callsite / 1 unique caller (`FUN_00415300` @ `00415585`); target **statically resolvable** to `FUN_00479d80` |

### 1.2 Callsite reference counts (Phase 9C)

| Target | Callsites | Unique callers | Caller appears twice | All `E8` direct `CALL` |
|---|---|---|---|---|
| `FUN_0041e220` | 15 | 14 | `FUN_0041a6d0` (sites #2, #3) | yes |
| `FUN_0041e280` | 22 | 21 | `FUN_0041d380` (sites #8, #9) | yes |
| `FUN_00416650` | 1 | 1 | — | yes |

### 1.3 e280 caller adjustment matrix (Phase 9D §2a)

The e280 callers pass `this` with different adjustments; Group B (+0x10) does **not** appear at any e280 callsite.

| Callsite | Caller | Adjustment | Class hint |
|---|---|---|---|
| 00419bce | FUN_00419b30 | raw `this` (`MOV ECX,ESI`) | unknown |
| 0041a6b2 | FUN_0041a640 | raw | unknown |
| 0041a7f1 | FUN_0041a6d0 | raw (`EBX = [EBP+0x8]`) | FUN_00417850-class family |
| 0041aaee | FUN_0041aa40 | `+0x28` (Group A) | — |
| 0041b2a1 | FUN_0041b1e0 | raw (`EBX`) | FUN_00417850-class family |
| 0041c3fd | FUN_0041c300 | raw (`MOV ECX,[EBP+0x8]`) | unknown |
| 0041c8df | FUN_0041c870 | raw (`ESI`) | unknown |
| 0041d438 | FUN_0041d380 | `+0x28` (Group A) | — |
| 0041d468 | FUN_0041d380 | `+0x28` (Group A) | — |
| 0041d757 | FUN_0041d6e0 | raw (`EBX`) | FUN_00417850-class family |
| 0041d87e | FUN_0041d770 | raw (`EBX`) | FUN_00417850-class family |
| 0041dec2 | FUN_0041de60 | `+0x20` (**new slot**) | — |
| 0041e20d | FUN_0041e1f0 | raw (`EBX`) | FUN_00417850-class family |
| 0041e457 | FUN_0041e360 | raw (`EDI`) | unknown |
| 0041f67e | FUN_0041f450 | raw (`EBX`) | FUN_00417850-class family |
| 004229d9 | FUN_00422840 | raw (`EBX`) | FUN_00417850-class family |
| 00422ed0 | FUN_00422e00 | `+0x60` (**new slot**) | — |
| 00423239 | FUN_004230c0 | raw (`EBX`) | FUN_00417850-class family |
| 00423ad2 | FUN_00423980 | raw (`MOV ECX,[EBP+0x8]`) | unknown |
| 0042411c | FUN_004240f0 | `+0x60` (**new slot**) | — |
| 0042f889 | FUN_0042f810 | `+0x08` (Group C) | — |
| 0043057d | FUN_00430510 | raw (`ESI`) | unknown |

Summary: three callers adjust by +0x28 (`0041aa40`, `0041d380`×2), one by +0x08 (`0042f810`), two by +0x60 (`00422e00`, `004240f0`), one by +0x20 (`0041de60`), 16 pass raw `this` unchanged.

### 1.4 Reference reconciliation (Phase 9C)

`is_call=true` total is **32,848** = 27,770 `UNCONDITIONAL_CALL` + 5,075 `COMPUTED_CALL` + 3 `COMPUTED_CALL_TERMINATOR`. Earlier reports that stated `27,770 + 5,075` omitted the three `COMPUTED_CALL_TERMINATOR` records; no other type carries `is_call=true`. Machine-level `CALL` instructions number 30,338 (25,260 direct `E8` + 5,074 indirect with listing line + 3 terminators + 1 from outside non-analyzed code); 1,227 of the flagged records are direct `JMP` tail calls and 1,284 originate from outside analyzed bodies. Every one of the 38 dispatcher callsites is logged exactly once in `references.jsonl`. 33,329 `DATA` records (12,394 `LEA`, 8,881 `PUSH` of function VAs) are address materializations, not calls.

---

## 2. Callsite inventories (Phase 9C, rebuilt from `references.jsonl` + byte verification)

Every site is a direct `CALL 0x…` (`E8 rel32`); no `JMP`-tail, no computed call, no terminator appears among the 38 sites.

### 2.1 FUN_0041e220 — 15 callsites / 14 unique callers

| # | Caller | Callsite | Bytes | Reachability (Phase 9C) |
|---|---|---|---|---|
| 1 | FUN_00419e20 | 00419e9b | `E880430000` | BLOCKED UNDER EXPLICIT ASSUMPTIONS (via FUN_00422f20 gate) |
| 2 | FUN_0041a6d0 | 0041a739 | `E8E23A0000` | BLOCKED UNDER EXPLICIT ASSUMPTIONS (via FUN_004230c0 gate) |
| 3 | FUN_0041a6d0 | 0041a768 | `E8B33A0000` | BLOCKED UNDER EXPLICIT ASSUMPTIONS (same gate) |
| 4 | FUN_0041ae30 | 0041b05a | `E8C1310000` | CONDITIONAL |
| 5 | FUN_0041b090 | 0041b125 | `E8F6300000` | CONDITIONAL |
| 6 | FUN_0041b140 | 0041b1cc | `E84F300000` | CONDITIONAL |
| 7 | FUN_0041b2f0 | 0041b370 | `E8AB2E0000` | CONDITIONAL |
| 8 | FUN_0041bb40 | 0041bd36 | `E8E5240000` | CONDITIONAL |
| 9 | FUN_0041bd70 | 0041c03a | `E8E1210000` | CONDITIONAL |
| 10 | FUN_0041df70 | 0041e025 | `E8F6010000` | CONDITIONAL |
| 11 | FUN_0041f710 | 0041f80e | `E80DEAFFFF` | CONDITIONAL (incoming) |
| 12 | FUN_0041fa80 | 0041fc6e | `E8ADE5FFFF` | CONDITIONAL (incoming) |
| 13 | FUN_00420b80 | 00420c7b | `E8A0D5FFFF` | UNKNOWN (0 incoming refs) → corrected by Phase 9D (see §Corrections) |
| 14 | FUN_0041f110 | 0041f3b1 | `E86AEEFFFF` | UNKNOWN (0 incoming refs) → retained (see §Corrections) |
| 15 | FUN_0041f450 | 0041f6dd | `E83EEBFFFF` | CONDITIONAL |

### 2.2 FUN_0041e280 — 22 callsites / 21 unique callers

| # | Caller | Callsite | Bytes | Reachability |
|---|---|---|---|---|
| 1 | FUN_00419b30 | 00419bce | `E8AD460000` | CONDITIONAL |
| 2 | FUN_0041a640 | 0041a6b2 | `E8C93B0000` | CONDITIONAL |
| 3 | FUN_0041a6d0 | 0041a7f1 | `E88A3A0000` | BLOCKED UNDER EXPLICIT ASSUMPTIONS (via FUN_004230c0 gate) |
| 4 | FUN_0041aa40 | 0041aaee | `E88D370000` | CONDITIONAL |
| 5 | FUN_0041b1e0 | 0041b2a1 | `E8DA2F0000` | CONDITIONAL |
| 6 | FUN_0041c300 | 0041c3fd | `E87E1E0000` | CONDITIONAL |
| 7 | FUN_0041c870 | 0041c8df | `E89C190000` | CONDITIONAL |
| 8 | FUN_0041d380 | 0041d438 | `E8430E0000` | CONDITIONAL |
| 9 | FUN_0041d380 | 0041d468 | `E8130E0000` | CONDITIONAL |
| 10 | FUN_0041d6e0 | 0041d757 | `E8240B0000` | CONDITIONAL |
| 11 | FUN_0041d770 | 0041d87e | `E8FD090000` | CONDITIONAL |
| 12 | FUN_0041de60 | 0041dec2 | `E8B9030000` | CONDITIONAL |
| 13 | FUN_0041e1f0 | 0041e20d | `E86E000000` | CONDITIONAL (wrapper; called from exactly 3 sites: `FUN_0041ae30`@0041b043, `FUN_0041bb40`@0041bc76, `FUN_0041bd70`@0041bed2) |
| 14 | FUN_0041e360 | 0041e457 | `E824FEFFFF` | CONDITIONAL (incoming) |
| 15 | FUN_0041f450 | 0041f67e | `E8FDEBFFFF` | CONDITIONAL (incoming) |
| 16 | FUN_00422840 | 004229d9 | `E8A2B8FFFF` | CONDITIONAL (incoming) |
| 17 | FUN_00422e00 | 00422ed0 | `E8ABB3FFFF` | CONDITIONAL (incoming) |
| 18 | FUN_004230c0 | 00423239 | `E842B0FFFF` | BLOCKED UNDER EXPLICIT ASSUMPTIONS (same gate) |
| 19 | FUN_00423980 | 00423ad2 | `E8A9A7FFFF` | CONDITIONAL |
| 20 | FUN_004240f0 | 0042411c | `E85FA1FFFF` | CONDITIONAL |
| 21 | FUN_0042f810 | 0042f889 | `E8F2E9FEFF` | CONDITIONAL |
| 22 | FUN_00430510 | 0043057d | `E8FEDCFEFF` | CONDITIONAL |

### 2.3 FUN_00416650 — 1 callsite / 1 unique caller

| # | Caller | Callsite | Bytes |
|---|---|---|---|
| 1 | FUN_00415300 | 00415585 | `E8C6100000` |

---

## 3. Pointer chains P / D / V

Three chains share a dereference skeleton but have different argument prologues, return widths, and resolvability; they were **not merged** (Phase 9C §3 answer 4, §B7).

### 3.1 Chain A — FUN_0041e220 indirect call at `0041e26f`

Target instruction: `0041e26f  FF12  CALL dword ptr [EDX]` (`listing/0041e220.asm`).

Register trace (every register definition reaching the call):

```
0041e225  MOV EDI,ECX              ; EDI := this (dispatching object; Group A callers pass base+0x28)
0041e227  MOV EDX,0xf423f          ; CAS1 replacement sentinel
0041e22c  XOR EAX,EAX              ; accumulator = 0
0041e22e  LEA ESI,[EDI + 0x4]      ; ESI := &[this+0x04]
0041e231  CMPXCHG.LOCK dword ptr [ESI],EDX   ; CAS1: [this+0x04] vs 0 → store 0x000f423f
0041e235  TEST EAX,EAX
0041e237  JNZ 0x0041e248           ; if old [this+0x04] != 0, skip CAS1-success block
0041e239  MOV ECX,dword ptr [EBP + 0x8]   ; ECX := arg1
0041e23c  LEA EAX,[ESI + 0x4]      ; EAX := &[this+0x08]
0041e23f  XCHG dword ptr [EAX],ECX           ; [this+0x08] ↔ arg1
0041e241  MOV EAX,0x6              ; replacement = 6
0041e246  XCHG dword ptr [ESI],EAX           ; [this+0x04] ↔ 6
0041e248  MOV EDX,0x1              ; CAS2 replacement = 1
0041e24d  LEA ECX,[EDI + 0x10]     ; ECX := &[this+0x10]
0041e250  XOR EAX,EAX              ; accumulator = 0
0041e252  CMPXCHG.LOCK dword ptr [ECX],EDX ; CAS2: [this+0x10] vs 0 → store 1
0041e256  TEST EAX,EAX
0041e258  JNZ 0x0041e278           ; if old [this+0x10] != 0, skip work block
0041e25a  CALL dword ptr [0x00517280]  ; GetLastError (IAT 0x00517280, hint 0x264=612)
0041e260  MOV ECX,dword ptr [EDI + 0xc]     ; P := [this+0x0C]
0041e263  MOV ESI,EAX              ; ESI := GetLastError result (saved)
0041e265  MOV ECX,dword ptr [ECX + 0x4]     ; D := [P + 0x04]
0041e268  ADD ECX,0xc              ; ECX := D + 0x0C
0041e26b  ADD ECX,EDI              ; A  := D + 0x0C + EDI
0041e26d  MOV EDX,dword ptr [ECX]  ; V  := [A]
0041e26f  CALL dword ptr [EDX]     ; CALL [V]
0041e271  PUSH ESI                 ; PUSH GetLastError result
0041e272  CALL dword ptr [0x00517260]  ; SetLastError (IAT 0x00517260, hint 0x534=1332)
0041e278  POP EDI ; POP ESI ; POP EBP ; RET 0x4
```

Pointer expression (order of dereference):

| Step | Register | Expression |
|---|---|---|
| 1 | `EDI` | `this` (caller-supplied ECX at entry) |
| 2 | `ECX`/`P` | `P = [EDI + 0x0C]` |
| 3 | `ECX`/`D` | `D = [P + 0x04]` |
| 4 | `ECX`/`A` | `A = EDI + D + 0x0C` |
| 5 | `EDX`/`V` | `V = [A]` |
| 6 | target | `[V]` |

Target: `target = *(*(EDI + *(P+4) + 0x0C))` with `P = *(EDI + 0x0C)`. **Not statically resolvable** — no static producer for `P` attributed to dispatch objects (403 `[reg+0x0C]` store sites surveyed, none provably tied to dispatch objects); no export code provably writes `[P+0x04]`.

### 3.2 Chain B — FUN_0041e280 indirect call at `0041e2ee`

Target instruction: `0041e2ee  FF12  CALL dword ptr [EDX]` (`listing/0041e280.asm`). Same dereference shape as Chain A; differs only in argument-mixing prologue and CAS2 replacement semantics.

Register trace:

```
0041e283  CMP dword ptr [EBP + 0x8],0x0     ; arg1 != 0?
0041e287  PUSH EBX
0041e288  PUSH ESI
0041e289  MOV ESI,dword ptr [EBP + 0xc]     ; ESI := arg2
0041e28d  PUSH EDI
0041e28d  MOV EDI,ECX                       ; EDI := this = ECX
0041e28f  JNZ 0x0041e299                    ; arg1 != 0 → BL=1
0041e291  TEST ESI,ESI                      ; arg2 == 0?
0041e293  JNZ 0x0041e299                    ; arg2 != 0 → BL=1
0041e295  XOR BL,BL                         ; BL := 0 (both args zero)
0041e297  JMP 0x0041e29b
0041e299  MOV BL,0x1                        ; BL := 1
0041e29b  LEA EDX,[EDI + 0x4]               ; EDX := &[this+0x04]
0041e29e  MOV ECX,0xf423f                   ; CAS1 replacement sentinel
0041e2a3  XOR EAX,EAX
0041e2a5  CMPXCHG.LOCK dword ptr [EDX],ECX ; CAS1: [this+0x04] vs 0
0041e2a9  MOV EDX,0x1                       ; CAS2 replacement = 1
0041e2ae  TEST EAX,EAX
0041e2b0  JNZ 0x0041e2cc                    ; if old [this+0x04] != 0 skip
0041e2b2  TEST BL,BL
0041e2b4  MOV ECX,0x5                       ; default = 5
0041e2b9  CMOVNZ ECX,ESI                    ; ECX := (BL != 0) ? arg2 : 5
0041e2bc  LEA ESI,[EDI + 0x4]               ; ESI := &[this+0x04]
0041e2bf  LEA EAX,[ESI + 0x4]               ; EAX := &[this+0x08]
0041e2c2  XCHG dword ptr [EAX],ECX          ; [this+0x08] ↔ (BL ? arg2 : 5)
0041e2c4  MOV EAX,EDX                       ; EAX := 1
0041e2c6  CMOVNZ EAX,dword ptr [EBP + 0x8]  ; EAX := (BL != 0) ? arg1 : 1
0041e2ca  XCHG dword ptr [ESI],EAX          ; [this+0x04] ↔ (BL ? arg1 : 1)
0041e2cc  LEA ECX,[EDI + 0x10]              ; ECX := &[this+0x10]
0041e2cf  XOR EAX,EAX
0041e2d1  CMPXCHG.LOCK dword ptr [ECX],EDX  ; CAS2: [this+0x10] vs 0 → store 1
0041e2d5  TEST EAX,EAX
0041e2d7  JNZ 0x0041e2f7                    ; if old [this+0x10] != 0 skip
0041e2d9  CALL dword ptr [0x00517280]       ; GetLastError
0041e2df  MOV ECX,dword ptr [EDI + 0xc]     ; P := [this+0x0C]
0041e2e2  MOV ESI,EAX
0041e2e4  MOV ECX,dword ptr [ECX + 0x4]     ; D := [P + 0x04]
0041e2e7  ADD ECX,0xc                       ; ECX := D + 0x0C
0041e2ea  ADD ECX,EDI                       ; A  := D + 0x0C + EDI
0041e2ec  MOV EDX,dword ptr [ECX]           ; V  := [A]
0041e2ee  CALL dword ptr [EDX]              ; CALL [V]
0041e2f0  PUSH ESI
0041e2f1  CALL dword ptr [0x00517260]       ; SetLastError
0041e2f7  POP EDI ; POP ESI ; POP EBX ; POP EBP ; RET 0x8
```

| Aspect | e220 (Chain A) | e280 (Chain B) |
|---|---|---|
| Argument semantics | arg1 → raw swap value; constant `0x6` | blends arg1/arg2/`5`/`1` via `BL` (`CMOVNZ`) |
| CAS1 replacement | `0xf423f` | `0xf423f` |
| CAS2 replacement | `0x1` | `0x1` |
| CAS1-success `[this+0x8]` write | arg1 (raw) | `BL ? arg2 : 5` |
| CAS1-success `[this+0x4]` write | arg1 (raw) | `BL ? arg1 : 1` |
| RET | `RET 0x4` | `RET 0x8` |
| Argument count | 1 (`[EBP+0x8]`) | 2 (`[EBP+0x8]`, `[EBP+0xc]`) |

**Not statically resolvable** (same reasons as Chain A).

### 3.3 Chain C — FUN_00416650 indirect call at `0041693f`

Target instruction: `0041693f  FF520C  CALL dword ptr [EDX + 0x0C]` (`listing/00416650.asm`). One dereference level shallower than Chains A/B; field at `+0x08` instead of `+0x0C`; uniquely among the three, a static producer for the pointer exists on the two constructor-set tables.

Register trace:

```
00416664  MOV EBX,ECX                 ; EBX := this
…
00416936  MOV EDX,dword ptr [EBX + 0x8]     ; EDX := P16650 = [this + 0x08]
00416939  LEA ECX,[EBX + 0x8]             ; ECX := &[this + 0x08]
0041693c  PUSH 0x1
0041693e  PUSH EAX                      ; push CAS result (old local)
0041693f  CALL dword ptr [EDX + 0xc]    ; CALL [[this+0x08] + 0x0C]
```

Pointer expression:

| Step | Register | Expression |
|---|---|---|
| 1 | `EBX` | `this` (ECX at entry, `00416664`) |
| 2 | `EDX`/`P16650` | `P16650 = [EBX + 0x08]` |
| 3 | `ECX` | `A16650 = &[this + 0x08]` |
| 4 | target | `[P16650 + 0x0C]` i.e. `target = *((*(EBX+0x08)) + 0x0C)` |

**Statically resolvable:** constructor `FUN_00421410` writes `[EDI + 0x8]` := `0x00519dac` (path via `004214da`) or `0x0051b254` (path via `0042155b`); both `.rdata` tables store `0x00479d80` at `+0x0C` (`0x00519db8`, `0x0051b260`). Target = `0x00479d80` = `FUN_00479d80` (thiscall, 251 bytes). Conditional on constructor-path object identity; proven at instruction level, not dynamically observed.

### 3.4 Chain differences (must not be merged)

| | e16650 (Chain C) | e220 (Chain A) | e280 (Chain B) |
|---|---|---|---|
| Instruction | `CALL [EDX + 0x0C]` | `CALL [EDX]` | `CALL [EDX]` |
| Adjusted EDI | `obj + 0x08` | `obj + 0x28` (A) / `obj + 0x10` (B) / `obj + 0x08` (C) | same as A |
| P | `[EDI + 0x08]` — **static** `0x00519dac`/`0x0051b254` | `[base+0x34]` A `0x0051aee0` / `[base+0x1c]` B `0x0051b01c` / `[base+0x14]` C `0x0` | identical |
| D | `[P + 0x0C]` — **pointer** `0x00479d80` | `[P + 0x04]` — **offset** `0x210` / `0x2b0` — literal integer | identical |
| A | `obj + 0x0C` relative (no further pointer hop) | `EDI + D + 0x0C` — object-relative | identical |
| Final target | `0x00479d80` (`_guard_check_icall` thunk) | `0x004e7650` (CFG-instrumented global-callback dispatch stub, reads `[0x005a5a54]`) | identical |
| Runtime callback | static symbol | `[0x005a5a54] = 0x004dd190` — runtime-registered at 4 callsites | identical |

Mechanistic note (Phase 9D): e220/e280 are more-involved e16650-style dispatches — constructor-installed static `.rdata` tables in both cases; e220/e280 read an RTTI-COL-like structure (P = COL pointer, D = vbase offset, A = object + offset, V = [A], target = [V]) versus e16650's single-pointer-hop vtable read. Both ultimately route through compiler CFG machinery (`FUN_004e7650` for e220/e280; `FUN_00479d80` for e16650), not application logic.

---

## 4. Object classes and lifecycles (Phase 9D)

### 4.1 Class identity matrix

| Attribute | FUN_00421410-class | FUN_00417850-class | FUN_0041ea00-class |
|---|---|---|---|
| Allocation size | 0x258 = 600 B | 0x2d0 = 720 B | 0x2d0 = 720 B |
| Constructor | `FUN_00421410` | `FUN_00417850` | `FUN_0041ea00` |
| Created by | `FUN_0042d980` (via `0042daf2`) | `FUN_00424550` (via `004245f6`) | `FUN_00417850` (via `00417bc6`) |
| Creator allocation call | `0042d2f8`/`0042d3f6` | `00422230`/`00422340` | `00417bc6` |
| Allocation path | `FUN_004e5a66 → FUN_004018a0 → __malloc_base → HeapAlloc(0x005a61a0, 0, size)` — flag 0, memory **not zeroed** | same | same |
| Primary vtable | `0x0051b248` | `0x0051ae28` | `0x0051afd8` |
| Secondary vtable | `0x0051b254` | `0x0051ae30` | `0x0051afe0` |
| Sub-object vtable | `0x0051a984` | `0x0051ae44` | `0x0051b004` |
| Group A active? | No | **Yes** | No |
| Group B active? | No | No | **Yes** |
| Group C active? | No | No | **Yes** (dead path) |
| `+0x214` gate context | **Yes — this class** (`FUN_00422f20`, `FUN_004230c0`) | No | No |
| e220/e280 directly routed | No | Yes (e220: 10 callers, e280: 0 direct) | Yes (e280: 22 callers, e220: 2 direct) |
| Final indirect target | n/a | `FUN_004e7650` | `FUN_004e7650` |

### 4.2 Class hierarchy

```
Radmin Service (process)
 └── FUN_00421410-class (parent)            size 0x258  [the +0x214 gate family]
       └── FUN_00417850-class (child)       size 0x2d0  [Group A object]
             └── FUN_0041ea00-class (grandchild) size 0x2d0  [Group B/C object]
```

Constructor call graph:

```
ServiceEntry → FUN_0042d980 → FUN_00421410  (parent; writes [EDI+0x214] = 0 — B2 gate object)
FUN_00422260/FUN_00422150 → FUN_00424550 → FUN_00417850  (child; Group A constructor)
FUN_00417850 → FUN_0041ea00 (at 00417bc6)  (grandchild; Group B/C constructor)
```

### 4.3 Object-member store provenance

| Offset | FUN_00421410-class | FUN_00417850-class | FUN_0041ea00-class |
|---|---|---|---|
| `[obj+0x0]` | `0x0051b248` | `0x0051ae28` | `0x0051afd8` |
| `[obj+0x08]` | `0x0051b254` | `0x0051ae30` | `0x0051afe0` |
| `[obj+0x10]` | — (not written) | `0x0051ae44` | `0x0051b004` |
| `[obj+0x14]` | — | — | `0x00000000` |
| `[obj+0x18]` | — | — | `0x00000000` |
| `[obj+0x1c]` | — | — | `0x0051b01c` |
| `[obj+0x20]` | — | — | `0x00000000` |
| `[obj+0x28]` | — (NOT written) | `0x0051a984 → 0x0051ae58` | `0x0051b004`? |
| `[obj+0x2c]` | — (NOT written) | `0x00000000` | — |
| `[obj+0x34]` | — (NOT written) | `0x0051aee0` | — |
| `[obj+0x38]` | — (NOT written) | `0x00000000` | — |
| `[obj+0x214]` | `0x00000000` | — | — |
| `[obj+0x238]` | `0x00000000` (byte) | — | — |
| `[obj+0x244]` | — | `0x00519e54` | — |

FUN_00421410-class objects are **never** dispatched into the e220/e280 indirect chain (P fields never written → would fault); they route through `FUN_00422ce0` (envelope/message dispatcher, vtable at `0x0051b248` slot 1 = `0x00422ce0`).

### 4.4 Lifecycle chain (Phase 9D §4)

Group A:
```
parent (created by FUN_0042d980, gate = parent class)
   └── child (FUN_00424550 → FUN_00417850)        ← Group A object
         └── grandchild (FUN_00417850 → FUN_0041ea00)  ← Group B / Group C object
```

End-to-end Group A chain:
```
this ──vtable slot (0x0051ae34..0x0051ae38)
       └── FUN_0041df20   ← vtable slot [+0x10] at .rdata 0x0051ae38
             └── FUN_0041e090   (ECX = obj - 0x8)
                   └── FUN_0041ae30 → 0041b05a: e220 (LEA ECX,[EDI + 0x28])
                   └── FUN_0041bb40 → 0041bd36: e220 (LEA ECX,[EDI + 0x28])
                   └── FUN_0041bd70 → 0041c03a: e220 (LEA ECX,[EDI + 0x28])
                   └── FUN_0041e1f0 → e280 (CALL 0041e280)
```

Direct blockers: Group A e220 callers invoked from the vtable dispatch loop do **not** pass through the `+0x214` gates; the gates gate only the `FUN_00422ce0 → FUN_00422f20/004230c0` chain. `00423239` (the blocked path) is downstream of `FUN_004230c0`'s gate and cannot execute while the gate stands.

---

## 5. Static tables (Phase 9D §Static Tables Audit)

Every `.rdata` table referenced by a dispatcher instruction or a dispatch-object constructor:

### 5.1 `0x0051aee0` — RTTI CompleteObjectLocator-like table (P for Group A)
Referenced by: constructor `FUN_00417850` at `0041788e` (`MOV dword ptr [EBX + 0x34],0x0051aee0`).

```
0x0051aee0  fffffff4   offset-to-top = -12
0x0051aee4  00000210   ← D = 0x210 (528) for Group A
0x0051aee8  00000218
0x0051aeec  00000220
0x0051aef0  0000022c
0x0051aef4  00000238
0x0051aef8  00000000
0x0051aefc  00000208
0x0051af00  00000210
0x0051af04  0000021c
0x0051af08  fffffffc
```
Contains signed offsets, no function pointers; matches MSVC RTTI Complete Object Locator offset-table layout.

### 5.2 `0x0051b01c` / `0x0051b014` — RTTI CompleteObjectLocator layout (P Group B / CAS1 Group C)
Referenced by `FUN_0041ea00` at `0041ea3b` (`MOV dword ptr [EDI + 0x1c],0x0051b01c`) and `0041ea2d` (`MOV dword ptr [EDI + 0xc],0x0051b014`).

```
0x0051b014:  fffffffc
0x0051b018:  000002c0
0x0051b01c:  fffffff4   ← P (Group B)
0x0051b020:  000002b0   ← D = 0x2b0 (688) for Group B
0x0051b024:  74697277   "wirr" (ASCII)
0x0051b028:  00000065
0x0051b02c:  6e65706f   "open"
```

### 5.3 `0x00519e54` — universal target pointer
```
0x00519e54  004e7650   ← FUN_004e7650 (CFG-instrumented global-callback dispatch stub)
```
Referenced from `.rdata` from **219 call/data refs** — every entry matches a vtable slot position; `FUN_004e7650` is the universal slot filler / indirect-call trampoline for this binary. Group A and B chains resolve to `obj+0x244` / `obj+0x2cc` → `V = [obj+0x244|0x2cc] = 0x00519e54` → target `[V] = 0x004e7650`. Runtime target registered at `[0x005a5a54]` (currently `0x004dd190`, set at 4 callsites — 3 unconditional literal `0x004dd190`, 1 via runtime table).

### 5.4 `0x00519dac` / `0x0051b254` — e16650 tables (Chain C)
```
0x00519dac:  004048e5  00479fa0  00479d70  00479d80  ...   → [+0x0C] = 0x00479d80 (0x00519db8)
0x0051b254:  00421c8a  00479fa0  00479d70  00479d80  ...   → [+0x0C] = 0x00479d80 (0x0051b260)
```
Constructor `FUN_00421410` stores `[EDI + 0x8]` := `0x00519dac` (`004214f0`) or `0x0051b254` (`0042155b`); both tables store `FUN_00479d80` at `+0x0C`. Never written by any code (read-only `.rdata`).

### 5.5 Phase 2.5 tables (different binary — `RvControlSvc_Installed.exe`)
Table A base `0x51FFAC`, vptr transitions `0x51FFB4 → 0x51E570 → 0x51E4F0`; slot 13 (+0x34), slot 22 (+0x58). Targets:
- vptr `0x51FFB4`: slot 13 → `0x004510A0` (returns 0), slot 22 → `0x00450FA0` (body not analyzed)
- vptr `0x51E570`: slot 13 → `0x004510B0` (returns 16), slot 22 → `0x00450FC0` (body not analyzed)
- vptr `0x51E4F0`: slot 13 → `0x004510B0` (returns 16), slot 22 → `0x00450FC0` (body not analyzed)

Phase 2.4 errors corrected: Table A slot 13 at `0x51FFE8 → 0x4510A0` (not `0x51FFE0 → 0x451010`); slot 22 at `0x52000C → 0x450FA0` (not `0x520004 → 0x451070`); Table B/C slot 22 at `0x51E5C8`/`0x51E548 → 0x450FC0` (not `0x51E5C4`/`0x51E544 → 0x451090`).

### 5.6 PE section table (Phase 2.5 / Phase 9C binaries)
Phase 2.5 `RvControlSvc_Installed.exe`: `.text` `0x401000–0x519000`, `.rdata` `0x519000–0x54A000`, `.data` `0x54A000–0x5A9000`. `0x00500CA6` is in `.text` (RVA `0x100CA6`), not `.data` as Phase 2.4 Report 08 claimed; bytes are `free` function prologue (`8B FF 55 8B EC …`), and `CALL [0x00500CA6]` reads DWORD `0x8B55FF8B` (not a valid pointer) — anomalous, requires runtime validation.

---

## 6. CAS initialization (Phase 9D §CAS Initialization Matrix)

### 6.1 Class 1 — FUN_00417850-class (Group A direct dispatch object)

| Field | Offset | Classification | Evidence |
|---|---|---|---|
| Adjusted EDI | `obj + 0x28` | EXPLICIT STATIC | `[EBX + 0x28] = 0x0051a984` (temp) → `0x0051ae58` |
| CAS1 | `obj + 0x2c` | EXPLICIT STATIC ZERO | `MOV dword ptr [EBX + 0x2c],0x0` at `004179a1` |
| P | `obj + 0x34` | EXPLICIT STATIC | `0x0051aee0` at `0041788e` |
| CAS2 | `obj + 0x38` | EXPLICIT STATIC ZERO | `MOV dword ptr [EBX + 0x38],0x0` at `004179c1` |
| CAS1 witness | `obj + 0x30` | EXPLICIT STATIC ZERO | `[EBX + 0x30] = 0` at `004179a8` |
| Sub-vtable | `obj + 0x44` | EXPLICIT STATIC | `0x0051aef8` at `00417895` |
| Ladder slot | `obj + 0x244` | EXPLICIT STATIC | `0x00519e54` at `004178ba` |

Group A CAS state at creation: CAS1 = 0, CAS2 = 0 (static — not from allocation clearing).

### 6.2 Class 2 — FUN_0041ea00-class (Group B/C sub-object)

| Field | Offset | Classification | Evidence |
|---|---|---|---|
| Adjusted EDI | `obj + 0x10` | EXPLICIT STATIC | `0x0051b004` final / `0x0051a984` temp |
| CAS1 | `obj + 0x14` | EXPLICIT STATIC ZERO | `[EDI + 0x14] = 0` at `0041ea80` |
| P | `obj + 0x1c` | EXPLICIT STATIC | `0x0051b01c` at `0041ea3b` (path A) |
| CAS2 | `obj + 0x20` | EXPLICIT STATIC ZERO | `[EDI + 0x20] = 0` at `0041eaa3` |
| CAS1 alt | `obj + 0xc` | EXPLICIT STATIC (non-zero) | `0x0051b014` at `0041ea2d` (path A) |
| CAS2 alt | `obj + 0x18` | EXPLICIT STATIC ZERO | `[EDI + 0x18] = 0` at `0041ea8e` |
| Ladder slot | `obj + 0x2cc` | EXPLICIT STATIC | `0x00519e54` |

Group B CAS: CAS1 = 0, CAS2 = 0. Group C CAS: CAS1 = `0x0051b014` (non-zero, path A), CAS2 = 0.

### 6.3 Class 3 — FUN_00421410-class (+0x214-gate dispatch parent)

| Field | Offset | Classification | Evidence |
|---|---|---|---|
| +0x214 | `obj + 0x214` | EXPLICIT STATIC ZERO | `MOV dword ptr [EDI + 0x214],0x0` at `0042173b` (single direct store) |
| +0x218 | `obj + 0x218` | EXPLICIT STATIC ZERO | `[EDI + 0x218] = 0` at `00421745` |
| +0x1b0 | `obj + 0x1b0` | sub-init — `FUN_00479510` | indirect |
| +0x1c8 | `obj + 0x1c8` | sub-init — `FUN_00479510` | indirect |
| +0x20c | `obj + 0x20c` | XADD-CAS locked RMW | sets bit 0 to 1 via CAS in factory |
| +0x238 | `obj + 0x238` | EXPLICIT STATIC BYTE ZERO | `00417d42` region |

Group A/B/C-like fields in FUN_00421410-class objects are never initialized by design; these objects route through `FUN_00422ce0`, never into the e220/e280 indirect chain.

### 6.4 Dispatcher CAS behavior on first invocation (Phase 9D cross-reference)
With CAS fields zero at construction, e220's first dispatch passes CAS1 (`[this+0x04] == 0` → store arg1, set to 6) and CAS2 (`[this+0x10] == 0` → store 1), then reaches the target `V = FUN_004e7650`. The very next dispatch skips the CAS1-success block (`[this+0x04] != 0`) but CAS2 still passes; subsequent calls are no-ops (the gate refuses). Two invocations per object max: 1 full dispatch + 1 pre-completed.

---

## 7. Blocked paths (Phase 9C §Blocked Path Revalidation)

Five callsites reached through two `+0x214` gates; all classified **BLOCKED UNDER EXPLICIT ASSUMPTIONS** — none proven PROVEN BLOCKED.

| ID | Site | Dispatcher | Gate | Path |
|---|---|---|---|---|
| E1 | `00419e9b` | e220 (`FUN_0041e220`) | B1 | `FUN_00422ce0` → `00422f20` →(CAS `00422fa3`) `00423030` → `FUN_00419e20` → `00419e9b` |
| E2a | `0041a739` | e220 | B2 | `FUN_00422ce0` → `004230c0` →(CAS `00423157`) `004231f7` → `FUN_0041a6d0` → `0041a739` |
| E2b | `0041a768` | e220 | B2 | same → `FUN_0041a6d0` → `0041a768` |
| E3 | `0041a7f1` | e280 (`FUN_0041e280`) | B2 | same → `FUN_0041a6d0` → `0041a7f1` |
| E4 | `00423239` | e280 | B2 | `FUN_00422ce0` → `004230c0` →(CAS `00423157`) →…→ `00423239` |

### 7.1 The gates (instruction-level)

**B1 — `FUN_00422f20`** (`listing/00422f20.asm`): `00422f4b MOV EDI,ECX`; `00422f99 LEA EDX,[EDI + 0x214]`; `00422fa3 CMPXCHG.LOCK dword ptr [EDX],ECX`; `00422fa9 JZ 0x0042303f` (field==0 → failure, `FUN_00419e20` NOT called); `00423030 CALL 0x00419e20`. Exactly one caller: `FUN_00422ce0` at `00422d35`.

**B2 — `FUN_004230c0`** (`listing/004230c0.asm`): `004230eb MOV ESI,ECX`; `0042314d LEA EDX,[ESI + 0x214]`; `00423157 CMPXCHG.LOCK dword ptr [EDX],ECX`; `00423162 JZ 0x004232e2` (field==0 → failure, `FUN_0041a6d0`/`FUN_0041e280` NOT called); `00423239 CALL 0x0041e280` (direct). Exactly one caller: `FUN_00422ce0` at `00422d42`. Additional local-flag gates on same execution: `004231b1 JZ`, `004231ea JZ`, `00423216 JZ`/`0042321d JZ`.

Gate semantics: if `[this+0x214] == 0`, `CMPXCHG` writes 0, EAX stays 0, ZF=1, `JZ` taken → skip work block (call does not execute). If `[this+0x214] != 0`, EAX←old field (non-zero), `JZ` not taken → work block executes. The gate is "proceed iff field non-zero"; the "always-zero" premise comes from construction initialization + no non-zero writer, not from the branch itself.

### 7.2 Exhaustive `+0x214` write inventory (whole export, 6,904 listings)

No instruction in the export stores a **non-zero** value into `[X+0x214]`. Sites:

| Site | Instruction | Effect |
|---|---|---|
| `00421410.asm:0042173b` | `MOV dword ptr [EDI + 0x214],0x0` | only direct store; writes 0 |
| `00421990.asm:00421a9d`/`00421aa3` | `LEA EAX,[EDI+0x214]`; `XCHG [EAX],ECX` (ECX=0) | writes 0 |
| `00422150.asm:004221f0`/`00422203` | `CMPXCHG.LOCK [EDX],ECX` (EAX=0,ECX=0) | writes 0 |
| `004224f0.asm:004225ae`/`004225b9`/`004225c5` | `CMPXCHG.LOCK ×2` (EAX=0) | writes 0 |
| `00422e00.asm:00422e81`/`00422e89`/`00422e95` | same shape | writes 0 |
| `00422840.asm` (×8 sites) | `LEA ESI,[EBX+0x214]`; CMPXCHG×4 | writes 0 |
| `00422f20.asm` | `LEA EDX,[EDI+0x214]`; CMPXCHG×2 | writes 0 |
| `004230c0.asm:0042314d`/`00423157`/`0042316c` | `LEA EDX,[ESI+0x214]`; CMPXCHG×2 | writes 0 |
| `004230c0.asm:00423190` | `LEA EAX,[ESI+0x214]` → `CALL 0x0041ee90` | `FUN_0041ee90` CAS([field],0) then XCHG local; writes 0 |
| `00423550.asm`, `00423980.asm`, `00424140.asm`, `00424230.asm`, `00424310.asm`, `004243f0.asm`, `00422260.asm` | `LEA …,[reg+0x214]` | address materialization only |
| `00422ce0.asm` | — | no `+0x214` reference |
| 6 × `PUSH 0x214` | constant push | not a memory access |

### 7.3 Explicit assumptions required for BLOCKED

- **A1 (construction):** every dispatch-object instance whose gate is reached was created via the single creation path (`FUN_0042d980` @ `0042daf2` → `FUN_00421410`), which completes (one RET at `00421777`; `+0x214` store unconditional). → STRONGLY_SUPPORTED.
- **A2 (no external writer):** no code outside this binary (`RVROLCLIENT.DLL`, `SHELPER.DLL`, another process, memory corruption) writes `+0x214 != 0`. → UNKNOWN (export cannot prove absence).
- **A3 (object identity):** gate register denotes the same allocation decorated by `FUN_00421410` → STRONGLY_SUPPORTED (conditional on A1).

If A1 or A2 fails, the field contains heap garbage / non-zero and the path becomes reachable. Neither can be excluded from the export alone. Minimum evidence to settle: one instrumented run breaking on `00423157`/`00422fa3`, dumping `[ESI+0x214]`/`[EDI+0x214]`.

### 7.4 Reachability independence
The blocked callsites' reachability is independent of the vtables; they are reachable iff assumptions fail or an external agent sets `+0x214 != 0`. The dispatch CAS chain itself re-tests `[adjusted+0x4] == 0` with heap-garbage sub-object fields (HeapAlloc flag 0x0 — not zeroed; nothing initializes them); under any non-zero-garbage distribution the probability fresh objects pass CAS1/CAS2 is negligible — statistical, not proof.

---

## 8. Corrections to earlier phases

### 8.1 Phase 9C corrections to Phase 8 (reported in `phase_9C_previous_claims_verification.md` and `phase_9C_main_report.md`)

| # | Earlier claim | Phase 9C verdict | Correction |
|---|---|---|---|
| A1 | `is_call=true` total = 32,848 | CONFIRMED | — |
| A2 | 32,848 = 27,770 + 5,075 | REFUTED (incomplete) | Corrected: 27,770 + 5,075 + **3** (`COMPUTED_CALL_TERMINATOR`) |
| A3 | 15 e220 callsites / 14 unique callers | CONFIRMED | all byte-verified `E8` direct calls |
| A4 | 22 e280 callsites | CONFIRMED | all byte-verified `E8` direct calls |
| A5 | "22 distinct caller functions (no function calls it twice)" for e280 | REFUTED | `FUN_0041d380` calls e280 twice (`0041d438`, `0041d468`) → **21 unique callers** |
| A6 | `FUN_0041e1f0` wrapper called from exactly 3 sites | CONFIRMED | `0041b043`, `0041bc76`, `0041bed2` |
| A7 | `FUN_0041e1f0` calls e280 at `0041e20d` | CONFIRMED | bytes `E86E000000` |
| A8 | `FUN_00416650` exactly 1 caller `FUN_00415300` @ `00415585` | CONFIRMED | — |
| A10 | `FUN_0041f110` and `FUN_00420b80` have no incoming calls | CONFIRMED (Phase 9C) | `FUN_00420b80` corrected by Phase 9D below |
| B1 | `FUN_004230c0` directly calls `FUN_0041e280` at `00423239` | CONFIRMED (existence) / DOWNGRADED (reachability) | bytes `E842B0FFFF`; references.jsonl edge confirmed; blocked under assumptions |
| B2 | `0041a7f1` e280 call attributed to `FUN_004230c0` | REFUTED as written | `0041a7f1` is inside `FUN_0041a6d0`, a **callee** of `FUN_004230c0`; `FUN_004230c0` reaches e280 via `004231f7`→`0041a6d0` **and** directly at `00423239` |
| B3 | CMPXCHG `00423157` always reads 0 → `JZ` `00423162` always taken | DOWNGRADED → CONDITIONAL | "always 0" premise not provable from export alone |
| B4 | "only write to `[x+0x214]` is `MOV [EDI+0x214],0` at `0042173b`" | REFUTED as stated → CONFIRMED-CORRECTED | no instruction stores non-zero into `[X+0x214]`; conclusion survives, evidence statement incomplete |
| B5 | `FUN_00416650` chain `CALL [EDX+0x0C]` opaque dynamic pointer | CORRECTED | target statically resolvable: `FUN_00479d80` via tables `0x00519dac`/`0x0051b254` |
| B7 | e220/e280 chains "the same dispatch mechanism" (mergeable) | REFUTED | same dereference skeleton, different argument state machines, RET widths, prologue semantics; 16650 is a third shape |
| C1 | "BLOCKED (proven unreachable)" for all 5 gate-reached sites | DOWNGRADED → BLOCKED UNDER EXPLICIT ASSUMPTIONS | assumptions A1–A3 explicit |
| C5 | `relatorio_parte8R_caller_table.md` e280 caller table "22 distinct callers" | REFUTED | 21 unique callers; table's own rows show `FUN_0041d380` twice |

### 8.2 Phase 9D corrections to Phase 9C (recorded in `phase_9D_main_report.md` §Q7)

| Phase 9C claim | Phase 9D verdict |
|---|---|
| `FUN_00420b80` — 0 incoming callers, UNKNOWN | **REFUTED** — it has **2 direct callers**: `FUN_0041f450 @ 0041f6bd` (`E869A6FFFF`) and `FUN_00420b30 @ 00420b52` (`E8E381FFFF`), both direct `E8` from listing. Reclassified **CONDITIONAL**. |
| `FUN_0041f110` — "0 incoming refs, UNKNOWN" | CONFIRMED (no `UNCONDITIONAL_CALL` records target it); but a `DATA` ref at `0x0051afe8` proves it lives in the FUN_0041ea00-class vtable at `0x0051afe0` — enterable only via vtable dispatch by framework code outside this export. UNRESOLVED but vtable-backed. |
| e220 caller grouping A/B/C | CONFIRMED by re-reading callsites: 10 Group A sites (`LEA ECX,[EDI + 0x28]` etc.), 4 Group B sites (`+0x10`), 1 Group C site (`LEA ECX,[EBX + 0x8]`). |
| "Object identity unresolved for ALL callers" | PARTIALLY RESOLVED — Group A objects are FUN_00417850-class children (created via `FUN_00424550 → FUN_00417850`); Group B/C share FUN_0041ea00-class grandchild. Per-callsite class receipt from its own caller remains unresolved. |
| `+0x214` gate family analysis | Unchanged — remains BLOCKED UNDER EXPLICIT ASSUMPTIONS |
| e220/e280 pointer chains "target not statically resolvable" | **MAJOR UPGRADE** — for Group A and Group B the target is statically resolvable to `0x004e7650` (CFG-instrumented global-callback dispatch stub). Chain C (`FUN_00416650`) already resolved to `FUN_00479d80` in Phase 9C. |

Unresolved questions carried forward (Phase 9D §Q8): dispatch-slot-selection code at class entry; runtime resolution of `[0x005a5a54]`; Group C chain viability (P=0 → fault at `[0x4]`, never reaches call); whether other classes with homologous layouts exist elsewhere.

### 8.3 Phase 2.5 corrections to Phase 2.4 (different binary; `docs/PHASE_2_5/17_FINAL_TECHNICAL_REPORT.md` §7)

| # | Phase 2.4 claim | Phase 2.5 correction |
|---|---|---|
| C1 | Table A base = vptr | vptr = `0x51FFB4`, not table base `0x51FFAC` |
| C2 | Table B slot 22 address | `0x51E5C8`, not `0x51E5C4` |
| C3 | Table C slot 22 address | `0x51E548`, not `0x51E544` |
| C4 | Table A slot 13 target | `0x4510A0` (→0), not `0x451010` |
| C5 | Table A slot 22 target | `0x450FA0` (?), not `0x451070` |
| C6 | Table B slot 22 target | `0x450FC0` (?), not `0x451090` |
| C7 | Table C slot 22 target | `0x450FC0` (?), not `0x451090` |
| C8 | `0x500CA6` section | `.text`, not `.data`/gap |
| C9 | `0x500CA6` is IAT slot | `free` function code, not pointer |
| C10 | `FUN_00473210` = Release | Destroy/reset, not Release |
| C11 | Standard AddRef/Release | Destroy-on-read-nonzero; no AddRef |
| C12 | Subinitializer count | 9, not 8 |
| C13 | obj+0x20/0x28/0x2C initialized | Not initialized by constructor |

---

## 9. Additional Phase 2.5 findings (separate binary — `RvControlSvc_Installed.exe`)

- Constructor `FUN_0043E1A0` (853 bytes, 36 basic blocks); wrapper `FUN_0043ECF0`; 5 adjustment thunks (`0x43E85E–0x43E881`); **no external callers** found (static); factory/allocation site unknown.
- `FUN_0044F3F0` indirect dispatch guard: `field_0x28 == 5 && field_0x2C != 0`; fields `0x20`, `0x28`, `0x2C` **not initialized by constructor**; `field_0x30` initialized to 0 by `FUN_00410E80`/`FUN_00410F60`, incremented by `FUN_0044F3F0` (call counter).
- `FUN_00473210` is a **destroy/reset** function, not `Release()`: calls `DeleteCriticalSection(obj+8)` via `FUN_00489750`, sets `obj+0x20` to 0 (unconditional LOCK store, not decrement), exchanges `obj+0x24` to 1. Called by `FUN_004731E0` when `obj+0x20 != 0`. **AddRef not found** in any analyzed function (8 sub-initializers not analyzed).
- `0x00500CA6` is in `.text`, contains `free` function code; `CALL [0x00500CA6]` reads `0x8B55FF8B` (invalid pointer) — requires Windows runtime debugging (no Windows debugger available on Linux).
- 12 sub-initializers total; 4 analyzed; 9 not analyzed (`FUN_0047A8A0`, `FUN_0043E500`, `FUN_00403540`, `FUN_004728E0`, `FUN_00483750`, `FUN_0043E680`, `FUN_0047BB20`, `FUN_00475B70`, `FUN_00479240`).

---

## Sources

All 38 sources mapped to `DISPATCH_ANALYSIS` in `analysis_workspace/compaction/mapping.tsv`, read in full:

**Phase 2.5 (16):**
1. `docs/PHASE_2_5/00_ENVIRONMENT_AND_REPOSITORY_PRESERVATION.md`
2. `docs/PHASE_2_5/01_AUTHORITATIVE_MARKDOWN_INVENTORY.md`
3. `docs/PHASE_2_5/03_CORRECTED_VTABLE_ADDRESS_POINT_ANALYSIS.md`
4. `docs/PHASE_2_5/04_CORRECTED_INDIRECT_DISPATCH_TARGETS.md`
5. `docs/PHASE_2_5/05_PE_SECTION_AND_500CA6_ADDRESS_CORRECTION.md`
6. `docs/PHASE_2_5/06_FUN_00473210_COMPLETE_ANALYSIS.md`
7. `docs/PHASE_2_5/07_REFERENCE_COUNT_INCREMENT_AND_RELEASE_SEARCH.md`
8. `docs/PHASE_2_5/08_OBJECT_FIELD_INITIALIZATION_RECONSTRUCTION.md`
9. `docs/PHASE_2_5/09_SUBINITIALIZER_COMPLETE_INVENTORY.md`
10. `docs/PHASE_2_5/10_SUBINITIALIZER_DETAILED_ANALYSIS.md`
11. `docs/PHASE_2_5/11_CONSTRUCTOR_REACHABILITY_AND_FACTORY_ANALYSIS.md`
12. `docs/PHASE_2_5/12_WINDOWS_RUNTIME_DEBUGGING_PLAN.md`
13. `docs/PHASE_2_5/14_AUTHORITATIVE_FINDING_REGISTRY.md`
14. `docs/PHASE_2_5/17_FINAL_TECHNICAL_REPORT.md`
15. `docs/PHASE_2_5/18_RAW_EVIDENCE_APPENDIX.md`
16. `docs/PHASE_2_5/19_COMPLETION_AND_REPOSITORY_PRESERVATION.md`

**Phase 9C audit (11):**
17. `docs/analysis_workspace/phase_9C_audit/phase_9C_main_report.md`
18. `docs/analysis_workspace/phase_9C_audit/phase_9C_evidence_index.md`
19. `docs/analysis_workspace/phase_9C_audit/phase_9C_callsite_inventory.md`
20. `docs/analysis_workspace/phase_9C_audit/phase_9C_blocked_path_revalidation.md`
21. `docs/analysis_workspace/phase_9C_audit/phase_9C_previous_claims_verification.md`
22. `docs/analysis_workspace/phase_9C_audit/phase_9C_reference_count_reconciliation.md`
23. `docs/analysis_workspace/phase_9C_audit/phase_9C_e220_pointer_chain.md`
24. `docs/analysis_workspace/phase_9C_audit/phase_9C_e280_pointer_chain.md`
25. `docs/analysis_workspace/phase_9C_audit/phase_9C_16650_pointer_chain.md`
26. `docs/analysis_workspace/phase_9C_audit/phase_9C_230c0_discrepancy.md`
27. `docs/analysis_workspace/phase_9C_audit/phase_9C_498fe0_manual_analysis.md`

**Phase 9D audit (11):**
28. `docs/analysis_workspace/phase_9D_audit/phase_9D_main_report.md`
29. `docs/analysis_workspace/phase_9D_audit/phase_9D_object_identity_matrix.md`
30. `docs/analysis_workspace/phase_9D_audit/phase_9D_group_A_lifecycle.md`
31. `docs/analysis_workspace/phase_9D_audit/phase_9D_group_B_lifecycle.md`
32. `docs/analysis_workspace/phase_9D_audit/phase_9D_group_C_lifecycle.md`
33. `docs/analysis_workspace/phase_9D_audit/phase_9D_cas_initialization.md`
34. `docs/analysis_workspace/phase_9D_audit/phase_9D_constructor_dataflow.md`
35. `docs/analysis_workspace/phase_9D_audit/phase_9D_e16650_comparison.md`
36. `docs/analysis_workspace/phase_9D_audit/phase_9D_pointer_P_producers.md`
37. `docs/analysis_workspace/phase_9D_audit/phase_9D_pointer_D_producers.md`
38. `docs/analysis_workspace/phase_9D_audit/phase_9D_static_tables.md`

---

## Provenance note

This consolidation was produced by reading all 38 sources listed above and deduplicating their per-audit reports into one narrative; every technical fact (addresses, counts, chains, classifications) was preserved verbatim where it appeared in the sources. No facts were invented; where two audits disagree (Phase 2.5 vs Phase 9C/9D binaries; Phase 8 vs Phase 9C/9D conclusions), both are recorded with their provenance.

**Phase 9C/9D corrections documented here (see `RECONCILIATION.md` for the full discrepancy trail, including discrepancy log D-01…D-14):**

1. **`FUN_00420b80` caller count:** Phase 9C reported 0 incoming callers / UNKNOWN. Phase 9D found **2 direct callers** — `FUN_0041f450 @ 0041f6bd` (`E869A6FFFF`) and `FUN_00420b30 @ 00420b52` (`E8E381FFFF`) — and reclassified the function **CONDITIONAL**. Pointer: `RECONCILIATION.md` (Phase 9D discrepancy entry; also `phase_9D_main_report.md` §Q7).
2. **e280 unique-caller count:** `relatorio_parte8R_caller_table.md` claimed "22 distinct caller functions (no function calls it twice)". Phase 9C refuted this: `FUN_0041d380` calls e280 twice (`0041d438`, `0041d468`), so the correct count is **22 callsites / 21 unique callers** (Phase 8X count was correct).
3. **`00423239` direct e280 call:** Phase 8W graph labeled the edge both "CONDITIONAL" and "BLOCKED"; Phase 8X labeled it BLOCKED. Phase 9C verified `00423239` = `E842B0FFFF CALL 0x0041e280` is a genuine direct call from `FUN_004230c0`, confirmed in `references.jsonl`; existence is not disputed, only reachability → **BLOCKED UNDER EXPLICIT ASSUMPTIONS**.
4. **`0041a7f1` attribution:** `0041a7f1` (`CALL 0x0041e280`) is inside `FUN_0041a6d0`, a callee of `FUN_004230c0`, not a call by `FUN_004230c0` itself. Both paths coexist.
5. **`+0x214` write inventory:** earlier claim "only write is `MOV [EDI+0x214],0` at `0042173b`" was incomplete; Phase 9C's exhaustive inventory shows **no instruction stores a non-zero value into `[X+0x214]`** (all writes are 0 or CAS-with-0). Conclusion survives; evidence statement corrected.
6. **`is_call=true` total:** earlier phrasing `27,770 + 5,075 = 32,845` dropped the three `COMPUTED_CALL_TERMINATOR` records. Corrected: `27,770 + 5,075 + 3 = 32,848`.
7. **`FUN_00416650` target:** Phase 8R treated `CALL [EDX+0x0C]` as an opaque dynamic pointer; Phase 9C/9D resolved it statically to `FUN_00479d80` via constructor-set tables `0x00519dac`/`0x0051b254` (both store `0x00479d80` at `+0x0C`).
8. **Blocked classifications:** all five "PROVEN BLOCKED / unreachable" claims (E1–E4) downgraded to **BLOCKED UNDER EXPLICIT ASSUMPTIONS** (assumptions A1–A3; `RECONCILIATION.md` discrepancy log).
9. **Group A/B/C P/D values:** Phase 9D established Group A `P = 0x0051aee0`, `D = 0x00000210`; Group B `P = 0x0051b01c`, `D = 0x000002b0`; Group C `P = 0x00000000` (literal zero → chain faults at `[0x4]`, never reaches call).
10. **Group A/B target upgrade:** Phase 9C held e220/e280 targets not statically resolvable; Phase 9D upgraded Group A and B to statically resolvable target `0x004e7650` (CFG-instrumented global-callback dispatch stub reading `[0x005a5a54]`).

**Data provenance:** Phase 9C/9D binary `RvControlSvc.exe` SHA-256 `546efad9…8daa1e`, Ghidra 12.2 export `ghidra_export/` (HEAD `b873cea0`, main, unchanged during the audits; `.gitignore`, `src/session/control_handshake.rs`, `src/session/mod.rs` pre-existing modifications only). Phase 2.5 binary `RvControlSvc_Installed.exe` SHA-256 `0e2e6eaa…d6ef2ad` (different binary; separate analysis, marked as such throughout).
---

## Evidence appendix (exact tokens from consolidated sources)

Exact addresses, hashes and identifiers from the consolidated sources that are not repeated in the prose above. They are preserved here so that no evidence anchor is lost during compaction; the full narrative for each source remains available in git history.

- `docs/PHASE_2_5/00_ENVIRONMENT_AND_REPOSITORY_PRESERVATION.md`: `6be002076beeb898a338c18c2eb1d263089c25ee`
- `docs/PHASE_2_5/01_AUTHORITATIVE_MARKDOWN_INVENTORY.md`: `6be002076beeb898a338c18c2eb1d263089c25ee`
- `docs/PHASE_2_5/03_CORRECTED_VTABLE_ADDRESS_POINT_ANALYSIS.md`: `0x0043eed0`, `0x0043f110`, `0x0044f3e0`, `0x0044f6b0`, `0x0044f6c0`, `0x0044f850`, `0x43e1b1`, `0x43e4c8`, `0x43e4e8`, `0x44f501`, `0x44f50d`, `0x44f5aa`, `0x44f5b6`, `0x51e4f4`, `0x51e4f8`, `0x51e4fc`, `0x51e524`, `0x51e574`, `0x51e578`, `0x51e57c`, `0x51e5a4`, `0x51ffb8`, `0x51ffbc`, `0x51ffc0`, `fun_00450fa0`, `fun_00450fc0`, `fun_004510a0`, `fun_004510b0`
- `docs/PHASE_2_5/04_CORRECTED_INDIRECT_DISPATCH_TARGETS.md`: `0x44f4ee`, `0x44f4f4`, `0x44f4fe`, `fun_00450fa0`, `fun_00450fc0`, `fun_004510a0`, `fun_004510b0`
- `docs/PHASE_2_5/05_PE_SECTION_AND_500CA6_ADDRESS_CORRECTION.md`: `0x0ffca6`, `0x1000a6`, `0x118600`, `0x149600`, `0x14a000`, `0x400400`, `0x500cdf`, `0x5c1000`, `0x5d6000`, `0xffdff000`, `0xffe00000`, `fun_004ec736`
- `docs/PHASE_2_5/07_REFERENCE_COUNT_INCREMENT_AND_RELEASE_SEARCH.md`: `fun_0043a9a0`, `fun_0043b420`, `fun_0043b470`, `fun_0043b4c0`, `fun_00440670`, `fun_00451900`, `fun_0046ae70`, `fun_0046b9f0`, `fun_00475c00`, `fun_004802f0`, `fun_004831f0`
- `docs/PHASE_2_5/08_OBJECT_FIELD_INITIALIZATION_RECONSTRUCTION.md`: `0x410ebd`, `0x410f9d`, `0x44f4fe`
- `docs/PHASE_2_5/09_SUBINITIALIZER_COMPLETE_INVENTORY.md`: `0x43a9a0`, `0x43e100`, `0x4e7ec0`, `fun_0043a9a0`, `fun_0043e100`, `fun_004802f0`, `fun_004e7ec0`, `fun_004ec736`
- `docs/PHASE_2_5/10_SUBINITIALIZER_DETAILED_ANALYSIS.md`: `fun_0043a9a0`, `fun_004802f0`
- `docs/PHASE_2_5/11_CONSTRUCTOR_REACHABILITY_AND_FACTORY_ANALYSIS.md`: `0x11941e`, `0x11942a`, `0x11998c`, `0x1199c0`, `0x43e866`, `0x43e86e`, `0x43e876`
- `docs/PHASE_2_5/12_WINDOWS_RUNTIME_DEBUGGING_PLAN.md`: `0x004ec736`, `0x43e1b1`, `0x43e4c8`, `0x43e4e8`, `0x44f501`, `0x44f50d`, `0x44f5aa`, `0x44f5b6`, `0x51e524`, `0x51e5a4`, `fun_004e6cd7`, `fun_004ec736`
- `docs/PHASE_2_5/14_AUTHORITATIVE_FINDING_REGISTRY.md`: `0x1000a6`, `0x43e1b1`, `fun_00450fa0`, `fun_00450fc0`, `fun_004ec736`
- `docs/PHASE_2_5/17_FINAL_TECHNICAL_REPORT.md`: `0x51e524`, `0x51e5a4`, `fun_00450fa0`, `fun_00450fc0`, `fun_004e6cd7`, `fun_004ec736`
- `docs/PHASE_2_5/18_RAW_EVIDENCE_APPENDIX.md`: `0x0043eed0`, `0x0043f110`, `0x0044f3e0`, `0x0044f6b0`, `0x0044f6c0`, `0x0044f850`, `0x11ffac`, `0x11ffb4`, `0x400400`, `0x43e1b1`, `0x43e1b7`, `0x43e1be`, `0x43e1c5`, `0x43e1cc`, `0x43e1d6`, `0x43e49a`, `0x43e4a4`, `0x43e4ae`, `0x43e4b5`, `0x43e4bc`, `0x43e4c8`, `0x43e4e8`, `0x43e866`, `0x43e86e`, `0x43e876`, `0x473215`, `0x47321d`, `0x4ec736`, `0x51be00`, `0x51be0c`, `0x51be20`, `0x51e4f4`, `0x51e4f8`, `0x51e4fc`, `0x51e524`, `0x51e574`, `0x51e578`, `0x51e57c`, `0x51e5a4`, `0x51e7f8`, `0x51e810`, `0x51ffb0`, `0x51ffb8`, `0x520014`, `0x520020`, `0x520034`, `0x520050`, `0x5200e8`, `0x5c1000`, `0x5d6000`, `0xffdff000`, `0xffe00000`, `fun_00450fa0`, `fun_00450fc0`, `fun_00451010`, `fun_00451070`, `fun_00451090`, `fun_004510a0`, `fun_004510b0`, `fun_004ec736`
- `docs/analysis_workspace/phase_9C_audit/phase_9C_16650_pointer_chain.md`: `0x00116400`, `0x0040f6a0`, `0x004104b0`, `0x0041674d`, `0x0041692b`, `0x00473b70`, `0x004e5abb`, `0x00517000`, `0x00553250`, `0x0055bf80`, `0x0055bf84`, `0x2000303`, `0x519da0`, `0x55bf80`, `0x55bf84`, `fun_0040f6a0`, `fun_004104b0`
- `docs/analysis_workspace/phase_9C_audit/phase_9C_230c0_discrepancy.md`: `0x00415f80`, `0x0042328b`
- `docs/analysis_workspace/phase_9C_audit/phase_9C_498fe0_manual_analysis.md`: `0x00489280`, `0x004aebe0`, `0x004aec20`, `0x004aec60`, `0x004aec70`, `0x004aec80`, `0x004e74f0`, `0x0050af50`, `0x00549138`, `0x0055bf80`, `0x0055bf84`, `0x005988cc`, `0x005a4348`, `0x005a494c`, `0x005a4f50`, `fun_004891d0`, `fun_00498fe0`
- `docs/analysis_workspace/phase_9C_audit/phase_9C_blocked_path_revalidation.md`: `0x00423090`, `0x0042326d`, `0x00521710`, `0x46000000`, `fun_004ff788`
- `docs/analysis_workspace/phase_9C_audit/phase_9C_callsite_inventory.md`: `fun_0041ae30@0041b043`, `fun_0041bb40@0041bc76`, `fun_0041bd70@0041bed2`
- `docs/analysis_workspace/phase_9C_audit/phase_9C_evidence_index.md`: `0x00515830`, `0x005172f0`, `0x0051a9d0`, `0x00521710`, `0x0055bf80`, `0x0055bf84`, `0x422da0`, `0x422dc8`, `b873cea0bd1f3890925a0c0f79bbe2abc16db6cd`
- `docs/analysis_workspace/phase_9C_audit/phase_9C_main_report.md`: `0x005172f0`, `0x0055bf80`, `0x0055bf84`, `b873cea0bd1f3890925a0c0f79bbe2abc16db6cd`, `fun_004891d0`, `fun_00498fe0`, `fun_004ff788`
- `docs/analysis_workspace/phase_9C_audit/phase_9C_previous_claims_verification.md`: `0x00415f80`, `0x0055bf80`, `0x0055bf84`, `0x422da0`, `0x422dc8`, `fun_00498fe0`
- `docs/analysis_workspace/phase_9D_audit/phase_9D_cas_initialization.md`: `0x0051afc0`, `0x0051afcc`
- `docs/analysis_workspace/phase_9D_audit/phase_9D_constructor_dataflow.md`: `0x0051a9d0`, `0x0051aee8fffffff4`, `fun_004183d0`, `fun_00422060`, `fun_0042d3a0`, `fun_0046ab80`, `fun_0046e4f0`, `fun_00478710`, `fun_004794e0`, `fun_0047a650`, `fun_0047ac80`, `fun_0047f4b0`, `fun_00487900`
- `docs/analysis_workspace/phase_9D_audit/phase_9D_group_A_lifecycle.md`: `0x0051ae60`, `0x0051ae6c`, `fun_0042d2a0`, `fun_0042d3a0`
- `docs/analysis_workspace/phase_9D_audit/phase_9D_group_B_lifecycle.md`: `0x0051afc0`, `0x0051afcc`
- `docs/analysis_workspace/phase_9D_audit/phase_9D_main_report.md`: `0x005172f0`, `b873cea0bd1f3890925a0c0f79bbe2abc16db6cd`, `fun_00418940`, `fun_0041f090`, `fun_004e766c`
- `docs/analysis_workspace/phase_9D_audit/phase_9D_object_identity_matrix.md`: `fun_0042d2a0`, `fun_0042d3a0`, `fun_0044d140`, `fun_0044d600`
- `docs/analysis_workspace/phase_9D_audit/phase_9D_pointer_P_producers.md`: `fun_00418940`
- `docs/analysis_workspace/phase_9D_audit/phase_9D_static_tables.md`: `0x0041ece0`, `0x0051ae2c`, `0x0051ae3c`, `0x0051ae40`, `0x0051ae48`, `0x0051ae4c`, `0x0051ae50`, `0x0051ae54`, `0x0051ae5c`, `0x0051ae60`, `0x0051ae64`, `0x0051ae68`, `0x0051ae6c`, `0x0051ae70`, `0x0051af0c`, `0x0051af10`, `0x0051af14`, `0x0051af18`, `0x0051af1c`, `0x0051af20`, `0x0051af24`, `0x0051af28`, `0x0051af2c`, `0x0051afd0`, `0x0051afd4`, `0x0051afdc`, `0x0051afe4`, `0x0051afec`, `0x0051aff0`, `0x0051aff4`, `0x0051aff8`, `0x0051affc`, `0x0051b000`, `0x0051b008`, `0x0051b00c`, `0x0051b010`, `0x0051b24c`, `0x0051b250`, `0x0051b258`, `0x0053464c`, `fun_00418fd0`, `fun_0041a630`, `fun_0041e0e0`, `fun_0041ece0`, `fun_0041efdd`, `fun_0041f090`, `fun_0041f100`, `fun_0041fd70`, `fun_0041fdc0`, `fun_0041fdd0`, `fun_0041fdf0`, `fun_0041fe00`, `fun_004200b2`, `fun_00420540`, `fun_00421020`, `fun_00421e20`
