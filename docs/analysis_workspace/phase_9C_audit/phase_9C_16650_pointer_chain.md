# Phase 9C — Pointer Chain C: `FUN_00416650` indirect call at `0041693f`

**Target instruction:** `0041693f  FF520C  CALL dword ptr [EDX + 0x0C]` (`listing/00416650.asm`)
**This is NOT the same dispatch shape as Chains A/B.** One dereference level shallower, field at `+0x08` instead of `+0x0C`, different CAS/spin machinery, and — uniquely among the three — a **static producer for the pointer** on the two constructor-set tables.

## 1. Caller context

`FUN_00416650` is called from exactly one site — `FUN_00415300` at `00415585` (`E8C6100000`, verified; see `phase_9C_callsite_inventory.md` §3). Its argument at `00415585` (from `FUN_00415300` listing `00415300.asm` context: the site follows the wait-object setup; the referenced functions `FUN_0040f6a0` / `FUN_00415300` deal with WaitForMultipleObjects-style machinery, but the identity of the object passed is only partially traceable — the `this` of `FUN_00416650` is whatever `FUN_00415300` passes in `ECX`; exact construction site of that object is outside the dispatch investigation; its *type family* is `FUN_00421410`'s dispatch object — see §4).

## 2. Full instruction trace (relevant region)

```
00416656  A150325500           MOV EAX,[0x00553250]        ; SEH cookie
0041665b  33C5                 XOR EAX,EBP
00416664  8BD9                 MOV EBX,ECX                 ; EBX := this
00416671  0F1145D0             MOVUPS xmmword ptr [EBP - 0x30],XMM0   ; zero-init locals (WaitObject block)
…
00416704  33C0                 XOR EAX,EAX
00416706  B980BF5500           MOV ECX,0x55bf80            ; shared state global #1
0041670b  F00FC101             XADD.LOCK dword ptr [ECX],EAX          ; atomic read-modify-write with 0
0041670f  3D3F420F00           CMP EAX,0xf423f              ; old == sentinel ?
00416714  7537                 JNZ 0x0041674d                ; != sentinel → try #2
00416720  (spin loop, up to 10 iterations, XADD with EDX=0)
00416740  B884BF5500           MOV EAX,0x55bf84            ; shared state global #2
00416745  F00FC108             XADD.LOCK dword ptr [EAX],ECX
…
00416911  33C9                 XOR ECX,ECX
00416913  8D55F0               LEA EDX,[EBP + -0x10]       ; EDX := &local[EBP-0x10]
00416916  33C0                 XOR EAX,EAX
00416918  F00FB10A             CMPXCHG.LOCK dword ptr [EDX],ECX ; local CAS, accumulator 0
0041691c  85C0                 TEST EAX,EAX
0041691e  750B                 JNZ 0x0041692b               ; local non-zero → skip the wait path
00416920  8BCA                 MOV ECX,EDX
00416922  32DB                 XOR BL,BL
00416924  E8879BFFFF           CALL 0x004104b0              ; wait registration helper (argument ECX = &local)
0041692b  33C9                 XOR ECX,ECX                  ; fall-through path
0041692d  8D55F0               LEA EDX,[EBP + -0x10]       ; EDX := &local[EBP-0x10]  (again)
00416930  33C0                 XOR EAX,EAX
00416932  F00FB10A             CMPXCHG.LOCK dword ptr [EDX],ECX ; local CAS again (result EDX stays = &local)
00416936  8B5308               MOV EDX,dword ptr [EBX + 0x8]        ; EDX := [this + 0x08]   (P16650)
00416939  8D4B08               LEA ECX,[EBX + 0x8]                 ; ECX := &[this + 0x08]
0041693c  6A01                 PUSH 0x1                             ; push 1
0041693e  50                   PUSH EAX                             ; push CAS result (old local)
0041693f  FF520C               CALL dword ptr [EDX + 0xc]           ; CALL [[this+0x08] + 0x0C]
00416942  8D4DF0               LEA ECX,[EBP + -0x10]
00416945  B301                 MOV BL,0x1
00416947  E8649BFFFF           CALL 0x004104b0                       ; symmetric helper (wait/unwait)
```

## 3. Pointer expression (in order of dereference)

| Step | Register | Expression |
|---|---|---|
| 1 | `EBX` | `this` (ECX at entry, `00416664`) |
| 2 | `EDX` / `P16650` | `P16650 = [EBX + 0x08]` — one memory read (runtime field, **but statically initialized** on this class — see §4) |
| 3 | `ECX` | `A16650 = &[this + 0x08]` |
| 4 | target | `[P16650 + 0x0C]` — i.e. `target = *((*(EBX+0x08)) + 0x0C)` |

**Target expression: `target = *(P16650 + 0x0C)` with `P16650 = *(this + 0x08)`.**

Compared to chains A/B: `target = *(EDI + *(P+4) + 0x0C)` — **one fewer indirection level** and the offset `+0x08` instead of `+0x0C` for the table pointer.

## 4. Static producer — the decisive difference from Chains A/B

`FUN_00421410` (the only creation path for this object class, via `FUN_0042d980` @ `0042daf2`) writes the `+0x08` field at two sites:

```
004214ee?  C707A09D5100   MOV dword ptr [EDI],0x519da0     ; vtable phase-1, [this+0]
004214f0  C74708AC9D5100  MOV dword ptr [EDI + 0x8],0x519dac   ; table A  (taken when [EBP+0x24]==0: path via 004214da)
00421555  C70748B25100    MOV dword ptr [EDI],0x51b248         ; vtable phase-2
0042155b  C7470854B25100  MOV dword ptr [EDI + 0x8],0x51b254   ; table B  (alternate path)
```

`.rdata` contents dumped read-only from the PE (via `dump_rdata.py`, ImageBase 0x00400000; `.rdata` VMA `0x00517000`, file off `0x00116400`):

```
0x00519dac:  004048e5  00479fa0  00479d70  00479d80  0052fb00  004048ed  00407320  ...
0x0051b254:  00421c8a  00479fa0  00479d70  00479d80  00534ed8  00421c92  00407320  ...
```

Address `+0x0C` into each table:

| Table | base offset +0x0C | dword at |
|---|---|---|
| A (`0x00519dac`) | `0x00519db8` | **`0x00479d80`** |
| B (`0x0051b254`) | `0x0051b260` | **`0x00479d80`** |

**Target = `0x00479d80` = `FUN_00479d80`** (`thiscall`, 251 bytes, not a thunk, not an import stub — verified in `functions.jsonl` and `listing/00479d80.asm` exists and begins `00479d80 55 PUSH EBP`).

**Qualifications:** (1) holds iff the object was constructed by `FUN_00421410` (STRONGLY_SUPPORTED, single creation site); (2) the constructor sets table A or B based on `[EBP+0x24]` — both paths store the same dispatch target at `+0x0C`; (3) nothing else in the export writes `[this+0x08]` for this class (its 403 `[reg+0xc]`-scale store survey found no store to `[reg+0x8]` with object provenance on this class); "STRONGLY_SUPPORTED", not "CONFIRMED", because the dynamic instance is unobserved.

## 5. Machinery specific to Chain C (do not merge with A/B)

- Global shared state `0x0055BF80` / `0x0055BF84` (both in `.data`, all-zero at image layout) — atomic `XADD.LOCK …, 0` with retry spin up to 0xA (10) iterations and `0xf423f` sentinel — the **spin protocol** that prevents concurrent dispatch entry on this class. The globals' semantics (semaphore count vs flag) are NOT proven; they are used exactly as "lock held while 0xf423f handed to a waiter".
- An external "WaitObject" is created via `CALL 0x0040f6a0` (`PUSH 0x2000303`) and similar — the code path creates and later releases a wait object with an externally-meaningful handle; the `CALL [EDX+0xC]` is invoked while holding the object pair; `FUN_004104b0` is the symmetric release helper.
- The shared work block after dispatch calls `CALL 0x00473b70` and `CALL 0x004e5abb` (SEH epilogue cadence).
- No `GetLastError`/`SetLastError` around the indirect call (unlike Chains A/B).

## 6. Writers / producers relevant to the chain

- `[this+0x08]` (the table pointer): **statically produced** by the constructor (two sites) — PROVEN; alternate producers: none in export.
- Static table slot `[0x00519db8]` / `[0x0051b260]` (holding `0x00479d80`): **never written by any code** in the export (the `.rdata` tables are read-only: no `MOV [0x00519db8]`/`[0x0051b260]` stores; checked the full listing set).
- `[EBX+0x08]` read at `00416936`: value determined entirely by construction history (A/B) — both lead to `FUN_00479d80`.
- Local `[EBP-0x10]`: the CAS field — written zero in both CAS sites; consumers are the wait/release helper pattern; irrelevant to target resolution.

## 7. Assessment

- Chain C is fully reconstructible **and its target is statically resolvable**: `FUN_00479d80`, reached via a static vtable-like table on the constructor-set tables `0x00519dac` / `0x0051b254`.
- This is the **single statically-resolved indirect target in the dispatcher family** in this export. It is not the same dispatch mechanism as the Group A/B/C `+0x04`/`+0x10` gates; it belongs to the shared-state (globals `0x0055BF80/0x0055BF84`) wait-object subsystem.
- Static resolution is conditional on constructor-path object identity (A1 of the blocked-path assumptions) — but unlike A/B, the **producer is proven at instruction level**, and the two table variants agree.
- `FUN_00479d80` itself is not further analyzable cheaply (251 bytes, thiscall) — for the dispatch question it suffices that the chain resolves and stays inside analyzed code.
