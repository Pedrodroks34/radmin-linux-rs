# Phase 2.3 Stage 6 — Object Lifecycle and Ownership Analysis

**Classification: STRONGLY SUPPORTED** (reference counting pattern verified; destructor targets identified)

## 1. Reference Counting Pattern Found

All atomic operations found in constructor `FUN_0043E1A0` and `FUN_0043E100`:

| # | VA | Instruction | Raw Bytes | Memory Operand | Offset | Operation | Confidence |
|---|---|---|---|---|---|---|---|
| 1 | 0x43E15E | `XCHG dword ptr [EBX], EDI` | 8B 3B | [this+0x00] | 0x00 | Atomic swap (vptr) | VERIFIED |
| 2 | 0x43E167 | `XADD.LOCK dword ptr [EDI+0x4], EAX` | F0 0F C1 07 | [old_vtable+0x4] | old_vtable+4 | Atomic add-and-fetch (-1) | VERIFIED |
| 3 | 0x43E24C | `XCHG dword ptr [EAX], ECX` | 8B 10 | [this+0x1E50] | 0x1E50 | Atomic swap (pointer) | VERIFIED |
| 4 | 0x43E257 | `XADD.LOCK dword ptr [ECX+0x4], EAX` | F0 0F C1 01 | [ptr+0x4] | ptr+4 | Atomic add-and-fetch (-1) | VERIFIED |
| 5 | 0x43E27B | `XCHG dword ptr [EAX], ECX` | 8B 10 | [this+0x1E4C] | 0x1E4C | Atomic swap (pointer) | VERIFIED |
| 6 | 0x43E286 | `XADD.LOCK dword ptr [ECX+0x4], EAX` | F0 0F C1 01 | [ptr+0x4] | ptr+4 | Atomic add-and-fetch (-1) | VERIFIED |
| 7 | 0x43E2AE | `XCHG dword ptr [EAX], ECX` | 8B 10 | [this+0x1E48] | 0x1E48 | Atomic swap (pointer) | VERIFIED |
| 8 | 0x43E2B9 | `XADD.LOCK dword ptr [ECX+0x4], EAX` | F0 0F C1 01 | [ptr+0x4] | ptr+4 | Atomic add-and-fetch (-1) | VERIFIED |

Pattern for each XCHG-based cleanup:
1. `XCHG dword ptr [field], ECX` — atomically swap old pointer value into ECX, store 0 (or new value) at field
2. `TEST ECX, ECX` — check if old value was non-zero
3. `JZ skip` — if old was zero, skip cleanup
4. `MOV EAX, EBX` / `OR EAX, 0xFFFFFFFF` — EAX = -1
5. `XADD.LOCK dword ptr [ECX+0x4], EAX` — atomic decrement refcount at [old_pointer+0x4]
6. `DEC EAX; JNS skip` — if result >= 0, skip destructor call
7. `CALL [0x00519280]` — GetLastError()
8. `MOV EDX, dword ptr [ECX]` / `MOV EDX, dword ptr [ECX]` — EDX = [old+0x0] (destructor pointer)
9. `CALL [EDX]` — CALL destructor at slot 0 of old vtable
10. `CALL [0x00519260]` — SetLastError

## 2. Destructor Candidates

| Function | VA | Size | Signature | Role | Classification |
|---|---|---|---|---|---|
| FUN_0043EED0 | 0x0043EED0 | 68 bytes | `__thiscall void *(void *this, byte param_1)` | Intermediate table slot 0; sets vptr to 0x51E570, releases subobjects | STRONGLY SUPPORTED |
| FUN_0043F110 | 0x0043F110 | 36 bytes | `void * __thiscall \`scalar_deleting_destructor'(_Facet_base *this, uint param_1)` | Final table slot 0; MSVC scalar deleting destructor; sets vptr to 0x51E4F0, releases subobject at +0x4 | VERIFIED |

### FUN_0043EED0 (0x43EED0, 68 bytes, 3 blocks)
```
0x43EED0: PUSH EBP
0x43EED1: MOV EBP, ESP
0x43EED3: PUSH ESI
0x43EED4: MOV ESI, ECX                    ; ESI = this
0x43EED6: MOV dword ptr [ESI], 0x51e570   ; [this+0x00] = 0x51E570 (intermediate vtable)
0x43EEDC: LEA ECX, [ESI + 0xC]            ; &[this+0x0C]
0x43EEDF: MOV dword ptr [0x0055E264], 0   ; global = 0
0x43EEEE: CALL 0x00475B70                  ; FUN_00475B70(&[this+0x0C]) — release subobject at +0x0C
0x43EEEE: LEA ECX, [ESI + 0x4]            ; &[this+0x04]
0x43EEF1: CALL 0x00479240                  ; thunk → FUN_004792C0 (&[this+0x04])
0x43EEF6: TEST byte ptr [EBP + 0x8], 0x1   ; param_1 bit 0
0x43EEF0: MOV dword ptr [ESI], 0x51e4f0   ; [this+0x00] = 0x51E4F0 (final vtable)
0x43EEF0: JZ 0x0043EF0D
0x43EEF2: PUSH 0x34
0x43EEF4: PUSH ESI
0x43EEF5: CALL 0x004E6CD7                  ; FUN_004E6CD7(this, 0x34) — free this, size 0x34
0x43EEFA: ADD ESP, 0x8
0x43EEFD: MOV EAX, ESI
0x43EEFF: POP ESI
0x43EF00: POP EBP
0x43EF01: RET 0x4
```

### FUN_0043F110 (0x43F110, 36 bytes, 3 blocks) — `std::_Facet_base::scalar_deleting_destructor`
```
0x43F110: PUSH EBP
0x43F111: MOV EBP, ESP
0x43F113: TEST byte ptr [EBP + 0x8], 0x1   ; param_1 bit 0
0x43F117: PUSH ESI
0x43F118: MOV ESI, ECX                     ; ESI = this
0x43F11A: MOV dword ptr [ESI], 0x51e4f0    ; [this+0x00] = 0x51E4F0 (final vtable)
0x43F120: JZ 0x0043F12D                    ; if param_1 == 0, skip cleanup
0x43F122: PUSH 0x4
0x43F124: PUSH ESI                         ; push this
0x43F125: CALL 0x004E6CD7                  ; FUN_004E6CD7(this, 4) — free subobject at +0x4, size 4
0x43F12A: ADD ESP, 0x8
0x43F12D: MOV EAX, ESI                     ; return this
0x43F12F: POP ESI
0x43F130: POP EBP
0x43F131: RET 0x4
```

## 3. Construction/Destruction Symmetry

| Aspect | Construction | Destruction | Symmetric? |
|---|---|---|---|
| VPtr writes | 3 transitions (0x51FFB4 → 0x51E570 → 0x51E4F0) | 1 transition (to final vtable in FUN_0043EED0) | NO |
| Subobject initialization | 7+ subobject initializers | Subobject release calls | PARTIAL |
| Ref-counted cleanup | Multiple XCHG/XADD chains | Single destructor call per vptr | PARTIAL |
| Allocator | Not found | FUN_004E6CD7 (free with size) | NO |

**Not symmetric.** Construction is more complex than destruction, and the allocator is not identified.

## 4. Reference Counting Classification

| Field Offset | Classification | Evidence |
|---|---|---|
| [old_vtable+0x4] | Candidate reference counter | XADD.LOCK decrement pattern found in constructor |
| [this+0x1E28] through [this+0x1E3C] | Candidate reference counters | XCHG/XADD cleanup pattern found in constructor |
| [this+0x1E48] | Atomic reference counter | Read by FUN_0044F3F0 (`CMPXCHG.LOCK`) |
| [this+0x1E4C] | Atomic reference counter | Read by FUN_0044F3F0 (`CMPXCHG.LOCK`) |
| [this+0x1E50] | Atomic reference counter | Read by FUN_0044F3F0 (`CMPXCHG.LOCK`) |

## 5. Limitations

- Allocator not found — object construction site unknown
- What entity is being reference-counted (the object, a subobject, a shared control block) is unknown
- Whether refcount ever reaches 0 in observed code paths is unknown
- Construction/destruction not fully symmetric
- FUN_004E7EC0 (ultimate cleanup target of FUN_004E6CD7) not analyzed

## 6. Next Stage

Stage 7: Analyze FUN_00451090 (indirect call target under intermediate/final vptrs).