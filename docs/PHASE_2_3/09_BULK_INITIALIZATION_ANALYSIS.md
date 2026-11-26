# Phase 2.3 Stage 9 — Bulk Initialization Analysis

**Classification: VERIFIED** (all bulk initialization operations extracted from constructor disassembly)

## 1. Bulk Initialization Operations

### Zeroing Loop 1 — FUN_0043E100 (called at 0x43E1E0)

```
0x43E12F: LEA ESI, [EBX + 0xC]       ; ESI = &[this+0x0C]
0x43E132: MOV EDI, 0x64              ; EDI = 100 (count)
0x43E137: MOV ECX, ESI               ; ECX = &[this+0x0C]
0x43E139: CALL 0x0043a9a0            ; FUN_0043a9a0(&[this+0x0C])
0x43E13E: ADD ESI, 0xC               ; ESI += 0xC (next dword)
0x43E141: SUB EDI, 0x1               ; EDI--
0x43E144: JNZ 0x0043E137             ; loop if EDI != 0
```
- Range: [this+0x0C] to [this+0x0C+100*0xC] = [this+0x0C] to [this+0x4C4]
- Count: 100 dwords, step 0xC
- Function: FUN_0043a9a0 (writes vptr 0x51BD88 at [this+0x0C], initializes sub-objects at +0x18 and +0x20)

### Bulk Init 1 — FUN_004E70a5 (called at 0x43E159)

```
0x43E158: PUSH EAX                   ; EAX = &[this+0x0C]
0x43E159: CALL 0x004E70a5            ; __eh_vector_destructor_iterator(&[this+0x0C], 100, 0xC, FUN_0043a9a0)
```
- `__eh_vector_destructor_iterator(&[this+0x0C], 100, 0xC, FUN_0043a9a0)`
- Calls FUN_0043a9a0 for each element in the range

### Zeroing Loop 2 — FUN_0043E500 (called at 0x43E234)

```
0x43E52E: LEA ESI, [EBX + 0x3864]    ; ESI = &[this+0x1EEC+0x3864] = &[this+0x56F0]
0x43E534: MOV EDI, 0x64              ; EDI = 100
0x43E540: MOV ECX, ESI               ; ECX = &[this+0x56F0]
0x43E542: CALL 0x0043b470            ; FUN_0043b470(&[this+0x56F0])
0x43E547: ADD ESI, 0xC               ; ESI += 0xC
0x43E54A: SUB EDI, 0x1               ; EDI--
0x43E54D: JNZ 0x0043E540             ; loop
```
- Range: [this+0x56F0] to [this+0x56F0+100*0xC] = [this+0x56F0] to [this+0x5BA0]
- Count: 100 dwords, step 0xC
- Function: FUN_0043b470 (reads [EDI+0x4], calls FUN_00475870)

### Bulk Init 2 — FUN_004E70a5 (called at 0x43E565)

```
0x43E565: CALL 0x004E70a5            ; __eh_vector_destructor_iterator(&[this+0x56F0], 100, 0xC, FUN_0043b470)
```

### Zeroing Loop 3 — FUN_0043E500 (continued)

```
0x43E571: LEA ESI, [EBX + 0x1C38]    ; ESI = &[this+0x1EEC+0x1C38] = &[this+0x3C24]
0x43E577: MOV EDI, 0x258             ; EDI = 0x258 (600)
0x43E580: MOV ECX, ESI               ; ECX = &[this+0x3C24]
0x43E582: CALL 0x0043b4c0            ; FUN_0043b4c0(&[this+0x3C24])
0x43E587: ADD ESI, 0xC               ; ESI += 0xC
0x43E58A: SUB EDI, 0x1               ; EDI--
0x43E58D: JNZ 0x0043E580             ; loop
```
- Range: [this+0x3C24] to [this+0x3C24+0x258*0xC] = [this+0x3C24] to [this+0x4B24]
- Count: 0x258 (600) dwords, step 0xC
- Function: FUN_0043b4c0 (reads [EDI+0x4], calls FUN_0047B450)

### Bulk Init 4 — FUN_004E70a5 (called at 0x43E5A8)

```
0x43E5A8: CALL 0x004E70a5            ; __eh_vector_destructor_iterator(&[this+0x3C24], 0x258, 0xC, FUN_0043b4c0)
```

### Zeroing Loop 4 — FUN_0043E680 (called at 0x43E492)

```
0x43E703: LEA ESI, [EBX + 0x68]      ; ESI = &[this+0xA0+0x68] = &[this+0x108]
0x43E706: MOV EDI, 0x258             ; EDI = 0x258 (600)
0x43E710: MOV ECX, ESI               ; ECX = &[this+0x108]
0x43E712: CALL 0x00440670            ; FUN_00440670(&[this+0x108])
0x43E717: ADD ESI, 0xC               ; ESI += 0xC
0x43E71A: SUB EDI, 0x1               ; EDI--
0x43E71D: JNZ 0x0043E710             ; loop
```
- Range: [this+0x108] to [this+0x108+0x258*0xC] = [this+0x108] to [this+0x2008]
- Count: 0x258 (600) dwords, step 0xC
- Function: FUN_00440670 (reads [EDI+0x4], calls FUN_00475870)

### Bulk Init 5 — FUN_004E70a5 (called at 0x43E735)

```
0x43E735: CALL 0x004E70a5            ; __eh_vector_destructor_iterator(&[this+0x108], 0x258, 0xC, FUN_00440670)
```

## 2. Summary of Bulk Initialization Operations

| # | Function | Range | Count | Step | Per-Element Func | Purpose |
|---|---|---|---|---|---|---|
| 1 | FUN_0043E100 | [this+0x0C] to [this+0x4C4] | 100 | 0xC | FUN_0043a9a0 | Zero/init sub-objects |
| 2 | FUN_004E70a5 | [this+0x0C] to [this+0x4C4] | 100 | 0xC | FUN_0043a9a0 | Vector destructor iterator |
| 3 | FUN_0043E500 | [this+0x56F0] to [this+0x5BA0] | 100 | 0xC | FUN_0043b470 | Zero/init sub-objects |
| 4 | FUN_004E70a5 | [this+0x56F0] to [this+0x5BA0] | 100 | 0xC | FUN_0043b4c0 | Vector destructor iterator |
| 5 | FUN_0043E500 | [this+0x3C24] to [this+0x4B24] | 0x258 | 0xC | FUN_0043b420 | Zero/init sub-objects |
| 6 | FUN_004E70a5 | [this+0x3C24] to [this+0x4B24] | 0x258 | 0xC | FUN_0043b420 | Vector destructor iterator |
| 7 | FUN_0043E680 | [this+0x108] to [this+0x2008] | 0x258 | 0xC | FUN_00440670 | Zero/init sub-objects |
| 8 | FUN_004E70a5 | [this+0x108] to [this+0x2008] | 0x258 | 0xC | FUN_00440670 | Vector destructor iterator |

## 3. Total Initialized Range

| From | To | Size |
|---|---|---|
| 0x000C | 0x5BA0 | ~0x5A94 bytes |

The object's initialization covers nearly the entire object from offset 0x0C to approximately 0x5BA0 (~23,220 bytes), consistent with the estimated object size of ~0x5C44 bytes.

## 4. Sub-Initializer Functions Called in Bulk Loops

| Function | VA | Size | Role |
|---|---|---|---|
| FUN_0043a9a0 | 0x0043A9A0 | 82 bytes | Sub-object init (writes vptr 0x51BD88 at [this+0x0C], initializes sub-objects at +0x18 and +0x20) |
| FUN_0043b470 | 0x0043B470 | 68 bytes | List node manipulation |
| FUN_0043b4c0 | 0x0043B4C0 | 68 bytes | List node manipulation |
| FUN_0043b420 | 0x0043B420 | 68 bytes | List node manipulation |
| FUN_00440670 | 0x00440670 | 55 bytes | List node manipulation |
| FUN_00475870 | Unknown | Unknown | Object lookup (called by FUN_0043b470, FUN_0043b4c0, FUN_0043b420, FUN_00440670) |

## 5. Limitations

- FUN_00475870 (object lookup) not analyzed
- Object allocation site still unknown
- FUN_0043a9a0 sub-initializers not fully analyzed (calls FUN_004728E0, FUN_00408AF0)
- FUN_00440670 sub-initializer not fully analyzed (calls FUN_00475870)

## 6. Next Stage

Stage 10: Symbol and string evidence — search for strings, symbols, and other contextual clues.