# Phase 2.3 Stage 8 — VPtr State and Dispatch Analysis

**Classification: STRONGLY SUPPORTED** (all vptr states and call targets verified via raw byte extraction)

## 1. VPtr State Transitions

The constructor `FUN_0043E1A0` writes three different vtable pointers to `[EDI+0x00]`:

| Phase | VA | Instruction VA | Raw Bytes | Table | Slot 0 Target |
|---|---|---|---|---|---|
| Initial | 0x0051FFB4 | 0x43E1B1 | C7 03 B4 FF 51 00 | Table A (slot 2) | FUN_0043ECF0 |
| Overwrite #2 | 0x0051E570 | 0x43E4C8 | C7 03 70 E5 51 00 | Intermediate table | FUN_0043EED0 |
| Final | 0x0051E4F0 | 0x43E4E8 | C7 03 F0 E4 51 00 | Final table | FUN_0043F110 |

## 2. Indirect Call Resolution Matrix

The function `FUN_0044F3F0` makes two indirect calls guarded by `field_0x28==5 && field_0x2C!=0`:

| Call Site | VA | Guard | VPtr State | [EAX+0x34] Target | Returns | [EAX+0x58] Target | Returns |
|---|---|---|---|---|---|---|---|
| Pair 1 | 0x44F501 | field_0x28==5 && field_0x2C!=0 | 0x51FFB4 | FUN_004510A0 | 0x10 | FUN_00450FA0 | 0 or 0xC5 |
| Pair 1 | 0x44F501 | field_0x28==5 && field_0x2C!=0 | 0x51FFAC | FUN_00451010 | 0 | FUN_00451070 | 0 |
| Pair 1 | 0x44F501 | field_0x28==5 && field_0x2C!=0 | 0x51E570 | FUN_004510B0 | 0x10 | FUN_00451090 | 0 |
| Pair 1 | 0x44F501 | field_0x28==5 && field_0x2C!=0 | 0x51E4F0 | FUN_004510B0 | 0x10 | FUN_00451090 | 0 |
| Pair 2 | 0x44F5AA | field_0x28==5 && field_0x2C!=0 | 0x51FFB4 | FUN_004510A0 | 0x10 | FUN_00450FA0 | 0 or 0xC5 |
| Pair 2 | 0x44F5AA | field_0x28==5 && field_0x2C!=0 | 0x51FFAC | FUN_00451010 | 0 | FUN_00451070 | 0 |
| Pair 2 | 0x44F5AA | field_0x28==5 && field_0x2C!=0 | 0x51E570 | FUN_004510B0 | 0x10 | FUN_00451090 | 0 |
| Pair 2 | 0x44F5AA | field_0x28==5 && field_0x2C!=0 | 0x51E4F0 | FUN_004510B0 | 0x10 | FUN_00451090 | 0 |

## 3. Target Function Details

### FUN_004510A0 (0x4510A0, 3 bytes)
```
MOV EAX, 0x10
RET
```
Returns constant 0x10 (16).

### FUN_00451010 (0x451010, 3 bytes)
```
XOR EAX, EAX
RET
```
Returns constant 0.

### FUN_004510B0 (0x4510B0, 6 bytes)
```
MOV EAX, 0x10
RET
```
Returns constant 0x10 (16).

### FUN_00451070 (0x451070, 3 bytes)
```
XOR EAX, EAX
RET
```
Returns constant 0.

### FUN_00451090 (0x451090, 3 bytes)
```
XOR EAX, EAX
RET
```
Returns constant 0.

### FUN_00450FA0 (0x450FA0, 31 bytes, 4 blocks)
```
PUSH EBP
MOV EBP, ESP
MOV EAX, dword ptr [EBP + 0x8]   ; param_1
CMP EAX, 0x2
JZ 0x00450fb9                    ; if param_1 == 2: return 0
CMP EAX, 0x20
JZ 0x00450fb9                    ; if param_1 == 0x20: return 0
MOV EAX, 0x0c5                   ; return 0xC5 (197)
POP EBP
RET 0x4
...
0x450fb9: XOR EAX, EAX           ; return 0
POP EBP
RET 0x4
```
Returns 0 if param_1 == 2 or 0x20; returns 0xC5 (197) otherwise.

## 4. Guard Condition Analysis

Both indirect call pairs are guarded by:
```
CMP dword ptr [EDI+0x28], 0x5    ; field_0x28 == 5
JNZ skip                         ; if not equal, skip
CMP dword ptr [EDI+0x2C], 0x0    ; field_0x2C != 0
JZ skip                          ; if zero, skip
```

Writers for field_0x28 found in 15+ functions. Writers for field_0x2C found in 7 functions. field_0x30 is incremented ONLY in FUN_0044F3F0 (2 call sites), but initialized to 0 by FUN_00410E80 and FUN_00410F60.

## 5. Key Findings

1. **VPtr transitions during construction:** The object's vptr changes 3 times during construction, meaning different code paths see different vtable layouts.

2. **Indirect call targets depend on vptr state:** Under the initial vptr, `[EAX+0x34]` returns 0x10 and `[EAX+0x58]` does parameter checking. Under intermediate/final vptrs, both calls return constants (0x10 and 0 respectively).

3. **Guard condition:** Both calls are only executed when `field_0x28==5 && field_0x2C!=0`. Writers for field_0x28 found in 15+ functions. Writers for field_0x2C found in 7 functions. field_0x30 is incremented ONLY in FUN_0044F3F0 (2 call sites), but initialized to 0 by FUN_00410E80 and FUN_00410F60.

## 6. Limitations

- Runtime vptr state unknown — cannot determine which dispatch path is taken at runtime
- field_0x28 and field_0x2C writers found in many functions but initial values unknown
- FUN_00451090 body now analyzed — returns 0
- FUN_00450FA0 parameter semantics unknown

## 7. Next Stage

Stage 9: Bulk initialization analysis — investigate `memset`-like operations and bulk initialization in the constructor.