# Phase 2.5 Stage 08 — Object Field Initialization Reconstruction

**Classification: PARTIALLY RESOLVED** (writer analysis complete for known functions; 8 sub-initializers not yet analyzed)

## 1. Purpose

Investigate field initialization for offsets `0x20`, `0x28`, `0x2C`, and `0x30`, correcting Phase 2.4's unresolved initial values.

## 2. Field Writer Matrix

| Offset | Constructor Write? | Sub-Initializer Write? | Other Writers | Initial Value | First Read | Initialized Before Read? |
|--------|-------------------|----------------------|---------------|---------------|------------|-------------------------|
| 0x00 | YES (3× vptr writes) | Unknown | Unknown | 0x51FFB4 → 0x51E570 → 0x51E4F0 | FUN_0044F3F0 (MOV EAX,[EDI]) | YES |
| 0x04 | Unknown | Unknown | Unknown | Unknown | Unknown | UNKNOWN |
| 0x0C | YES (zeroing loop) | Unknown | Unknown | 0 | Unknown | YES |
| 0x20 | NO | Unknown | FUN_004731E0 (read), FUN_00473210 (store 0) | UNKNOWN | FUN_004731E0 | NO |
| 0x28 | NO | Unknown | 17 sites, 15 functions | UNKNOWN | FUN_0044F3F0 (CMP to 5) | NO |
| 0x2C | NO | Unknown | 7 sites, 7 functions | UNKNOWN | FUN_0044F3F0 (CMP to 0) | NO |
| 0x30 | NO | Unknown | FUN_00410E80 (init 0), FUN_00410F60 (init 0), FUN_0044F3F0 (INC) | 0 | FUN_0044F3F0 (INC only) | YES |

## 3. Critical Finding: Fields Not Initialized by Constructor

The constructor `FUN_0043E1A0` does NOT write to:
- `obj + 0x20` (refcount)
- `obj + 0x28` (state field, compared to 5)
- `obj + 0x2C` (handle/flag field, compared to 0)

This means their initial values are set by:
1. Memory allocation (zero-initialized heap?)
2. A caller before constructor invocation
3. An unanalyzed sub-initializer
4. A factory function

## 4. Guard Condition Implications

`FUN_0044F3F0` requires `field_0x28 == 5 && field_0x2C != 0` before making indirect calls. Since neither field is initialized by the constructor:

**Scenario A — Zero-initialized memory:** If the object is allocated with `HeapAlloc` (which zero-initializes), then `field_0x28 = 0` and `field_0x2C = 0` initially. The guard `field_0x28 == 5` would fail, and indirect calls would never execute unless some other function sets these fields first.

**Scenario B — Non-zero initialization:** If a factory or caller sets these fields before `FUN_0044F3F0` executes, the guard could be satisfied.

**Scenario C — Guard never satisfied:** If these fields are never set to the required values, `FUN_0044F3F0`'s indirect calls are dead code.

## 5. Field_0x30 — Best Understood Field

| Writer | Address | Value | Confidence |
|--------|---------|-------|------------|
| FUN_00410E80 | 0x410EBD | 0 | CONFIRMED |
| FUN_00410F60 | 0x410F9D | 0 | CONFIRMED |
| FUN_0044F3F0 | 0x44F4FE | Increment (+1) | CONFIRMED |

**Initial value:** 0 (set by FUN_00410E80 or FUN_00410F60 before FUN_0044F3F0 reads it).

**Purpose:** Call counter — incremented each time FUN_0044F3F0 passes the guard.

## 6. Unresolved Questions

| Question | Evidence Needed |
|----------|-----------------|
| Who initializes obj+0x20? | Search all writes to obj+0x20 |
| Who initializes obj+0x28? | Search all writes to obj+0x28 |
| Who initializes obj+0x2C? | Search all writes to obj+0x2C |
| Are 8 unanalyzed sub-initializers writing these fields? | Analyze FUN_0047A8A0, FUN_0043E500, FUN_00403540, FUN_004728E0, FUN_00483750, FUN_0043E680, FUN_0047BB20, FUN_00475B70, FUN_00479240 |
| Is memory zero-initialized before constructor? | Find allocation call site |

## 7. Confidence Classification

| Question | Classification | Basis |
|----------|---------------|-------|
| Constructor doesn't write obj+0x20 | CONFIRMED | Full constructor disassembly reviewed |
| Constructor doesn't write obj+0x28 | CONFIRMED | Full constructor disassembly reviewed |
| Constructor doesn't write obj+0x2C | CONFIRMED | Full constructor disassembly reviewed |
| field_0x30 initialized to 0 | CONFIRMED | FUN_00410E80/FUN_00410F60 write 0 |
| Guard condition satisfiable | UNKNOWN | Depends on unanalyzed field initialization |
| field_0x28 initial value | UNKNOWN | No writer found in constructor |
| field_0x2C initial value | UNKNOWN | No writer found in constructor |