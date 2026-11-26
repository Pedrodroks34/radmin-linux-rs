# Phase 2.3 Stage 10 — Symbol and String Evidence

**Classification: PARTIALLY SUPPORTED** (some symbols found; no direct object identification)

## 1. Symbol Evidence from Ghidra

| Address | Name | Type | Classification |
|---|---|---|---|
| 0x43F110 | `std::_Facet_base::\`scalar_deleting_destructor'` | Destructor | VERIFIED — final table slot 0 |
| 0x4E70A5 | `eh_vector_destructor_iterator` | Bulk init helper | VERIFIED — called by constructors |
| 0x475870 | Unknown | Object lookup helper | UNKNOWN — called by multiple initializers |
| 0x474800 | Unknown | Unknown | UNKNOWN — called by FUN_0043a9a0 |
| 0x474870 | Unknown | Unknown | UNKNOWN — called by FUN_00414020 |

## 2. String Evidence

No string search tool was available in REA toolset. The following strings were observed as immediate values in disassembly:

| String/Value | VA | Context |
|---|---|---|
| 0x55E084 | 0x43E6B6 | Pushed to FUN_004831F0 in FUN_0043E680 |
| 0x55E444 | 0x46AE75, 0x46B9F8 | XADD.LOCK target (atomic counter) |
| 0x55E428 | 0x46AE87, 0x46BA0A | ECX for FUN_00403700 |
| 0x55E3FD | 0x46AE99, 0x46BA1F | Byte flag read |
| 0x55E264 | 0x43E4D1 | MOV [0x0055E264], 0 |
| 0x5190A4 | 0x475C11 | IAT — destructor call |
| 0x519204 | 0x48321B | IAT — called by FUN_004831F0 |
| 0x519200 | 0x48322F | IAT — called by FUN_004831F0 |
| 0x54A008 | 0x472928 | IAT — destructor called by FUN_004728E0 |

## 3. Symbol Analysis

### FUN_0043F110 — `std::_Facet_base::scalar_deleting_destructor`
This is a standard C++ STL facet base class destructor. Its presence as the final table's slot 0 strongly suggests the object (or a sub-object) uses C++ STL `std::locale::facet` or related locale infrastructure. This is consistent with the Radmin VPN service's locale/language handling.

### FUN_004E70A5 — `__eh_vector_destructor_iterator`
Standard C++ exception handling vector destructor iterator. Used for destroying arrays of objects with destructors. Confirms the binary uses C++ exception handling and object arrays.

### Atomic Counter at 0x55E444
FUN_0046AE70 and FUN_0046B9F0 both use XADD.LOCK on [0x55E444] with EAX=0, then XCHG with ESI. This is a global atomic counter, possibly a reference count or instance count for the object class.

### Global Flag at 0x55E3FD
Read as a byte in FUN_0046AE70 and FUN_0046B9F0. Written by FUN_0046B9F0 (`MOV [0x0055E3FD], AL`). This is a global flag.

### Global at 0x55E428
Used as ECX for FUN_00403700 in both FUN_0046AE70 and FUN_0046B9F0. Likely a global object pointer.

## 4. Symbol Analysis

No function names are directly available (no PDB symbols). All names are Ghidra-generated (`FUN_004XXXX`). The only exception is FUN_0043F110 which Ghidra identified as `std::_Facet_base::scalar_deleting_destructor` based on signature matching.

## 5. Limitations

- No string search tool available in REA toolset
- No PDB symbols available
- Function names are Ghidra-generated guesses
- No string literals found that directly identify the object's role

## 6. Next Stage

Stage 11: Caller and Cross-Module Analysis — search for callers of the constructor and related functions across the entire binary.