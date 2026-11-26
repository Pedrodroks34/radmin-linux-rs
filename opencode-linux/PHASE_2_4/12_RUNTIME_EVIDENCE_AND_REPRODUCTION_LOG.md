# Phase 2.4 Stage 12 — Runtime Evidence and Reproduction Log

**Classification: BLOCKED** (no Windows runtime debugging available in Linux environment)

## 1. Runtime Debugging Availability

| Capability | Status |
|------------|--------|
| Windows debugger (WinDbg/x32dbg/x64dbg) | NOT INSTALLED |
| Windows VM | NOT CONFIGURED |
| Live process (RvControlSvc.exe running) | NOT RUNNING |
| Debugger attached to process | N/A (no process) |
| Remote debugging | NOT AVAILABLE |

## 2. Static Analysis Performed

All analysis in Phase 2.4 is static REA/Ghidra analysis:

| Operation | Tool | Result |
|-----------|------|--------|
| Binary identity verification | sha256sum | SHA-256 matches expected |
| PE import table parsing | REA inspect_pe_imports | 14 DLLs, 327 functions |
| Function procedure info | REA procedure_info | 13 functions analyzed |
| Function pseudocode | REA procedure_pseudo_code | 11 functions decompiled |
| Raw byte extraction | REA read_bytes | All key addresses verified |
| Caller analysis | REA (via Ghidra) | Call graphs constructed |

## 3. Runtime Questions That Cannot Be Resolved Statically

| Question | Why Blocked | Required Evidence |
|----------|-------------|-------------------|
| Runtime vptr state at FUN_0044F3F0 | No execution trace | Breakpoint at 0x44F3F0, inspect [EDI] |
| Actual indirect-call targets | No runtime register values | Breakpoint at CALL [EAX+0x34]/[EAX+0x58] |
| Object allocation site | No constructor callers found | Breakpoint at HeapAlloc/RolClient_AllocMemory |
| Allocation size | No size argument observed | Capture HeapAlloc arguments |
| [0x00500ca6] target | No runtime memory read | Read memory at 0x500ca6 at breakpoint |
| AddRef function | Not found statically | Search for increment at obj+0x20 at runtime |

## 4. Reproduction Procedure (When Windows Debugger Available)

```
1. Launch RvControlSvc_Installed.exe under WinDbg/x64dbg
2. Set breakpoint at HeapAlloc (KERNEL32!HeapAlloc)
3. Capture: allocation size, returned pointer
4. Set breakpoint at FUN_0043E1A0 (constructor)
5. Capture: this pointer (ECX), compare with allocation pointer
6. Set breakpoint at constructor's 3 vptr writes
7. Capture: vptr value after each write
8. Set breakpoint at FUN_0044F3F0
9. Capture: [EDI] vptr value, field_0x28, field_0x2C, field_0x30
10. Set breakpoint at CALL [EAX+0x34] (0x44F501)
11. Capture: actual indirect call target
12. Set breakpoint at CALL [0x00500ca6] (0x4ec736)
13. Capture: resolved deallocation target
14. Read memory at [0x500ca6] to identify IAT slot value
```

## 5. Static Evidence Available for Reproduction

All static evidence is reproducible from the binary:

| Evidence | Location | Reproducible Via |
|----------|----------|------------------|
| Binary SHA-256 | 0e2e6eaacbe8ebe01286cda39a12eaad34a20434d50f4f8bf2fdd91d4d6ef2ad | sha256sum |
| Constructor disassembly | 0x43E1A0–0x43E4F0 | REA procedure_info/procedure_pseudo_code |
| Adjustment thunks | 0x43E85E–0x43E881 | Raw bytes: 83 E9 XX E9 XX XX 00 00 |
| Vtable tables | 0x51FFAC (A), 0x51E570 (B), 0x51E4F0 (C) | REA read_bytes |
| Indirect call sites | 0x44F501, 0x44F50D, 0x44F5AA, 0x44F5B6 | Raw bytes: FF 50 34 / FF 50 58 |
| Destruction chain | FUN_004e6cd7 → [0x500ca6] | REA procedure_pseudo_code |
| Refcount access | obj + 0x20 in FUN_004731E0 | REA procedure_pseudo_code |
| Allocator imports | PE import table | REA inspect_pe_imports |

## 6. Confidence Classification

| Question | Classification | Basis |
|----------|---------------|-------|
| All static findings are reproducible | CONFIRMED | Verified via REA tools |
| Runtime vptr state | BLOCKED | No Windows debugger |
| Runtime indirect call targets | BLOCKED | No Windows debugger |
| Object allocation at runtime | BLOCKED | No Windows debugger |
| Deallocation target at runtime | BLOCKED | No Windows debugger |