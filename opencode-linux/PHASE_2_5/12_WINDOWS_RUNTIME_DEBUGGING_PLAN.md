# Phase 2.5 Stage 12 — Windows Runtime Debugging Plan

**Classification: BLOCKED** (no Windows debugger available on Linux; plan prepared for Windows execution)

## 1. Purpose

Provide a precise, reproducible Windows runtime-debugging plan to resolve the remaining Phase 2.5 blockers.

## 2. Prerequisites (Not Met on Linux)

| Prerequisite | Status |
|--------------|--------|
| Windows host or VM | NOT AVAILABLE |
| x64dbg / x32dbg / WinDbg | NOT INSTALLED |
| RvControlSvc_Installed.exe | Accessible at `/home/rhuan/Desktop/opencode/RvControlSvc_Installed.exe` |
| PDB symbols | NOT AVAILABLE (Ghidra reports load state unknown) |

## 3. Debugger Execution Plan

### Breakpoint 1 — Object Allocation

**Candidate APIs:**
- `KERNEL32!HeapAlloc`
- `RvROLClient!RolClient_AllocMemory`

**Capture at breakpoint:**
- Arguments (hHeap, dwFlags, dwBytes for HeapAlloc)
- Return pointer (EAX)
- Allocation size
- Caller return address
- Full stack trace
- Relationship between returned pointer and constructor `this` (ECX at FUN_0043E1A0 entry)

### Breakpoint 2 — Constructor Entry

**Address:** `0x0043E1A0` (FUN_0043E1A0)

**Capture at breakpoint:**
- ECX (`this` pointer)
- EDI
- ESP, EBP
- Stack arguments (if any)
- Object pointer = ECX
- Compare object pointer with allocation pointer from Breakpoint 1

**At each vptr write breakpoint:**
| Address | Instruction | Capture |
|---------|-------------|---------|
| 0x43E1B1 | `MOV [EDI], 0x51FFB4` | Vptr value after write |
| 0x43E4C8 | `MOV [EDI], 0x51E570` | Vptr value after write |
| 0x43E4E8 | `MOV [EDI], 0x51E4F0` | Vptr value after write |

### Breakpoint 3 — Virtual Dispatch

**Address:** `0x0044F3F0` (FUN_0044F3F0)

**Capture at breakpoint:**
- EDI (`this` pointer)
- `[EDI]` (current vptr)
- `[EDI+0x28]` (field_0x28)
- `[EDI+0x2C]` (field_0x2C)
- `[EDI+0x30]` (field_0x30)

**At each indirect CALL:**
| Address | Instruction | Capture |
|---------|-------------|---------|
| 0x44F501 | `CALL [EAX+0x34]` | EAX value, computed target address, actual destination |
| 0x44F50D | `CALL [EAX+0x58]` | EAX value, computed target address, actual destination |
| 0x44F5AA | `CALL [EAX+0x34]` | EAX value, computed target address, actual destination |
| 0x44F5B6 | `CALL [EAX+0x58]` | EAX value, computed target address, actual destination |

**Expected corrected targets (from Stage 03):**
| Vptr | [vptr+0x34] Address | Target | [vptr+0x58] Address | Target |
|------|---------------------|--------|---------------------|--------|
| 0x51FFB4 | 0x51FFE8 | 0x4510A0 → 0 | 0x52000C | 0x450FA0 → ? |
| 0x51E570 | 0x51E5A4 | 0x4510B0 → 16 | 0x51E5C8 | 0x450FC0 → ? |
| 0x51E4F0 | 0x51E524 | 0x4510B0 → 16 | 0x51E548 | 0x450FC0 → ? |

### Breakpoint 4 — Reference Count Operations

**Addresses:** `0x004731E0` and `0x00473210`

**Capture at FUN_004731E0 entry:**
- Object pointer (ECX)
- `[obj+0x20]` before atomic read
- `[obj+0x20]` after (should be same — just a read)
- Branch result (taken/not taken to FUN_00473210)

**Capture at FUN_00473210 entry:**
- Object pointer (ECX)
- `[obj+0x8]` (critical section address)
- `[obj+0x20]` before store
- `[obj+0x20]` after store (should be 0)
- `[obj+0x24]` before exchange
- `[obj+0x24]` after exchange (should be 1)
- Return value (EDX:EAX)

### Breakpoint 5 — Indirect Deallocation

**Address:** `0x004EC736` (FUN_004ec736)

**Capture at breakpoint:**
- Instruction at CALL site: `CALL DWORD PTR [0x500CA6]`
- Memory contents at `[0x500CA6]` before the call
- Resolved call target
- Stack arguments (the `_Memory` parameter)
- Caller (FUN_004ec736 → thunk → FUN_004e6cd7 → list cleanup)
- Module containing the destination

## 4. Reproduction Procedure

```
1. Copy RvControlSvc_Installed.exe to Windows VM
2. Launch under x64dbg/x32dbg/WinDbg
3. Set all breakpoints listed above
4. Run the executable
5. At each breakpoint, capture register and memory state
6. Correlate allocation pointer with constructor this pointer
7. Correlate vptr state with indirect dispatch target
8. Record the actual deallocation target of CALL [0x500CA6]
9. Compare all observations against Stage 03 corrected dispatch matrix
```

## 5. Expected Outcomes

| Question | Expected Evidence | Resolves Blocker? |
|----------|-----------------|-------------------|
| Object allocation site | Breakpoint at HeapAlloc/RolClientAllocMemory | B1 |
| Object allocation size | dwBytes argument at allocation breakpoint | B2 |
| Runtime vptr state | [EDI] at FUN_0044F3F0 breakpoint | B3 |
| Indirect call targets | Actual destination at each CALL breakpoint | B4 |
| Deallocation target | Memory at [0x500CA6] at CALL breakpoint | B7 |
| FUN_00473210 behavior | Already resolved statically | B5 (resolved) |
| AddRef function | Not addressable via breakpoints (need to find increment) | B6 |