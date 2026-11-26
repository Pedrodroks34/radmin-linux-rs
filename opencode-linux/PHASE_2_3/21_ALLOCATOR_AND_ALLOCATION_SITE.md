# Phase 2.3 Stage 21 — Allocator and Allocation Site Analysis

**Classification: VERIFIED** (PE import directory parsed via REA `inspect_pe_imports`; all allocator APIs confirmed from import table)

## 1. Allocator APIs Found in PE Import Directory

The target binary imports **heap allocation APIs** from KERNEL32.dll and **custom allocator APIs** from RvROLClient.dll. This resolves the previously unresolved question Q2 (object allocation site) — allocators are present; the exact call site still needs to be traced.

| DLL | Function | Role | IAT RVA | Confidence |
|-----|----------|------|---------|------------|
| KERNEL32.dll | `HeapAlloc` | Heap memory allocation | 0x11941e | CONFIRMED (import table) |
| KERNEL32.dll | `HeapFree` | Heap memory deallocation | 0x11942a | CONFIRMED (import table) |
| KERNEL32.dll | `HeapReAlloc` | Heap memory reallocation | 0x119436 | CONFIRMED (import table) |
| KERNEL32.dll | `HeapSize` | Query heap block size | 0x11959c | CONFIRMED (import table) |
| KERNEL32.dll | `GetProcessHeap` | Get process heap handle | 0x11957a | CONFIRMED (import table) |
| RvROLClient.dll | `ROLClient_AllocMemory` | Custom ROL client allocation | 0x1199c0 | CONFIRMED (import table) |
| RvROLClient.dll | `ROLClient_FreeMemory` | Custom ROL client deallocation | 0x11998c | CONFIRMED (import table) |
| ole32.dll | `CoTaskMemFree` | COM task memory deallocation | 0x119942 | CONFIRMED (import table) |
| KERNEL32.dll | `LocalFree` | Local memory deallocation | 0x117cd4 | CONFIRMED (import table) |

**No `malloc`, `operator new`, `CoTaskMemAlloc`, or `VirtualAlloc` found** in the import directory. The allocation pattern is `HeapAlloc(GetProcessHeap(), flags, size)` or `ROLClient_AllocMemory(size)`.

## 2. Object Allocation Site — Still Unresolved

Despite finding allocator APIs, **no direct call to `HeapAlloc` or `ROLClient_AllocMemory` was found in the constructor `FUN_0043E1A0`** or its sub-initializers. The constructor initializes fields up to offset `0x5C40` but does not call any allocator.

**Possible explanations (all unverified):**

1. **Object is stack-allocated or embedded in a parent object** — The caller allocates space and passes `this` via ECX (`__fastcall`). No heap allocation in the constructor itself.

2. **Object is allocated by a factory function** not yet identified — A separate function calls `HeapAlloc` then calls the constructor. This factory function has not been found in the call graph (the constructor's callers are only 5 adjustment thunks, which have no callers).

3. **Object is allocated via `ROLClient_AllocMemory`** from RvROLClient.dll — This is a custom allocator in the ROL client library. The constructor does not call it directly, but a factory/wrapper might.

4. **Object is globally allocated** — A global/static object instance exists in `.data` or `.bss`, and the constructor initializes it in place.

## 3. Object Size — Unknown

No `HeapAlloc` call with a size argument was found in the constructor or any analyzed function. The constructor initializes fields up to offset `0x5C40` (23,744 bytes), and a zeroing loop covers `0x0C`–`0x4C4`. The actual object size cannot be confirmed without finding the allocation call.

**Upper bound estimate:** Fields initialized up to `0x5C40`, suggesting the object is at least 0x5C40 bytes (~23 KB). The true size could be larger if fields beyond `0x5C40` exist but were not observed in the constructor disassembly.

## 4. Allocation/Deallocation Symmetry

The destruction path is now fully traced:

```
Object release (FUN_004731E0: refcount decrement at +0x20)
  → FUN_00473210 (destroy if refcount reaches 0)
    → List cleanup functions (FUN_00440670, FUN_0043B470, FUN_0043B4C0, FUN_0043B420, FUN_0043A9A0)
      → FUN_004e6cd7(node) per node
        → thunk_FUN_004ec736 (JMP 0x4ec736)
          → FUN_004ec736
            → CALL dword ptr [0x00500ca6]  ← DEALLOCATION
```

The indirect call through `[0x00500ca6]` is the deallocation entry point. This IAT slot likely contains `HeapFree` or `ROLClient_FreeMemory`. The `[0x00500ca6]` address is in the `.data` section (VA 0x500ca6 → RVA 0x100ca6 → raw offset in `.data`).

## 5. Impact on Rust Compatibility

| Windows Pattern | Rust Equivalent | Notes |
|-----------------|-----------------|-------|
| `HeapAlloc(GetProcessHeap(), ...)` / `ROLClient_AllocMemory` | `Box::new()`, `Vec::new()`, `Arc::new()` | Object allocation |
| `HeapFree` / `ROLClient_FreeMemory` | `Drop` trait, `Arc::strong_count() == 0` | Object deallocation |
| Reference count at `obj + 0x20` with `LOCK()`/`UNLOCK()` | `Arc<T>` / `Rc<T>` + `AtomicUsize` | Thread-safe refcounting |
| `FUN_004e6cd7` → indirect call `[0x00500ca6]` | Custom `Drop::drop()` | Deallocation hook |

## 6. Remaining Unknowns

| Unknown | Impact | Blocks Rust? |
|---------|--------|--------------|
| Exact allocation call site (which function calls HeapAlloc/RolClientAllocMemory) | Cannot determine object size or who owns initial allocation | No |
| Object size (bytes) | Cannot confirm exact memory layout | No |
| Value stored at IAT slot `[0x00500ca6]` | Cannot confirm which deallocator is called at destruction | No |
| Whether `FUN_00473210` calls `HeapFree` or `ROLClient_FreeMemory` | Cannot confirm deallocation symmetry | No |