# Phase 9D — Object Identity Matrix

For every dispatch class in the chain, the full identity evidence.

## Class identity matrix

| Attribute | FUN_00421410-class | FUN_00417850-class | FUN_0041ea00-class |
|---|---|---|---|
| Allocation size | 0x258 = 600 B | 0x2d0 = 720 B | 0x2d0 = 720 B |
| Constructor | `FUN_00421410` | `FUN_00417850` | `FUN_0041ea00` |
| Created by | `FUN_0042d980` (via `0042daf2`) | `FUN_00424550` (via `004245f6`) | `FUN_00417850` (via `00417bc6`) |
| Creator allocation call | `0042d2f8` (FUN_0042d2a0) and `0042d3f6` (FUN_0042d3a0) | `00422230` (FUN_00422150) and `00422340` (FUN_00422260) | `00417bc6` (FUN_00417850) |
| Allocation path | `FUN_004e5a66 → FUN_004018a0 → __malloc_base → HeapAlloc(0x005a61a0, 0, size)` — flag 0, memory **not zeroed** | same | same |
| Primary vtable | `0x0051b248` (phase 2) | `0x0051ae28` | `0x0051afd8` |
| Secondary vtable | `0x0051b254` | `0x0051ae30` | `0x0051afe0` |
| Sub-object vtable | `0x0051a984` (phase 2) | `0x0051ae44` | `0x0051b004` |
| Group A active? | **No** (no P/CAS set) | **Yes** | **No** |
| Group B active? | **No** | **No** | **Yes** |
| Group C active? | **No** | **No** | **Yes** (dead path) |
| `+0x214` gate context | **Yes — this class** (`FUN_00422f20`, `FUN_004230c0`) | No | No |
| e220/e280 directly routed | No | Yes (e220: 10 callers, e280: 0 direct) | Yes (e280: 22 callers, e220: 2 direct) |
| Final indirect target | n/a | `FUN_004e7650` (CFG-instrumented global-callback dispatch stub) | `FUN_004e7650` |

## Object-member matching — provenance of each store

| Offset | FUN_00421410-class | FUN_00417850-class | FUN_0041ea00-class |
|---|---|---|---|
| `[obj+0x0]` | `0x0051b248` (phase 2) | `0x0051ae28` | `0x0051afd8` |
| `[obj+0x08]` | `0x0051b254` (phase 2) | `0x0051ae30` | `0x0051afe0` |
| `[obj+0x10]` | — (not written) | `0x0051ae44` | `0x0051b004` (phase 1) |
| `[obj+0x14]` | — | — | **0x00000000** |
| `[obj+0x18]` | — | — | **0x00000000** |
| `[obj+0x1c]` | — | — | **0x0051b01c** |
| `[obj+0x20]` | — | — | **0x00000000** |
| `[obj+0x28]` | — (NOT written) | `0x0051a984 → 0x0051ae58` | `0x0051b004`? (via phase 1 → `0x0051b004`) |
| `[obj+0x2c]` | — (NOT written) | **0x00000000** | — |
| `[obj+0x34]` | — (NOT written) | **0x0051aee0** | — |
| `[obj+0x38]` | — (NOT written) | **0x00000000** | — |
| `[obj+0x214]` | **0x00000000** | — | — |
| `[obj+0x238]` | **0x00000000** (byte) | — | — |
| `[obj+0x244]` | — | **0x00519e54** | — |

## Object-chain certainty summary

| Step | Object type | Evidence class |
|---|---|---|
| Allocation 0x258 bytes | FUN_00421410-class | DIRECTLY VERIFIED |
| Allocation 0x274 bytes | child FUN_00417850-class | DIRECTLY VERIFIED |
| Allocation 0x2d0 bytes | grandchild FUN_0041ea00-class | DIRECTLY VERIFIED |
| Parent gets `FUN_00421410` | FUN_00421410-class only | DIRECTLY VERIFIED |
| Parent → child link via `FUN_00424550` | FUN_00421410-class → FUN_00417850-class | DIRECTLY VERIFIED |
| Child → grandchild link via `FUN_00417850` | FUN_00417850-class → FUN_0041ea00-class | DIRECTLY VERIFIED |
| Child reads parent's `[ESI+0x1b0]` via `LEA ECX,[ESI + 0x1b0]` at `004216dd/ee` region | parent-contains-child relationship | DIRECTLY VERIFIED |
| Object reaches e280 dispatch at 0041a7f1/00423239 | FUN_00417850-class library dispatch | STRONGLY SUPPORTED |
| Object reaches e220 dispatch at `0041b05a`/`0041bd36`/`0041c03a` | FUN_00417850-class | STRONGLY SUPPORTED |

## Gaps in identity attribution

1. **How the runtime selects which derived-type object to dispatch via each vtable slot** — vtables point at the FUN_004e7650 stub universally; the derived-type selection must come from the Radmin framework's own dispatch into the object creation API (e.g., `SpawnSession`, `JoinVpnNetwork`-like entry points). Not traceable from lower-level inspection without identifying the Windows-side service callback.
2. **Session-binding moment** — vtable slots at 0051ae38 (`FUN_0041df20`) etc. suggest a binding pattern (Radmin VPN service calls the method from its top-level dispatcher). Identity of that caller is unknown.
3. **Whether these classes are actually instantiated at runtime or only at process launch** — construction happens in `FUN_0044d600` (`call sites targeting 0042d2a0` — `from_function=FUN_0044d600` and `FUN_0044d140`); that function is the Radmin VPN manager's `StartSession`-equivalent. Narrowing down which session type uses which object class is beyond this phase's scope.
