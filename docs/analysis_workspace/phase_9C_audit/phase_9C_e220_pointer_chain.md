# Phase 9C — Pointer Chain A: `FUN_0041e220` indirect call at `0041e26f`

**Target instruction:** `0041e26f  FF12  CALL dword ptr [EDX]` (`listing/0041e220.asm`)
**References records for `0041e26f`:** none — `0041e26f` is `COMPUTED_CALL` territory but the actual dispatcher records are produced for the *caller* edges; the instruction has no `references.jsonl` entry of its own as a *target* (it is internal to the dispatcher), and its `from` would be logged as `COMPUTED_CALL` if any reference pointed to it — none does (`BUILD`-internal indirections are referenced by `INDIRECTION` only for IAT stubs). The reference layer records `COMPUTED_CALL` for the *callers of* `FUN_0041e220`, not inside it.

## 1. Full instruction trace (every register definition reaching the call)

```
0041e225  8BF9                 MOV EDI,ECX                  ; EDI := this (the dispatching object — Group A: caller passed ECX = base+0x28)
0041e227  BA3F420F00           MOV EDX,0xf423f              ; CAS1 replacement sentinel
0041e22c  33C0                 XOR EAX,EAX                  ; accumulator = 0
0041e22e  8D7704               LEA ESI,[EDI + 0x4]          ; ESI := &[this+0x04]
0041e231  F00FB116             CMPXCHG.LOCK dword ptr [ESI],EDX   ; CAS1: [this+0x04] vs 0 → if ==0 store 0x000f423f and ZF=1
0041e235  85C0                 TEST EAX,EAX
0041e237  750F                 JNZ 0x0041e248                ; if old [this+0x04] != 0, skip CAS1-success block
0041e239  8B4D08               MOV ECX,dword ptr [EBP + 0x8]      ; ECX := arg1
0041e23c  8D4604               LEA EAX,[ESI + 0x4]                ; EAX := &[this+0x08]
0041e23f  8708                 XCHG dword ptr [EAX],ECX           ; atomically swap [this+0x08] ↔ arg1
0041e241  B806000000           MOV EAX,0x6                        ; replacement = 6
0041e246  8706                 XCHG dword ptr [ESI],EAX           ; atomically swap [this+0x04] ↔ 6 (into 0xf423f state)
0041e248  BA01000000           MOV EDX,0x1                  ; CAS2 replacement = 1
0041e24d  8D4F10               LEA ECX,[EDI + 0x10]         ; ECX := &[this+0x10]
0041e250  33C0                 XOR EAX,EAX                  ; accumulator = 0
0041e252  F00FB111             CMPXCHG.LOCK dword ptr [ECX],EDX   ; CAS2: [this+0x10] vs 0 → if ==0 store 1
0041e256  85C0                 TEST EAX,EAX
0041e258  751E                 JNZ 0x0041e278                ; if old [this+0x10] != 0, skip the work block
0041e25a  FF1580725100         CALL dword ptr [0x00517280]        ; GetLastError (IAT slot 0x00517280 = KERNEL32.DLL::GetLastError hint 0x264=612 — verified vs PE directory and objdump -p)
0041e260  8B4F0C               MOV ECX,dword ptr [EDI + 0xc]      ; P := [this+0x0C]
0041e263  8BF0                 MOV ESI,EAX                        ; ESI := GetLastError result (saved)
0041e265  8B4904               MOV ECX,dword ptr [ECX + 0x4]      ; D := [P + 0x04]
0041e268  83C10C               ADD ECX,0xc                        ; ECX := D + 0x0C
0041e26b  03CF                 ADD ECX,EDI                        ; A  := D + 0x0C + EDI
0041e26d  8B11                 MOV EDX,dword ptr [ECX]            ; V  := [A]   (memory read)
0041e26f  FF12                 CALL dword ptr [EDX]               ; CALL [V]      (memory-indirect call)
0041e271  56                   PUSH ESI                           ; PUSH GetLastError result
0041e272  FF1560725100         CALL dword ptr [0x00517260]        ; SetLastError (IAT slot 0x00517260 = KERNEL32.DLL::SetLastError hint 0x534=1332 — verified)
0041e278  POP EDI ; POP ESI ; POP EBP ; RET 0x4
```

## 2. Pointer expression (exact, in order of dereference)

| Step | Register | Expression | Dereferences to |
|---|---|---|---|
| 1 | `EDI` | `this` — caller-supplied `ECX` at entry. Group A callers pass `base+0x28`, Group B `base+0x10`, Group C `base+0x08` | — |
| 2 | `ECX` | `P = [EDI + 0x0C]` | read 1 (P is loaded from object memory) |
| 3 | `ECX` | `D = [P + 0x04]` | read 2 |
| 4 | `ECX` | `A = EDI + D + 0x0C` | — |
| 5 | `EDX` | `V = [A]` | read 3 |
| 6 | call target | `[V]` | read 4 (the CALL itself) |

**Target expression: `target = *(*(EDI + D + 0x0C))` with `D = *(P + 4)`, `P = *(EDI + 0x0C)`.**

As a C-like annotation (not actual C): `target = V->…` where `V = *(EDI + *(P+4) + 0x0C)`.

## 3. Step-by-step provenance of each node

- **N0 (EDI / this):** Object base — sub-object inside the parent dispatch object created by `FUN_00421410`. The gate functions (`FUN_00422f20`/`FUN_004230c0`) hold the parent; dispatcher receives adjusted pointer from callers. Offsets from one base: `EDI+0x4`, `EDI+0x8`, `EDI+0xc`, `EDI+0x10` all live inside the parent.
- **N1 (P = [EDI+0x0C]):** NOT initialized by the parent constructor (no store to `[EDI+0x0C]` or `[EDI+0x18]`-to-`[EDI+0x0C]` path — verified the constructor's full store list; `[EDI+0x0C]` is never written). Producer for the sub-object `P`: none found in this export *attributed to dispatch objects*. **P is a runtime pointer, not a static table pointer** (as demonstrated for the different 16650 chain, where the field IS static-initialized — see `phase_9C_16650_pointer_chain.md`).
- **N2 (D = [P+0x04]):** `P` points to a structure whose `+0x04` holds another pointer `D`. No writer to `[P+0x04]` tied to object identity exists in the export (producers not isolated; the 403 `[reg+0x0C]` store sites are unrelated masses). **D is a runtime pointer**.
- **N3 (A = EDI + D + 0x0C):** computed address into whatever structure `D` denotes, offset `0x0C` — the read of `V = [A]` expects `A` to land on a dword containing a function pointer or code address (it is dereferenced again).
- **N4 (V = [A]) and call target = [V]):** one last indirection level. `V` itself is a pointer read from `[A]`; the call jumps to `[V]` — i.e. the CPU reads `[V]` as the branch target. Note: this is **two dereferences after V's computation**; the object graph `this -> P -> D -> A -> V -> target` is four pointer hops minimum plus the initial base.

## 4. Static resolvability

| Node | Statically resolvable? | Evidence |
|---|---|---|
| `EDI` | only conditionally | adjusted sub-object pointer, static only per-group |
| `P = [EDI+0x0C]` | **NO** | no static producer in export; runtime state (unknown heap contents) |
| `D = [P+0x04]` | **NO** | same |
| `A` | no | depends on D |
| `V = [A]` | **NO** | depends on A |
| final target | **NO** | depends on V |

**The indirect target is not statically resolvable in this export.** Any tool claiming a concrete callee for `0041e26f` is inventing information.

## 5. Writers / producers relevant to the chain (searched with the validated tooling)

- Stores to any `[reg + 0x0C]` in the whole export: 403 sites (mostly `[EBP+0x0C]` stack slots); none provably targets a dispatch object (no dispatch-object-escape analysis is possible statically without dataflow through the entire call graph).
- Stores to `[reg + 0x04]` in the whole export: same scale; the CAS-blocking gate writes `[adjusted+0x4] ← (XCHG [EAX],ECX)` with `ECX = arg1` — the **only in-export writer that provably writes into the N1-adjacent field** is the dispatch CAS1 itself (`0041e23f`, `0041e246`), with value = caller-supplied arg1. That sets `[this+0x8]` and `[this+0x4]` — **not** `[this+0x0C]`.
- `[this+0x0C]` (P) and `[P+0x04]` (D): no writer attributed to this chain in the export — **NOT PROVEN ABSENT**; just not isolated. See `phase_9C_previous_claims_verification.md` §"producers".

## 6. Reconciliation with prior reports

- The 8R indirect-call report's trace (`P` → `D` → `A` → `V`) **reproduces exactly**, including the `+0x0C` offsets and the absence of a direct-reference target.
- What this phase adds: the exact accumulator name/address mapping (N0..N4), the proven IAT slots and their verified names (GetLastError/SetLastError), and the proof that the CAS1 path stores `0x00000006` into `[this+0x4]` on the CAS-success path (EDX replacement = `MOV EAX,0x6` — not a sentinel error code; it is the "in-progress" state 6 used by the spin protocol alongside `0xf423f`).

## 7. Assessment

- The pointer chain is **reconstructible exactly** as far as memory layout goes; the register trace is unambiguous.
- The **target is unknown and unresolvable statically**.
- The dispatch is behind two gates (`[this+0x4] != 0` skip via CAS1 `0041e237 JNZ`; `[this+0x10] != 0` skip at `0041e258 JNZ`) **plus** the implicit-heap-garbage issue for `P`/`D`.
- "No writer found in the export" for `P` is a statement about **this binary only**; an external agent (DLL, debugger, or memory corruption) can populate `P` at any time — the function is exported only in the sense that the parent object holds it callable (via vtable at `+0x8/+0x18` tables) — so reachability via vtable is guaranteed.
