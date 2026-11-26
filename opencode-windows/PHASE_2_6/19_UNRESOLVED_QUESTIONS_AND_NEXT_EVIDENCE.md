# Phase 2.6 Stage 19 — Unresolved Questions and Next Evidence

**Classification: HONEST DOCUMENTATION** — every question remaining after this phase is listed, with evidence already inspected, why it remains unresolved, exact next evidence required, and priority. No hypothesis is presented as fact.

Cross-reference: all Phase 2.6 reports 01–18, especially `16_COMPLETE_OBJECT_LIFECYCLE_AND_OWNERSHIP_GRAPH.md`.

---

## 1. Unresolved Question Register

| # | Question | Classification | Evidence already inspected | Why unresolved | Exact next evidence required | Priority |
|---|----------|----------------|---------------------------|----------------|------------------------------|----------|
| U1 | Object allocation call site (which function allocates `ObjectCandidate`, with what size) | BLOCKED | Constructor `FUN_0043E1A0`/`FUN_0043ECF0` and all 5 thunks contain no allocator call (Reports 12, 13). Whole-program scan for `CALL [allocator_IAT]` found none. | Constructor takes `this` in ECX (caller-supplied). No factory found. No caller of constructor identified. | Find the caller of `FUN_0043ECF0` or the factory that calls `HeapAlloc`/`RolClient_AllocMemory` then invokes the constructor. Whole-program caller analysis or runtime breakpoint at `HeapAlloc`/`RolClient_AllocMemory` capturing return address. | High |
| U2 | Object actual allocation size | BLOCKED | Constructor initializes through `0x5C40` (minimum init extent); zeroing loop `0x0C`–`0x4C4` (Reports 07, 13). | `0x5C40` is highest initialized offset, not allocation size; no `HeapAlloc(size)` argument observed. | The allocation call site's size argument (depends on U1). | High |
| U3 | Who sets `field_0x20` to non-NULL initially? | UNKNOWN | Constructor has no write to `+0x20` (Report 07). No writer found in any analyzed function (Report 09). | Initialization source not found. | Search all writes to `field_0x20` across whole program; find constructor caller/factory that initializes it. | High |
| U4 | `field_0x24` initial value and readers | UNKNOWN | `FUN_00473210` sets it to 1 (Report 05). No confirmed reader found. | Written but never confirmed read. | Search for reads of `field_0x24`. | Low |
| U5 | AddRef / increment of `field_0x20` | NOT FOUND | Whole-program atomic scan: no `LOCK XADD`/`LOCK ADD`/`LOCK INC` on `field_0x20` (Report 08). No `InterlockedIncrement` imported (Report 09). | No increment path found anywhere. | Confirm program-wide absence; if truly absent, ownership is single-owner (`Box<T>`). | High |
| U6 | Import `[0x005192EC]` identity (called by `0x00500CA6`) | UNKNOWN | `0x500CA6` calls `FF 15 EC 92 51 00` = `CALL [0x5192EC]` with 3 args: `[0x5581E8]`, 0, arg (Report 14). | ILT name not resolved via PE import parsing in this phase. | Resolve ILT entry for IAT slot `0x5192EC`; likely `HeapFree` but unconfirmed. | Medium |
| U7 | Parent object block free location | UNKNOWN | `FUN_00473210` teardown does not free memory (Report 05). List nodes freed via `0x500CA6` chain (Report 14). Parent block free not separately confirmed. | Teardown only NULLs pointer + sets flag. Parent block free may be in caller of Release or elsewhere. | Trace who calls `FUN_004731E0` (Release) and frees the block afterward. | Medium |
| U8 | Active vptr at `FUN_0044F3F0` dispatch time | UNKNOWN | Constructor writes 3 vptrs (Report 05). `FUN_0044F3F0` has no callers (Report 12). | Cannot determine which constructor stage's vptr is live at dispatch without execution or caller identification. | Find caller of `FUN_0044F3F0`; or runtime breakpoint at `0x44F3F0` reading `[EDI]`. | High |
| U9 | `field_0x28`/`field_0x2C` writers and initial values | UNKNOWN | Phase 2.4 claimed 17 writers of `+0x28`, 7 of `+0x2C`; none re-verified in Phase 2.6. None found in constructor. | Writers not re-verified; initial values unknown. | Search all writes to `field_0x28`/`field_0x2C`. | Low |
| U10 | `field_0x30` readers | UNKNOWN | `FUN_0044F3F0` increments `+0x30` (plain `INC`, non-atomic). No confirmed read. | Incremented but never confirmed read. | Search for reads of `field_0x30`. | Low |
| U11 | Import `[0x5581E8]` contents (pointer global used by `0x500CA6`) | UNKNOWN | `0x500CA6` pushes `[0x5581E8]` as first arg to `[0x5192EC]` (Report 14). | Contents of this `.data` global not read. | Read 4 bytes at `0x005581E8`. | Low |
| U12 | `FUN_00489750` helper — full behavior | UNKNOWN | Body is 12 bytes: `push ecx; call [0x519138]=DeleteCriticalSection; mov eax,1; ret` (Report 06). Import return value discarded. | `DeleteCriticalSection` return is VOID; `EAX=1` hardcoded. The `neg/sbb/xor/neg` in caller is dead code. | None — fully understood except that caller's dead-code mask is unused. | Low |
| U13 | Vtable slot-22 targets `0x450FA0`/`0x450FC0` full semantics | PROVEN | Bodies decoded: arg-dependent (returns 0 for arg 2 or 0x20, 0xC5 otherwise) (Report 11). | Fully decoded. | None. | Resolved |

---

## 2. Questions Resolved in This Phase (previously open, now answered)

| # | Previously open (Phase 2.5) | Resolution | Report |
|---|----------------------------|------------|--------|
| 1 | `LOCK XCHG` vs `LOCK XADD` at `0x4731F2` | **LOCK XADD** (atomic fetch-add-zero, field UNCHANGED) | 03, 04 |
| 2 | `MOV ECX,[ESI+0x20]` vs `LEA` | **LEA** (loads address, not value) | 03, 05 |
| 3 | `MOV ECX,[ESI+0x24]` vs `LEA` | **LEA** (loads address, not value) | 03, 05 |
| 4 | `XCHG [ECX]` pointer-indirect vs direct field | **Direct field** via LEA-computed address | 05 |
| 5 | `FUN_00473210` = decrement-and-destroy | **NOT a decrement** — sets field_0x20=0, field_0x24=1 | 05, 15 |
| 6 | `CALL [0x500ca6]` indirect slot | **DIRECT CALL 0x500CA6** to code in `.text` | 14 (confirms P2.5 correction) |
| 7 | `field_0x20` is integer counter | **Pointer** (release latch) | 07, 10 |
| 8 | External control block | **None** — all direct field access | 07, 10 |
| 9 | `FUN_00489750` import identity | **`DeleteCriticalSection`** (KERNEL32 ILT[12]) | 06 |
| 10 | `Arc<T>` justified | **NO** — no AddRef found | 09, 17 |
| 11 | Slot-13 targets return values | All return 16 (`0x4510A0`/`0x4510B0`) | 11 |
| 12 | Slot-22 Table B/C target | `0x450FC0` (arg-dependent, shared) | 11 |

---

## 3. Genuinely BLOCKED Items

| # | Operation needed | Why cannot be performed statically | Alternatives attempted | Partial static answer | Minimum evidence to resolve |
|---|------------------|-----------------------------------|----------------------|----------------------|----------------------------|
| B1 | Capture runtime allocation (allocator call + size + return pointer) | No allocator call in any analyzed static path; caller unknown | Searched constructor, thunks, whole-program `CALL [IAT]` scan | Constructor does not allocate; caller-supplied `this` likely | Breakpoint at `HeapAlloc`/`RolClient_AllocMemory`, capture return address → factory/caller |
| B2 | Observe active vptr at `FUN_0044F3F0` | `FUN_0044F3F0` has no direct callers; no execution trace | Static caller analysis (empty); vptr states enumerated (Report 11) | All 3 possible vptr states and their targets enumerated | Breakpoint at `0x44F3F0`, read `[EDI]`; or find caller |
| B3 | Read memory at `field_0x20` initializer / resolve indirect target at runtime | No static write to `field_0x20` found; runtime call targets depend on active vptr | Whole-program write scan; slot targets per vptr (Report 11) | All statically-possible targets enumerated | Breakpoint at constructor caller; read `field_0x20` after init |

---

## 4. Recommended Next Evidence-Gathering Steps (priority order)

1. **Identify the constructor caller / factory.** Whole-program analysis to find who calls `FUN_0043ECF0` (no direct caller found). This likely reveals the allocation site (U1, U2).
2. **Search all writes to `field_0x20`** to find who initializes it non-NULL (U3).
3. **Resolve import `[0x5192EC]`** via ILT lookup (likely `HeapFree`, U6).
4. **Read `[0x5581E8]`** pointer global contents (U11).
5. **Find who calls `FUN_0044F3F0`** (dispatch) to determine active vptr at runtime (U8).
6. (Runtime, if available) Breakpoint at `HeapAlloc`, `FUN_0043ECF0`, `0x44F3F0`, and `0x44F501`/`0x44F50D` to capture allocation, vptr state, and indirect targets (B1–B3).

---

## 5. What Is NOT Unresolved

The following were Phase 2.5 questions that are now resolved in Phase 2.6:
- `LOCK XCHG` vs `LOCK XADD` → **LOCK XADD** (PROVEN)
- Direct field access vs pointer-indirect → **Direct via LEA** (PROVEN)
- `FUN_00473210` role → **Teardown (zero pointer + set flag)**, not decrement (PROVEN)
- `FUN_00489750` import → **`DeleteCriticalSection`** (PROVEN)
- `CALL [0x500ca6]` → **Direct CALL to code**, not indirect slot (PROVEN, confirmed P2.5)
- `Arc<T>` applicability → **NOT justified** (no AddRef) (STRONGLY SUPPORTED)
