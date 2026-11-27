# Phase 9C — Reference Count Reconciliation: `is_call=true` = 32,848

## 1. The arithmetic

| `reference_type` | Count |
|---|---|
| `UNCONDITIONAL_CALL` | 27,770 |
| `COMPUTED_CALL` | 5,075 |
| `COMPUTED_CALL_TERMINATOR` | **3** ← omitted from the earlier report |
| **Total (`is_call=true`)** | **32,848** |

`27,770 + 5,075 + 3 = 32,848`. The report that "listed 27,770 + 5,075 = 32,845" dropped the three `COMPUTED_CALL_TERMINATOR` records. No other type carries `is_call=true` (verified exhaustively: `grep '"is_call":true'` grouped by `reference_type` yields exactly the three types above).

## 2. What those 32,848 records actually are (measured)

`count_iscall.py` + `count_uncond.py` + `check_reference_samples.py` outputs (all run this phase):

| Bucket | Count | Notes |
|---|---|---|
| Machine-level `CALL` with listing line — `E8` direct | 25,260 | 14,504 outgoing + 10,756 incoming-mirror; 1,283 of the 27,770 have **no listing line** (all `incoming_to_function_entry`, from outside analyzed bodies) |
| Machine-level `CALL` with listing line — indirect (`ESI`/`EDI`/`EBX`/`[reg]`/`[imm32]`) | 5,074 | `COMPUTED_CALL`; **never** a direct `0x…` operand; targets: 4,779 `EXTERNAL:` ids (resolved imports) + 295 internal hex32 + 1 no-line |
| `COMPUTED_CALL` from outside analyzed bodies | 1 | 1 no-listing line |
| `COMPUTED_CALL_TERMINATOR` (indirect `CALL`, function ends) | 3 | all outgoing |
| **Machine-level `CALL` instructions, total** | **30,338** | |
| Direct `JMP 0x…` into a function entry (tail-call / thunk forward), logged `UNCONDITIONAL_CALL`, `is_call=true` | 1,227 | 580 outgoing + 647 incoming-mirror |
| No-listing-line `UNCONDITIONAL_CALL` | 1,283 | all `incoming_to_function_entry`, `from_function: null` |
| **`is_call=true` records that are not `CALL` instructions** | **2,510** | 1,227 + 1,283 |
| **Grand total** | **32,848** | 30,338 + 2,510 ✓ |

`incoming` vs `outgoing` split of all 32,848: 20,029 outgoing, 12,819 incoming-to-function-entry. Every one of the 38 dispatcher callsites is logged exactly once (verified individually in `phase_9C_callsite_inventory.md`).

## 3. Semantic warnings (measured, do not re-derive)

1. **`is_call=true` ≠ `E8`.** 1,227 records flagged as calls are `E9` direct `JMP`s (tail calls into function entries). The raw bytes decide; the type label does not.
2. **`is_call=true` includes records from outside analyzed code** (1,284), e.g. `0040100c → 004724a0` (below the analyzed function range) and 1,283 `UNCONDITIONAL_CALL` with no listing line. These are not calls inside any analyzed function.
3. **Every IAT call generates two records** (`COMPUTED_CALL` `is_call=true` + a paired `READ` `is_call=false` of the slot; see Phase-0B reference schema). Importing "indirect call site" counts from the type alone double-counts.
4. **Direct calls into entries are logged twice** — once as the caller's `outgoing` edge, once as the callee's `incoming` edge? No — **exactly once** in this export, but the *direction* is not deterministic per address (e.g. #11-#15 of the e220 inventory are `incoming`, the older addresses are `outgoing`). Queries must not assume a direction; they must match on `to`.
5. **`DATA` ≠ call.** 33,329 `DATA` records (12,394 `LEA`, 8,881 `PUSH` of function VAs) are address materializations, not calls.
6. **Zero `COMPUTED_CALL` records carry a direct hex target.**

## 4. Conclusion

- `32,848` is **correct** as a total; the accompanying breakdown was incomplete (`COMPUTED_CALL_TERMINATOR` ×3).
- Categories are additive only after this correction: `27,770 + 5,075 + 3`.
- The earlier figure pair "27,770 + 5,075" was not wrong in the numbers — it was **incomplete**, not incorrect.
- For dispatch analysis, the meaningful counts are: 25,260 `E8` direct calls (14,504 outgoing), 5,074 indirect calls with targets resolved (4,779 to imports), and 2,510 flagged records that are not `CALL` instructions.
- `FUN_0041e1f0` is never the target of an `E8` jump-bypass; all 38 dispatcher callsites are `E8`.
