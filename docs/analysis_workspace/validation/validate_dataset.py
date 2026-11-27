import json
import os
import sys
from collections import Counter

ROOT = "/home/pedrodroks/Downloads/radmin"
LISTING = os.path.join(ROOT, "ghidra_export", "listing")
FUNC_JSONL = os.path.join(ROOT, "ghidra_export", "functions.jsonl")
REF_JSONL = os.path.join(ROOT, "ghidra_export", "references.jsonl")
META_JSON = os.path.join(ROOT, "ghidra_export", "metadata.json")

out = []
def emit(msg):
    out.append(str(msg))

with open(META_JSON) as fh:
    meta = json.load(fh)

listing_files = sorted(os.listdir(LISTING))
asm_files = [f for f in listing_files if f.endswith(".asm")]
non_asm = [f for f in listing_files if not f.endswith(".asm")]
emit(f"listing .asm files: {len(asm_files)}  (non-.asm entries: {non_asm})")

with open(FUNC_JSONL) as fh:
    func_lines = [l for l in fh if l.strip()]
funcs = []
func_parse_failures = 0
for i, line in enumerate(func_lines):
    try:
        funcs.append(json.loads(line))
    except Exception:
        func_parse_failures += 1
emit(f"functions.jsonl lines: {len(func_lines)}  parsed: {len(funcs)}  parse failures: {func_parse_failures}")

entries = [f.get("entry") for f in funcs]
fn_names = [f.get("name") for f in funcs]
entry_counts = Counter(entries)
dup_entries = {e: c for e, c in entry_counts.items() if e and c > 1}
name_counts = Counter(n for n in fn_names if n)
dup_names = {n: c for n, c in name_counts.items() if c > 1}
emit(f"duplicate function entries: {dup_entries if dup_entries else 'NONE'}")
emit(f"duplicate function names: {dup_names if dup_names else 'NONE'}")
emit(f"null entries: {sum(1 for e in entries if not e)}")

expect_files = {(e + ".asm") for e in entries if e}
missing = sorted(expect_files - set(asm_files))
extra = sorted(set(asm_files) - expect_files)
emit(f"listings expected from functions.jsonl: {len(expect_files)}")
emit(f"missing listing files: {missing if missing else 'NONE'}")
emit(f"extra listing files without functions.jsonl entry: {extra if extra else 'NONE'}")

entry_vas = sorted(int(e, 16) for e in entries if e)
emit(f"function entry VA range: {entry_vas[0]:08x} .. {entry_vas[-1]:08x}")

insn_min = None
insn_max = None
insn_total = 0
for f in asm_files:
    with open(os.path.join(LISTING, f), errors="ignore") as fh:
        for line in fh:
            line = line.rstrip()
            if not line:
                continue
            head = line.split(None, 1)[0]
            try:
                va = int(head, 16)
            except ValueError:
                continue
            insn_total += 1
            if insn_min is None or va < insn_min:
                insn_min = va
            if insn_max is None or va > insn_max:
                insn_max = va
emit(f"instruction lines counted: {insn_total}")
emit(f"instruction VA range: {insn_min:08x} .. {insn_max:08x}")

cc = Counter(f.get("calling_convention") for f in funcs)
emit(f"calling conventions: {dict(cc)}")
unknown_cc = sorted(f["entry"] for f in funcs if f.get("calling_convention") == "unknown")
emit(f"unknown-convention function entries ({len(unknown_cc)}): {', '.join(unknown_cc)}")

dec_fail = [f for f in funcs if f.get("decompile_status") != "success"]
emit(f"decompile failures ({len(dec_fail)}): {[(f.get('entry'), f.get('decompile_error')) for f in dec_fail]}")

thunks = [f for f in funcs if f.get("is_thunk")]
emit(f"thunks: {len(thunks)}")
thunk_cc = Counter(f.get("calling_convention") for f in thunks)
emit(f"thunk calling conventions: {dict(thunk_cc)}")

externals = [f for f in funcs if f.get("is_external")]
emit(f"externals: {len(externals)}")

ref_types = Counter()
directions = Counter()
is_call_true = 0
ref_parse_failures = 0
ref_total = 0
dup_ref_lines = Counter()
missing_keys = Counter()
REQUIRED = ["direction", "from", "to", "reference_type", "is_call", "from_function", "to_function"]
with open(REF_JSONL) as fh:
    for line in fh:
        ref_total += 1
        dup_ref_lines[line.rstrip("\n")] += 1
        try:
            r = json.loads(line)
        except Exception:
            ref_parse_failures += 1
            continue
        for k in REQUIRED:
            if k not in r:
                missing_keys[k] += 1
        ref_types[r.get("reference_type")] += 1
        directions[r.get("direction")] += 1
        if r.get("is_call"):
            is_call_true += 1
duplicate_refs = {l: c for l, c in dup_ref_lines.items() if c > 1}
emit(f"references.jsonl records: {ref_total}  parse failures: {ref_parse_failures}")
emit(f"exact-duplicate reference lines: {sum(c - 1 for c in dup_ref_lines.values() if c > 1)} extra copies in {len(duplicate_refs)} distinct duplicated lines")
emit(f"missing required keys: {dict(missing_keys) if missing_keys else 'NONE'}")
emit(f"reference types: {dict(ref_types)}")
emit(f"reference directions: {dict(directions)}")
emit(f"is_call=true records: {is_call_true}")

emit("")
emit("metadata.json comparison:")
emit(f"  functions_total: meta={meta.get('functions_total')} observed={len(funcs)}")
emit(f"  functions_processed: meta={meta.get('functions_processed')}")
emit(f"  decompile_failures: meta={meta.get('decompile_failures')} observed={len(dec_fail)}")
emit(f"  instructions_exported: meta={meta.get('instructions_exported')} observed={insn_total}")
emit(f"  unique_references_exported: meta={meta.get('unique_references_exported')} records_observed={ref_total} exact_duplicate_lines={sum(c - 1 for c in dup_ref_lines.values() if c > 1)}")
emit(f"  image_base: meta={meta.get('image_base')}")
emit(f"  partial_export: meta={meta.get('partial_export')}")

with open("/home/pedrodroks/Downloads/radmin/analysis_workspace/validation/validation_output.txt", "w") as fh:
    fh.write("\n".join(str(l) for l in out) + "\n")
print("\n".join(str(l) for l in out))
