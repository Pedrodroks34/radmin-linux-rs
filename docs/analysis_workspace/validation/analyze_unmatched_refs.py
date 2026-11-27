import json
import os
import re
from collections import Counter, defaultdict

ROOT = "/home/pedrodroks/Downloads/radmin"
LISTING = os.path.join(ROOT, "ghidra_export", "listing")
FUNC_JSONL = os.path.join(ROOT, "ghidra_export", "functions.jsonl")
REF_JSONL = os.path.join(ROOT, "ghidra_export", "references.jsonl")

asm_vas = set()
with os.scandir(LISTING) as it:
    for entry in it:
        if not entry.name.endswith(".asm"):
            continue
        with open(entry.path, errors="ignore") as fh:
            for line in fh:
                head = line.split(None, 1)[0]
                try:
                    asm_vas.add(int(head, 16))
                except ValueError:
                    pass

bodies = []
with open(FUNC_JSONL) as fh:
    for line in fh:
        f = json.loads(line)
        try:
            bodies.append((int(f["body_min"], 16), int(f["body_max"], 16), f["entry"], f["name"]))
        except Exception:
            pass
bodies.sort()

def owner(va):
    lo, hi = 0, len(bodies) - 1
    while lo <= hi:
        mid = (lo + hi) // 2
        bmin, bmax, entry, name = bodies[mid]
        if va < bmin:
            hi = mid - 1
        elif va > bmax:
            lo = mid + 1
        else:
            return entry
    return None

no_line = Counter()
no_line_samples = defaultdict(list)
incoming_from_null = 0
incoming_from_set = 0
outgoing_from_null = 0
total = 0
in_body_no_line = 0
outside_body_no_line = 0
body_owner_counter = Counter()

with open(REF_JSONL) as fh:
    for line in fh:
        total += 1
        rec = json.loads(line)
        direction = rec["direction"]
        if direction == "incoming_to_function_entry":
            if rec.get("from_function") is None:
                incoming_from_null += 1
            else:
                incoming_from_set += 1
        elif direction == "outgoing_from_function":
            if rec.get("from_function") is None:
                outgoing_from_null += 1

        try:
            va = int(rec["from"], 16)
        except (TypeError, ValueError):
            no_line["from_not_hex"] += 1
            continue
        if va in asm_vas:
            continue
        no_line[rec["reference_type"]] += 1
        if len(no_line_samples[rec["reference_type"]]) < 8:
            no_line_samples[rec["reference_type"]].append(f'{rec["from"]}->{rec["to"]} dir={rec["direction"]}')
        if direction == "outgoing_from_function":
            no_line["outgoing_no_line"] += 1
        own = owner(va)
        if own:
            in_body_no_line += 1
            body_owner_counter[own] += 1
        else:
            outside_body_no_line += 1

print("total records:", total)
print("incoming from_function null:", incoming_from_null)
print("incoming from_function set:", incoming_from_set)
print("outgoing from_function null:", outgoing_from_null)
print()
print("records with from-VA not present as an instruction line:")
for k, v in sorted(no_line.items(), key=lambda kv: -kv[1]):
    print(f"  {k}: {v}")
print()
print("of no-line records: inside a function body (but not an instruction start):", in_body_no_line)
print("of no-line records: outside every function body:", outside_body_no_line)
print()
print("sample no-line records by type:")
for k in sorted(no_line_samples):
    print(f"  {k}: {no_line_samples[k]}")
print()
print("top owners of in-body no-line records:", body_owner_counter.most_common(10))
