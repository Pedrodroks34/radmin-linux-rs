import json
import re
from collections import Counter, defaultdict

REF_JSONL = "/home/pedrodroks/Downloads/radmin/ghidra_export/references.jsonl"
OUT = "/home/pedrodroks/Downloads/radmin/analysis_workspace/validation/import_mapping_output.txt"

lines = []
def emit(s=""):
    lines.append(str(s))

ext_to_name = {}
ext_name_conflicts = Counter()
ext_records = 0
ext_with_name = 0
ext_hex_to = 0
computed_call_to_styles = Counter()
hex_to_samples = []
to_function_null_with_external = 0

indirection_rows = []

with open(REF_JSONL) as fh:
    for line in fh:
        rec = json.loads(line)
        rt = rec["reference_type"]
        to = rec["to"]
        tf = rec.get("to_function")

        if rt.startswith("COMPUTED_CALL"):
            if to.startswith("EXTERNAL:"):
                computed_call_to_styles["external"] += 1
                ext_records += 1
                if tf:
                    ext_with_name += 1
                    if to in ext_to_name and ext_to_name[to] != tf:
                        ext_name_conflicts[to] += 1
                    ext_to_name[to] = tf
                else:
                    to_function_null_with_external += 1
            elif re.fullmatch(r"[0-9a-f]{8}", to):
                computed_call_to_styles["hex32"] += 1
                if len(hex_to_samples) < 10:
                    hex_to_samples.append(f'{rec["from"]}->{to} is_call={rec["is_call"]} to_function={tf}')
            else:
                computed_call_to_styles["other"] += 1

        if rt == "INDIRECTION":
            indirection_rows.append((rec["from"], to, rec.get("from_function"), tf))

emit(f"COMPUTED_CALL[*] 'to' styles: {dict(computed_call_to_styles)}")
emit(f"EXTERNAL-target records: {ext_records}; with to_function name: {ext_with_name}; missing name: {to_function_null_with_external}")
emit(f"unique EXTERNAL ids observed: {len(ext_to_name)}")
emit(f"EXTERNAL id -> conflicting names: {dict(ext_name_conflicts) if ext_name_conflicts else 'NONE'}")
emit()
emit("EXTERNAL id -> DLL::Name (sorted by name):")
for ext_id, name in sorted(ext_to_name.items(), key=lambda kv: kv[1]):
    emit(f"  {ext_id}  {name}")

emit()
name_counter = Counter(ext_to_name.values())
emit("unique imported APIs observed via COMPUTED_CALL: " + str(len(name_counter)))
emit()
emit("top imported APIs by distinct EXTERNAL id count:")
for name, c in name_counter.most_common(30):
    emit(f"  {name}: {c}")

emit()
emit("INDIRECTION records (import-thunk jumps):")
iat_map = {}
for frm, slot, ff, tf in indirection_rows:
    emit(f"  thunk@{frm}  IAT={slot}  from_function={ff}  to_function={tf}")
    if ff and ".DLL::" in ff:
        if slot in iat_map and iat_map[slot] != ff:
            emit(f"    WARNING: IAT slot {slot} mapped to both {iat_map[slot]} and {ff}")
        iat_map[slot] = ff

emit()
emit(f"IAT slot -> DLL::Name mappings derivable from INDIRECTION refs: {len(iat_map)}")
for slot, name in sorted(iat_map.items()):
    emit(f"  {slot}  {name}")

with open(OUT, "w") as fh:
    fh.write("\n".join(lines) + "\n")
print("\n".join(lines[:120]))
print("...")
print("\n".join(lines[-60:]))
