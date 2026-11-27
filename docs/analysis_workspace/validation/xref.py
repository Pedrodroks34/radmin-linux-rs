import json
import os
import sys

ROOT = "/home/pedrodroks/Downloads/radmin"
LISTING = os.path.join(ROOT, "ghidra_export", "listing")
FUNC_JSONL = os.path.join(ROOT, "ghidra_export", "functions.jsonl")
REF_JSONL = os.path.join(ROOT, "ghidra_export", "references.jsonl")

CALL_TYPES = ("UNCONDITIONAL_CALL", "COMPUTED_CALL", "COMPUTED_CALL_TERMINATOR")


def load_funcs():
    funcs = []
    with open(FUNC_JSONL) as fh:
        for line in fh:
            if line.strip():
                f = json.loads(line)
                funcs.append(f)
    return funcs


def name_index(funcs):
    idx = {}
    for f in funcs:
        idx[f["entry"]] = f
    return idx


def body_index(funcs):
    return sorted([(int(f["body_min"], 16), int(f["body_max"], 16), f["entry"], f["name"]) for f in funcs])


def owner_of(bodies, va):
    lo, hi = 0, len(bodies) - 1
    while lo <= hi:
        mid = (lo + hi) // 2
        bmin, bmax, entry, name = bodies[mid]
        if va < bmin:
            hi = mid - 1
        elif va > bmax:
            lo = mid + 1
        else:
            return entry, name
    return None, None


def iter_refs():
    with open(REF_JSONL) as fh:
        for line in fh:
            if line.strip():
                yield json.loads(line)


def norm(addr):
    a = addr.lower().strip()
    if a.startswith("0x"):
        a = a[2:]
    return a.zfill(8)[-8:]


def cmd_callers(target, unique=False):
    target = norm(target)
    sites = []
    callers = {}
    for r in iter_refs():
        if r["reference_type"] in CALL_TYPES and norm(r["to"]) == target and r["is_call"]:
            sites.append(r)
            callers[r.get("from_function") or "(non-function code)"] = True
    print(f"call sites targeting {target} (is_call=true, CALL types): {len(sites)}")
    for r in sites:
        print(f"  {r['from']}  {r['reference_type']:<28} from_function={r.get('from_function')}")
    print(f"unique caller functions: {len(callers)}")
    if unique:
        for name in sorted(callers):
            print(f"  {name}")


def cmd_callees(entry):
    funcs = load_funcs()
    fi = name_index(funcs)
    target = norm(entry)
    f = fi.get(target)
    name = f["name"] if f else None
    if f:
        lo, hi = int(f["body_min"], 16), int(f["body_max"], 16)
    else:
        lo = hi = int(target, 16)
        for b in body_index(funcs):
            if b[2] == target:
                lo, hi = b[0], b[1]
                break
    print(f"callees of {target} ({name}):")
    n = 0
    for r in iter_refs():
        if r["reference_type"] in CALL_TYPES and r["is_call"] and r.get("from_function") == name:
            print(f"  {r['from']}  {r['reference_type']:<28} to={r['to']}  to_function={r.get('to_function')}")
            n += 1
    print(f"total call sites: {n}")


def cmd_refs_to(addr, want_type=None):
    addr = norm(addr)
    n = 0
    by_type = {}
    for r in iter_refs():
        if norm(r["to"]) == addr:
            if want_type and r["reference_type"] != want_type:
                continue
            n += 1
            by_type[r["reference_type"]] = by_type.get(r["reference_type"], 0) + 1
            print(f"  {r['from']}  {r['reference_type']:<28} dir={r['direction']:<30} from_function={r.get('from_function')}")
    print(f"refs to {addr}" + (f" (type={want_type})" if want_type else "") + f": {n}")
    print(f"by type: {by_type}")


def cmd_writes_to(addr):
    addr = norm(addr)
    cmd_refs_to(addr, "WRITE")
    print()
    cmd_refs_to(addr, "READ_WRITE")


def cmd_refs_in_range(lo_addr, hi_addr, want_type=None):
    lo, hi = int(norm(lo_addr), 16), int(norm(hi_addr), 16)
    n = 0
    funcs = load_funcs()
    bodies = body_index(funcs)
    seen_functions = {}
    for r in iter_refs():
        to = r["to"]
        if not all(c in "0123456789abcdefABCDEF" for c in to):
            continue
        tv = int(to, 16)
        if not (lo <= tv <= hi):
            continue
        if want_type and r["reference_type"] != want_type:
            continue
        n += 1
        frm_fn = r.get("from_function")
        if frm_fn:
            seen_functions[frm_fn] = True
        owner, _ = owner_of(bodies, int(r["from"], 16))
    print(f"refs with to in [{lo:08x},{hi:08x}]" + (f" (type={want_type})" if want_type else "") + f": {n}")
    print(f"distinct from_function names: {len(seen_functions)}")
    for name in sorted(seen_functions):
        print(f"  {name}")


def cmd_listing(addr):
    addr = norm(addr)
    path = os.path.join(LISTING, addr + ".asm")
    if os.path.exists(path):
        with open(path) as fh:
            print(fh.read(), end="")
        return
    funcs = load_funcs()
    bodies = body_index(funcs)
    owner, _ = owner_of(bodies, int(addr, 16))
    if owner:
        with open(os.path.join(LISTING, owner + ".asm")) as fh:
            print(f"(address {addr} is inside {owner}.asm)")
            print(fh.read(), end="")
        return
    print(f"no listing covers {addr}", file=sys.stderr)
    sys.exit(1)


def cmd_unique_callers(target):
    cmd_callers(target, unique=True)


def usage():
    print(__doc__ or "usage: xref.py <command> [args]")
    print("commands:")
    print("  callers <fn-entry>")
    print("  callees <fn-entry>")
    print("  refs-to <addr> [--type TYPE]")
    print("  writes-to <addr>")
    print("  refs-in-range <lo> <hi> [--type TYPE]")
    print("  listing <addr>")
    print("  unique-callers <fn-entry>")


def main(argv):
    if len(argv) < 2:
        usage()
        return 2
    cmd = argv[1]
    args = argv[2:]
    want_type = None
    if "--type" in args:
        i = args.index("--type")
        want_type = args[i + 1]
        del args[i:i + 2]
    if cmd == "callers":
        cmd_callers(args[0])
    elif cmd == "unique-callers":
        cmd_callers(args[0], unique=True)
    elif cmd == "callees":
        cmd_callees(args[0])
    elif cmd == "refs-to":
        cmd_refs_to(args[0], want_type)
    elif cmd == "writes-to":
        cmd_writes_to(args[0])
    elif cmd == "refs-in-range":
        cmd_refs_in_range(args[0], args[1], want_type)
    elif cmd == "listing":
        cmd_listing(args[0])
    else:
        print(f"unknown command: {cmd}", file=sys.stderr)
        usage()
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
