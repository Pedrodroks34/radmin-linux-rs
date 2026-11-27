import os
import re
import sys

LISTING = "/home/pedrodroks/Downloads/radmin/ghidra_export/listing"
LINE_RE = re.compile(r"^([0-9A-Fa-f]{8})\s{2,}([0-9A-F]+(?:\s+[0-9A-F]+)*)\s{2,}(\S.*)$")

va_to_line = {}
va_to_file = {}

with os.scandir(LISTING) as entries:
    for entry in entries:
        if not entry.name.endswith(".asm"):
            continue
        with open(entry.path, errors="ignore") as fh:
            prev = None
            for line in fh:
                m = LINE_RE.match(line.rstrip("\n"))
                if not m:
                    continue
                iv = int(m.group(1), 16)
                va_to_line[iv] = line.rstrip("\n")
                va_to_file[iv] = entry.name

print(f"indexed {len(va_to_line)} lines", file=sys.stderr)
specs = sys.argv[1:]
context = int(os.environ.get("CTX", "12"))
for spec in specs:
    va_str, label = spec.split("=", 1)
    va = int(va_str, 16)
    print(f"### {label}  ({va_str})  [{va_to_file.get(va)}]")
    start = va - 0x80
    rows = [(a, va_to_line[a]) for a in sorted(va_to_line) if start <= a <= va]
    for _, line in rows[-context:]:
        print(line)
    print()
