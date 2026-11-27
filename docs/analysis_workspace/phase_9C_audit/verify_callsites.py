import os
import re
import sys

ROOT = "/home/pedrodroks/Downloads/radmin"
LISTING = os.path.join(ROOT, "ghidra_export", "listing")
LINE_RE = re.compile(r"^([0-9A-Fa-f]{8})\s{2,}([0-9A-F]+(?:\s+[0-9A-F]+)*)\s{2,}(\S.*)$")

va_to_line = {}
va_to_file = {}
with os.scandir(LISTING) as it:
    for entry in it:
        if not entry.name.endswith(".asm"):
            continue
        with open(entry.path, errors="ignore") as fh:
            for line in fh:
                m = LINE_RE.match(line.rstrip("\n"))
                if m:
                    iv = int(m.group(1), 16)
                    va_to_line[iv] = line.rstrip("\n")
                    va_to_file[iv] = entry.name

for spec in sys.argv[1:]:
    fn, addrs = spec.split("=", 1)
    print(f"### {fn}")
    for a in addrs.split(","):
        iv = int(a.strip(), 16)
        print(va_to_line.get(iv, f"!! {a}: NO INSTRUCTION LINE"), "   [" + va_to_file.get(iv, "?") + "]")
