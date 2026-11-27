import struct

PATH = "/home/pedrodroks/Downloads/radmin/claude-handoff/binaries/radmin_ext/RvControlSvc.exe"
IMAGE_BASE = 0x00400000

with open(PATH, "rb") as fh:
    data = fh.read()

e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
coff_off = e_lfanew + 4
num_sections = struct.unpack_from("<H", data, coff_off + 2)[0]
size_opt = struct.unpack_from("<H", data, coff_off + 16)[0]
sec_off = coff_off + 20 + size_opt

sections = []
for i in range(num_sections):
    name = data[sec_off:sec_off + 8].split(b"\0")[0].decode()
    vsize, vaddr, rawsize, rawoff = struct.unpack_from("<IIII", data, sec_off + 8)
    sections.append((name, IMAGE_BASE + vaddr, vsize, rawoff, rawsize))
    sec_off += 40

def read_va(va, n):
    for name, va_base, vsize, rawoff, rawsize in sections:
        if va_base <= va < va_base + max(vsize, rawsize):
            return data[rawoff + (va - va_base): rawoff + (va - va_base) + n]
    return b""

import json

def dump(base, n, label):
    raw = read_va(base, n)
    print(f"=== {label} @ {base:#010x} ({len(raw)} bytes) ===")
    for i in range(0, len(raw), 4):
        d = struct.unpack_from("<I", raw, i)[0]
        tag = ""
        if 0x00400000 <= d < 0x00517000:
            tag = "code?"
        elif 0x00517000 <= d < 0x0054702e:
            tag = "rdata-ptr"
        print(f"  {base + i:#010x}  {d:08x}  {tag}")
    print()

for base, n, label in [
    (0x00519da0, 0x20, "vtable phase-1 A-ish (constructor phase 1, table A)"),
    (0x0051ae30, 0x40, "table containing FUN_0041df20 at +0x08"),
    (0x0051afe0, 0x40, "table containing FUN_0041f110 at +0x08"),
    (0x0051b248, 0x40, "vtable phase-2 B (contains 00422ce0 at +0x04)"),
    (0x0051b900, 0x70, "tables around 0x0051b91c / 0x0051b930"),
    (0x0051b254, 0x20, "RTTI/table B (second table stored at [EDI+0x8])"),
]:
    dump(base, n, label)
