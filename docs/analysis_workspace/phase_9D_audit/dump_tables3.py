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

def dump(base, n, label):
    raw = read_va(base, n)
    print(f"=== {label} @ {base:#010x} ===")
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
    (0x00519e40, 0x30, "table targeted by [this+0x244] (V = 0x00519e54)"),
    (0x0051ae58, 0x10, "[this+0x28] final table (0x51ae58)"),
    (0x0051aec0, 0x40, "RTTI locator A region (0x51aec0..0x51aee0)"),
    (0x0051af00, 0x20, "following locator region"),
]:
    dump(base, n, label)
