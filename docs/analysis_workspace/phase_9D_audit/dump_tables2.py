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

def dump(base, n, label, code_hi=0x00517000):
    raw = read_va(base, n)
    print(f"=== {label} @ {base:#010x} ===")
    for i in range(0, len(raw), 4):
        d = struct.unpack_from("<I", raw, i)[0]
        tag = ""
        if 0x00400000 <= d < code_hi:
            tag = "code?"
        elif 0x00517000 <= d < 0x0054702e:
            tag = "rdata-ptr"
        print(f"  {base + i:#010x}  {d:08x}  {tag}")
    print()

for base, n, label in [
    (0x0051aee0, 0x30, "P table region (P=0x0051aee0; D=[P+4]=[0x0051aee4])"),
    (0x0051ae28, 0x48, "class vtable region (terminal stores 0x51ae28/0x51ae44/0x51ae58)"),
    (0x0051ae00, 0x30, "table at [this+0x40] region (0x51ae04)"),
    (0x0051ae44, 0x10, "table at [this+0x10] (0x51ae44)"),
]:
    dump(base, n, label)
