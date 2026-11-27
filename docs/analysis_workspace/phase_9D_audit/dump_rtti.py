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
            off = rawoff + (va - va_base)
            if off + n <= rawoff + rawsize:
                return data[off:off + n]
            head = data[off:rawoff + rawsize]
            return head + b"\x00" * (n - len(head))
    return b""

for base, n in [(0x0051ae20, 0x140)]:
    raw = read_va(base, n)
    print(f"=== region @ {base:#010x} ({n} bytes) ===")
    for i in range(0, len(raw), 4):
        d = struct.unpack_from("<I", raw, i)[0]
        tag = ""
        if 0x00400000 <= d < 0x00517000:
            tag = "code"
        elif 0x00517000 <= d < 0x0054702e:
            tag = "rdata"
        elif 0x00548000 <= d < 0x005c0000:
            tag = "data"
        print(f"  {base + i:#010x}  {d:08x}  {tag}")
