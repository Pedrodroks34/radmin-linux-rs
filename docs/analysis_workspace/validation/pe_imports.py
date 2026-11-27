import json
import struct
import sys

PATH = "/home/pedrodroks/Downloads/radmin/claude-handoff/binaries/radmin_ext/RvControlSvc.exe"
OUT = "/home/pedrodroks/Downloads/radmin/analysis_workspace/validation/import_iat_map.txt"

with open(PATH, "rb") as fh:
    data = fh.read()

e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
pe_sig = data[e_lfanew:e_lfanew + 4]
assert pe_sig == b"PE\0\0", f"bad PE signature: {pe_sig!r}"
coff_off = e_lfanew + 4
machine, num_sections, ts, sym, num_syms, size_opt, characteristics = struct.unpack_from("<HHIIIHH", data, coff_off)
opt_off = coff_off + 20
magic = struct.unpack_from("<H", data, opt_off)[0]
assert magic == 0x10B, f"not PE32: magic={magic:#x}"
image_base = struct.unpack_from("<I", data, opt_off + 28)[0]
num_dirs_off = opt_off + 92
num_rva_sizes = struct.unpack_from("<I", data, num_dirs_off)[0]
dir_base = num_dirs_off + 4
import_dir = struct.unpack_from("<II", data, dir_base + 1 * 8)
iat_dir = struct.unpack_from("<II", data, dir_base + 12 * 8)

sections = []
sec_off = opt_off + size_opt
for i in range(num_sections):
    name = data[sec_off:sec_off + 8].split(b"\0")[0].decode("ascii", "replace")
    vsize, vaddr, rawsize, rawoff = struct.unpack_from("<IIII", data, sec_off + 8)
    sections.append((name, vaddr, vsize, rawoff, rawsize))
    sec_off += 40

def rva_to_off(rva):
    for name, vaddr, vsize, rawoff, rawsize in sections:
        if vaddr <= rva < vaddr + max(vsize, rawsize):
            return rawoff + (rva - vaddr)
    raise ValueError(f"RVA {rva:#x} not in any section")

def cstr(off):
    end = data.index(b"\0", off)
    return data[off:end].decode("ascii", "replace")

import_rva, import_size = import_dir
off = rva_to_off(import_rva)
imports = []
iat_slot_map = {}
while True:
    oft, timedate, forwarder, name_rva, first_thunk = struct.unpack_from("<IIIII", data, off)
    if oft == 0 and timedate == 0 and name_rva == 0 and first_thunk == 0:
        break
    dll = cstr(rva_to_off(name_rva))
    thunk_rva = oft if oft else first_thunk
    index = 0
    while True:
        entry = struct.unpack_from("<I", data, rva_to_off(thunk_rva + index * 4))[0]
        if entry == 0:
            break
        iat_va = image_base + first_thunk + index * 4
        if entry & 0x80000000:
            label = f"{dll.upper()}::ordinal_{entry & 0xFFFF}"
        else:
            hint_name_off = rva_to_off(entry)
            hint = struct.unpack_from("<H", data, hint_name_off)[0]
            label = f"{dll.upper()}::{cstr(hint_name_off + 2)}"
        iat_slot_map[iat_va] = (label, hint if not (entry & 0x80000000) else None)
        imports.append(label)
        index += 1
    off += 20

ias_lo = image_base + iat_dir[0]
ias_hi = ias_lo + iat_dir[1]

with open(OUT, "w") as fh:
    fh.write(f"PE32 image base: 0x{image_base:08x}\n")
    fh.write(f"import directory RVA: 0x{import_rva:08x} size 0x{import_size:08x}\n")
    fh.write(f"IAT directory RVA: 0x{iat_dir[0]:08x} size 0x{iat_dir[1]:08x} -> VA 0x{ias_lo:08x}..0x{ias_hi:08x}\n")
    fh.write(f"sections: {[s[0] for s in sections]}\n")
    fh.write(f"total imported entries: {len(imports)}\n")
    dll_counter = {}
    for label in imports:
        dll = label.split("::")[0]
        dll_counter[dll] = dll_counter.get(dll, 0) + 1
    for dll, n in sorted(dll_counter.items()):
        fh.write(f"  {dll}: {n} imports\n")
    fh.write("\nIAT VA -> DLL::Name (imagebase-relative VAs):\n")
    for va in sorted(iat_slot_map):
        label, hint = iat_slot_map[va]
        fh.write(f"  {va:08x}  {label}  hint={hint}\n")

print(open(OUT).read())
