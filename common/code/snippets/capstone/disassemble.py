#!/usr/bin/env python3

# References:
# - https://binaryresearch.github.io/2019/12/11/Analyzing-ELF-Binaries-with-Malformed-Headers-Part-2-Mapping-Program-Logic-with-Qiling-and-Graphviz.html
# - https://www.capstone-engine.org/lang_python.html

from capstone import *
from elftools.elf.elffile import ELFFile
import sys


def get_segment_load_address(elffile):
    text_addr = elffile.get_section_by_name(".text").header["sh_addr"]
    for i in range(elffile.num_segments()):
        seg = elffile.get_segment(i)
        if seg.header["p_type"] == "PT_LOAD":
            seg_vaddr = seg.header["p_vaddr"]
            if seg_vaddr < text_addr:
                return seg_vaddr

    raise RuntimeError(
        f"No loadable segment found with a load address containing text section address {hex(text_addr)}"
    )


def get_object_code(file_name):

    with open(file_name, "rb") as f:
        elffile = ELFFile(f)

        entry_point = elffile._parse_elf_header().e_entry
        segment_load_address = get_segment_load_address(elffile)
        entry_offset = entry_point - segment_load_address
        print(f"entry_point: {hex(entry_point)}", file=sys.stderr)
        print(f"segment_load_address: {hex(segment_load_address)}", file=sys.stderr)
        print(f"entry_offset: {hex(entry_offset)}", file=sys.stderr)

        f.seek(entry_offset)
        buf = f.read()

    return buf, entry_point


def disassemble():
    code, entry_point = get_object_code(sys.argv[1])
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    for i in md.disasm(code, entry_point):
        print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))


if __name__ == "__main__":
    disassemble()
