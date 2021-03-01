#!/usr/bin/env python3

# TODO:
# - Use more in-depth executable format checks:
#     - https://github.com/lief-project/LIEF/blob/master/src/PE/utils.cpp
#     - https://corkamiwiki.github.io/PE

# References:
# - https://binaryresearch.github.io/2019/12/11/Analyzing-ELF-Binaries-with-Malformed-Headers-Part-2-Mapping-Program-Logic-with-Qiling-and-Graphviz.html
# - https://stackoverflow.com/a/47456401/8020917
#     - https://docs.microsoft.com/en-us/windows/win32/debug/pe-format
# - http://www.sunshine2k.de/reversing/tuts/tut_rvait.htm
# - https://www.capstone-engine.org/lang_python.html

from capstone import *
from elftools.elf.elffile import ELFFile
import pefile
import sys


def is_elf(file_name):
    magic = None
    with open(file_name, "rb") as f:
        raw = f.read()
        magic = raw[:4]
    return (
        magic[0] == 0x7F
        and magic[1] == ord("E")
        and magic[2] == ord("L")
        and magic[3] == ord("F")
    )


def is_pe(file_name):
    magic = None
    with open(file_name, "rb") as f:
        raw = f.read()
        magic = raw[:2]
    return magic[0] == ord("M") and magic[1] == ord("Z")


def get_elf_segment_load_address(elffile):
    text_addr = elffile.get_section_by_name(".text").header["sh_addr"]
    for i in range(elffile.num_segments()):
        seg = elffile.get_segment(i)
        if seg.header["p_type"] == "PT_LOAD":
            seg_vaddr = seg.header["p_vaddr"]
            if seg_vaddr < text_addr:
                return seg_vaddr

    raise RuntimeError(
        f"No loadable segment found with a load address containing text section address {hex(text_addr)}."
    )


def get_pe_text_section(pefile):
    for section in pefile.sections:
        if section.Name.rstrip(b"\x00") == b".text":
            return section

    raise RuntimeError("No text section found.")


def get_object_code(file_name):
    with open(file_name, "rb") as f:
        if is_elf(file_name):
            file = ELFFile(f)

            is_32 = file.elfclass == 32

            entry_point = file._parse_elf_header().e_entry
            segment_load_address = get_elf_segment_load_address(file)
            entry_offset = entry_point - segment_load_address
            print(f"entry_point: {hex(entry_point)}", file=sys.stderr)
            print(f"segment_load_address: {hex(segment_load_address)}", file=sys.stderr)
            print(f"entry_offset: {hex(entry_offset)}", file=sys.stderr)

            f.seek(entry_offset)
            buf = f.read()
        elif is_pe(file_name):
            file = pefile.PE(file_name)

            is_32 = file.OPTIONAL_HEADER.Magic == 0x10B or hasattr(
                file.OPTIONAL_HEADER, "BaseOfData"
            )

            base_address = file.OPTIONAL_HEADER.ImageBase
            entry_point = file.OPTIONAL_HEADER.AddressOfEntryPoint
            entry_va = entry_point + file.OPTIONAL_HEADER.ImageBase
            print(f"base_address: {hex(base_address)}", file=sys.stderr)
            print(f"entry_point: {hex(entry_point)}", file=sys.stderr)
            print(f"entry_point (virtual address): {hex(entry_va)}", file=sys.stderr)

            text_section = get_pe_text_section(file)
            virtual_address = text_section.VirtualAddress
            raw_offset = text_section.PointerToRawData
            entry_offset = entry_point - virtual_address + raw_offset
            print(f"virtual_address: {hex(virtual_address)}", file=sys.stderr)
            print(f"raw_offset: {hex(raw_offset)}", file=sys.stderr)
            print(
                f"entry_point (file offset): {hex(entry_offset)}", file=sys.stderr,
            )

            f.seek(entry_offset)
            raw_size = text_section.SizeOfRawData
            buf = f.read(raw_size)
        else:
            raise RuntimeError("Unsupported file format.")

    return buf, entry_point, is_32


def disassemble():
    code, entry_point, is_32 = get_object_code(sys.argv[1])
    if is_32:
        md = Cs(CS_ARCH_X86, CS_MODE_32)
    else:
        md = Cs(CS_ARCH_X86, CS_MODE_64)
    for i in md.disasm(code, entry_point):
        print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))


if __name__ == "__main__":
    disassemble()
