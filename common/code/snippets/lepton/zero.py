#!/usr/bin/env python3

from lepton import *
from struct import pack
import sys


def main():
    filename = sys.argv[1]
    with open(filename, "rb") as f:
        elf_file = ELFFile(f)

    # overwrite fields values with 0x00 bytes
    elf_file.ELF_header.fields["e_shoff"] = pack("<Q", 0)
    elf_file.ELF_header.fields["e_shentsize"] = pack("<H", 0)
    elf_file.ELF_header.fields["e_shnum"] = pack("<H", 0)
    elf_file.ELF_header.fields["e_shstrndx"] = pack("<H", 0)

    # output to file
    binary = elf_file.ELF_header.to_bytes() + elf_file.file_buffer[64:]
    with open(f"{filename}.lepton.zero", "wb") as f:
        f.write(binary)


if __name__ == "__main__":
    main()
