#!/usr/bin/env python3

import lief


def _dump_elf(self, address: int, out_file: str):
    """
    Reads the ELF header in-memory and dumps the loadable sections
    to disk, reconstructing a valid (re-executable) ELF binary.

    Arguments:
        address: virtual address of the ELF header.
        out_file: filename to dump the unpacked binary.
    """
    self._log.info(f"Dumping ELF @ 0x{address:x}")

    elf = lief.parse(self.z.memory.read(address, 0x1000))
    with open(out_file, "wb") as f:
        for segment in elf.segments:
            if segment.type != lief.ELF.SEGMENT_TYPES.LOAD:
                continue

            self._log.info(
                f"   Writing segment 0x{segment.virtual_address:08x} - "
                f"0x{segment.virtual_address+segment.physical_size:08x}"
            )

            f.seek(segment.file_offset)
            f.write(self.z.memory.read(segment.virtual_address, segment.physical_size))

        self._log.info(f"Success! Wrote {f.tell()} bytes to '{out_file}'")
