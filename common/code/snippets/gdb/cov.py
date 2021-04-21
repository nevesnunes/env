#!/usr/bin/env python3

import gdb
import r2pipe
import sys
import os


def to_loaded_offset(offset, is_pic):
    # Precondition: ASLR disabled
    if is_pic:
        return 0x555555554000 + offset

    return offset


class ContextualBreakpoint(gdb.Breakpoint):
    def __init__(self, offset, name, is_pic, hit_offsets):
        self.name = name
        self.offset = to_loaded_offset(offset, is_pic)
        self.hit_offsets = hit_offsets
        gdb.Breakpoint.__init__(self, f"*{hex(self.offset)}", gdb.BP_BREAKPOINT, temporary=True)

    def stop(self):
        if self.offset not in self.hit_offsets:
            self.hit_offsets.add(self.offset)
            print(f"hit: {self.name} ({hex(self.offset)})", file=sys.stderr)

        # inferior will continue
        return False

    def out_of_scope(self):
        print(f"out_of_scope: {self.name} ({hex(self.offset)})", file=sys.stderr)


def parse_functions(r2p):
    r2p.cmd("aaa")
    functions = r2p.cmdj("aflj")
    parsed_functions = {}
    for f in functions:
        if f["name"].startswith("sym.imp."):
            # Skip imports
            continue

        instructions = []
        opcodes = []
        # FIXME: Consider `pdrj` for non-linear obfuscated functions
        # - [radare2 disassembly commands doesn&\#39;t work properly\. · Issue \#11325 · radareorg/radare2 · GitHub](https://github.com/radareorg/radare2/issues/11325)
        for ins in r2p.cmdj(f"pdfj @{f['offset']}")["ops"]:
            instructions.append(f"{hex(ins['offset'])} {ins['disasm']}")
            opcodes.append(ins["disasm"].split()[0])
        parsed_functions[f["offset"]] = {
            "name": f["name"],
            "offset": f["offset"],
            "instructions": instructions,
            "opcodes": opcodes,
            "hash": hash(tuple(opcodes)),
        }

    return parsed_functions


process_name = os.path.basename(gdb.current_progspace().filename)
r2p = r2pipe.open(process_name)

info = r2p.cmdj("ij")
is_pic = info["bin"]["pic"]
functions = parse_functions(r2p)

gdb.execute("starti")
hit_offsets = set()
for offset in functions.keys():
    ContextualBreakpoint(offset, functions[offset]["name"], is_pic, hit_offsets)
    # Alternative:
    # ```
    # gdb.execute(f"tbreak *{offset}")
    # ```
    # On break:
    # ```
    # while 1
    # > c
    # > end
    # ```
gdb.execute("c")
