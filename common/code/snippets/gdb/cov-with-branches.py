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
        extras = []
        # FIXME: Consider `pdrj` for non-linear obfuscated functions
        # - [radare2 disassembly commands doesn&\#39;t work properly\. · Issue \#11325 · radareorg/radare2 · GitHub](https://github.com/radareorg/radare2/issues/11325)
        for ins in r2p.cmdj(f"pdfj @{f['offset']}")["ops"]:
            opcodes.append(ins["disasm"].split()[0])
            parsed_instruction = {
                "entry": f"{hex(ins['offset'])} {ins['disasm']}",
                "type": ins["type"],
            }
            if ins["type"] in ("call", "cjmp", "jmp"):
                parsed_instruction["jump"] = ins["jump"]
            if ins["type"] in ("cjmp") and "fail" in ins:
                parsed_instruction["fail"] = ins["fail"]
            instructions.append(parsed_instruction)
        parsed_functions[f["offset"]] = {
            "name": f["name"],
            "offset": f["offset"],
            "instructions": instructions,
            "opcodes": opcodes,
            "extras": extras,
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
for offset in functions.keys():
    for i in functions[offset]["instructions"]:
        i_offset = int(i["entry"].split()[0], 16)
        if i_offset in functions.keys():
            continue
        if i["type"] in ("call", "cjmp", "jmp"):
            if i["jump"] in functions.keys():
                continue
            ContextualBreakpoint(i["jump"], f'{functions[offset]["name"]} {i["entry"]}', is_pic, hit_offsets)
        if i["type"] in ("cjmp") and "fail" in i:
            if i["fail"] in functions.keys():
                continue
            ContextualBreakpoint(i["fail"], f'{functions[offset]["name"]} {i["entry"]}', is_pic, hit_offsets)
gdb.execute("c")
