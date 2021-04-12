#!/usr/bin/env python3

import ipdb
import networkx as nx
import r2pipe
import re
import sys


def parse_functions(filename):
    r2p = r2pipe.open(filename)
    r2p.cmd("aaa")
    functions = r2p.cmdj("aflj")
    parsed_functions = []
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
        parsed_functions.append(
            {
                "name": f["name"],
                "offset": f["offset"],
                "instructions": instructions,
                "opcodes": opcodes,
                "hash": hash(tuple(opcodes)),
            }
        )

    return parsed_functions


if __name__ == "__main__":
    g = nx.DiGraph()
    target_node = None
    target = None
    offset_dict = {}
    functions = parse_functions(sys.argv[1])
    for f in functions:
        if "walk_" not in f["name"]:
            continue
        offset_dict[f["name"]] = f["offset"]
        for ins in f["instructions"]:
            if "walk_" in ins:
                g.add_edge(f["name"], re.split(r"\s", ins)[-1])
            if re.search(r"mov [er]ax, 1", ins):
                target_node = f["name"]
                target = f

    p = nx.dijkstra_path(g, "sym.walk_start", target_node)
    print(p)
    ipdb.set_trace()
