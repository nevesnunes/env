# (c) Tim Blazytko 2021
# implementation based on the blog post "Automated Detection of Control-flow Flattening"
# https://synthesis.to/2021/03/03/flattening_detection.html
import sys

from miasm.analysis.binary import Container
from miasm.analysis.machine import Machine
from miasm.core.locationdb import LocationDB


def calc_flattening_score(asm_graph, loc_db):
    # init score
    score = 0.0
    # walk over all entry nodes in the graph
    for head in asm_graph.heads_iter():
        # compute dominator tree
        dominator_tree = asm_graph.compute_dominator_tree(head)
        # walk over all basic blocks
        for block in asm_graph.blocks:
            # get location key for basic block via basic block address
            block_key = loc_db.get_offset_location(block.lines[0].offset)
            # get all blocks that are dominated by the current block
            dominated = set(
                [block_key] + [b for b in dominator_tree.walk_depth_first_forward(block_key)])
            # check for a back edge
            if not any([b in dominated for b in asm_graph.predecessors(block_key)]):
                continue
            # calculate relation of dominated blocks to the blocks in the graph
            score = max(score, len(dominated)/len(asm_graph.nodes()))
    return score


# check args
if len(sys.argv) < 3:
    print("[x] Syntax: {} <file> <addr>".format(sys.argv[0]))
    sys.exit()

# parse stdin
file_path = sys.argv[1]
start_addr = int(sys.argv[2], 16)

# init symbol table
loc_db = LocationDB()

# open the binary for analysis
container = Container.from_stream(open(file_path, 'rb'), loc_db)

# cpu abstraction
machine = Machine(container.arch)

# init disassemble engine
mdis = machine.dis_engine(container.bin_stream, loc_db=loc_db)

# disassemble the function at address
asm_cfg = mdis.dis_multiblock(start_addr)

flattening_score = calc_flattening_score(asm_cfg, loc_db)

print(f"flattening score {flattening_score} for function {hex(start_addr)}")
