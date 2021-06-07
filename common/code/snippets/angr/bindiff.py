#!/usr/bin/env python3

import angr
import sys

if __name__ == "__main__":
    binary_path_1 = sys.argv[1]
    binary_path_2 = sys.argv[2]
    b = angr.Project(binary_path_1, load_options={"auto_load_libs": False})
    b2 = angr.Project(binary_path_2, load_options={"auto_load_libs": False})
    bindiff = b.analyses.BinDiff(b2)

    identical_functions = bindiff.identical_functions
    differing_functions = bindiff.differing_functions
    unmatched_functions = bindiff.unmatched_functions
    print(identical_functions)
    print(differing_functions)
    print(unmatched_functions)
    # fdiff = bindiff.get_function_diff(0x400616, 0x400616)
    # block_matches = { (a.addr, b.addr) for a, b in fdiff.block_matches }
