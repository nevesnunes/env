#!/usr/bin/env python3

import argparse
import sys


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "input1",
        type=argparse.FileType("rb"),
        help="1st input file",
    )
    parser.add_argument(
        "input2",
        type=argparse.FileType("rb"),
        help="2nd input file",
    )
    parser.add_argument(
        "output",
        type=str,
        default="out.bin",
        nargs="?",
        help="output filename",
    )
    parser.add_argument(
        "--skip",
        type=lambda x: int(x, 0),
        default=0,
        help="Number of bytes to skip from a file on each iteration",
    )
    parser.add_argument(
        "--size",
        type=lambda x: int(x, 0),
        default=1,
        help="Number of bytes to take from a file on each iteration",
    )
    return parser.parse_args()


def put(i, o, data, parsed_args):
    step_i = 0
    for x_i, x in enumerate(data):
        if x_i % (1 + parsed_args.skip) != 0:
            continue
        o[i] = x
        i += 1
        step_i += 1
        if step_i == parsed_args.size:
            i += parsed_args.size
            step_i = 0


if __name__ == "__main__":
    parsed_args = parse_args()

    with parsed_args.input1 as f1, parsed_args.input2 as f2:
        f1_bytes = f1.read()
        f2_bytes = f2.read()

    output_len = len(f1_bytes) + len(f2_bytes)
    o = bytearray(output_len)

    put(0, o, f1_bytes, parsed_args)
    put(parsed_args.size, o, f2_bytes, parsed_args)

    with open(parsed_args.output, "wb") as f_out:
        f_out.write(o)
