#!/usr/bin/env python3

from pathlib import Path
import argparse
import sys


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "inputs",
        type=str,
        nargs="+",
        help="input files",
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
    parser.add_argument("--split", action="store_true", help="Split file by configured pattern instead of zipping file")

    return parser.parse_args()


def put(i, o, data, skip, size):
    step_i = 0
    for x_i, x in enumerate(data):
        if x_i % (1 + skip) != 0:
            continue
        o[i] = x
        i += 1
        step_i += 1
        if step_i == size:
            i += size
            step_i = 0


def put_split(start, o, data, skip, size, upto):
    i = 0
    x_i = start
    while x_i < upto:
        for d_i in range(size):
            o[i] = data[x_i + d_i]
            i += 1
        x_i += skip + size


def split_file(args):
    with open(args.inputs[0], "rb") as f1:
        data = f1.read()

    output_len = len(data)
    assert output_len % 2 == 0

    o1 = bytearray(output_len // 2)
    o2 = bytearray(output_len // 2)
    put_split(0, o1, data, args.skip, args.size, output_len)
    put_split(args.size, o2, data, args.skip, args.size, output_len)

    parent_dir = Path(args.inputs[0]).parent
    output_dir = parent_dir / "splits"
    output_dir.mkdir(parents=True, exist_ok=True)

    output_dir.mkdir(parents=True, exist_ok=True)
    with open(output_dir / "1.bin", "wb") as f1_out:
        f1_out.write(o1)
    with open(output_dir / "2.bin", "wb") as f2_out:
        f2_out.write(o2)


def zip_files(args):
    assert len(args.inputs) == 2

    with open(args.inputs[0], "rb") as f1, open(args.inputs[1], "rb") as f2:
        f1_bytes = f1.read()
        f2_bytes = f2.read()

    output_len = len(f1_bytes) + len(f2_bytes)
    o = bytearray(output_len)

    put(0, o, f1_bytes, args.skip, args.size)
    put(args.size, o, f2_bytes, args.skip, args.size)

    parent_dir = Path(args.inputs[0]).parent
    output_dir = parent_dir / "merged"
    output_dir.mkdir(parents=True, exist_ok=True)

    output_dir.mkdir(parents=True, exist_ok=True)
    with open(output_dir / args.output, "wb") as f_out:
        f_out.write(o)


if __name__ == "__main__":
    args = parse_args()

    if args.split:
        split_file(args)
    else:
        zip_files(args)
