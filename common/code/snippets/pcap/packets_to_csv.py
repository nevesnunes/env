#!/usr/bin/env python3

import argparse
import csv
import json
from typing import Any, Dict, Generator, List, Set


def flatten(items: List[Any]) -> Generator[Any, None, None]:
    for item in items:
        if isinstance(item, list) and isinstance(item[0], list):
            yield from flatten(item)
        else:
            yield item


def walk(node: Any, name: str) -> List[Any]:
    if node is None:
        return [name, ""]
    elif isinstance(node, bool):
        return [name, str(node).lower()]
    elif isinstance(node, (str, bytes)):
        return [name, node]
    elif isinstance(node, dict):
        res = []
        for k, v in sorted(node.items()):
            res.append(walk(v, name + "." + k))
        return res
    elif isinstance(node, (list, tuple)):
        res = []
        for i, e in enumerate(node):
            res.append(walk(e, name + str([i])))
        return res
    else:
        return [name, node]


def all_numbers(values: List[Any]) -> bool:
    for val in values:
        if not val:
            continue
        try:
            float(val)
        except ValueError:
            return False
    return True


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "filename",
        type=str,
        help="Path for json file with array of packets (output by `tshark -T json`)",
    )
    parser.add_argument(
        "-t",
        "--type",
        type=str,
        default="str",
        const="str",
        nargs="?",
        choices=["float", "str"],
        help="Target type used when transforming values",
    )
    parsed_args = parser.parse_args()

    filename = parsed_args.filename
    with open(filename, "r") as f:
        json_data = json.load(f)
    if not isinstance(json_data, list):
        raise RuntimeError("Expected array.")

    keys = set()
    kv: Dict[str, Set[Any]] = {}
    row_kv: Dict[int, Dict[str, Any]] = {}
    for i, el in enumerate(json_data):
        for flat_pair in flatten(walk(el, "data")):
            key = flat_pair[0]
            val = flat_pair[1]

            keys.add(key)
            if key not in kv:
                kv[key] = set()
            kv[key].add(val)

            if i not in row_kv:
                row_kv[i] = {}
            if not val:
                row_kv[i][key] = ""
            else:
                row_kv[i][key] = val

    for key, vals in kv.items():
        vals_list = list(vals)
        is_all_numbers = all_numbers(vals_list)
        for i in range(len(json_data)):
            if key not in row_kv[i]:
                row_kv[i][key] = ""
            elif not is_all_numbers and parsed_args.type == "float":
                row_kv[i][key] = float(vals_list.index(row_kv[i][key]))

    output_suffix = ""
    if parsed_args.type == "float":
        output_suffix = ".float"
    output_filename = f"{filename}{output_suffix}.csv"
    with open(output_filename, "w", newline="") as f2:
        writer = csv.DictWriter(f2, keys)
        writer.writeheader()
        for el in row_kv.values():
            writer.writerow(el)
