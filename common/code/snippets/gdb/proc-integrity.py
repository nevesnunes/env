#!/usr/bin/env python3

"""
Monitors integrity of process mappings (e.g. to detect self-modifying code).

Example:
```
Mismatch! /tmp/a.out_end_0x401000_0x402000
   start: 0x401000 0x402000 r-x
     end: 0x401000 0x402000 rwx
```

Validation:
```
diff -Nauw \
    <(objdump -D -b binary -mi386:x86-64 a.out_start_0x401000_0x402000) \
    <(objdump -D -b binary -mi386:x86-64 a.out_end_0x401000_0x402000)
```

References:
- ~/opt/pwndbg/pwndbg/vmmap.py
"""

import gdb
import hashlib
import os
import re


def proc_pid_maps(pid):
    """
    Parse the contents of /proc/$PID/maps on the server.
    """

    locations = [
        "/proc/%s/maps" % pid,
        "/proc/%s/map" % pid,
        "/usr/compat/linux/proc/%s/maps" % pid,
    ]

    for location in locations:
        try:
            with open(location, "rb") as f:
                data = f.read()
            break
        except (OSError, gdb.error):
            continue
    else:
        return {}

    data = data.decode()

    pages = {}
    for line in data.splitlines():
        maps, perm, offset, dev, inode_objfile = line.split(None, 4)

        start, stop = maps.split("-")

        try:
            inode, objfile = inode_objfile.split(None, 1)
        except BaseException:
            objfile = "anon_" + start[:-3]

        start = int(start, 16)
        stop = int(stop, 16)
        offset = int(offset, 16)
        size = stop - start

        flags = 0
        if "r" in perm:
            flags |= 4
        if "w" in perm:
            flags |= 2
        if "x" in perm:
            flags |= 1

        key = f"{hex(start)}_{hex(stop)}"
        page = {
            "start": start,
            "end": stop,
            "size": size,
            "flags": flags,
            "offset": offset,
            "objfile": objfile,
        }
        pages[key] = page

    return pages


def dump_maps(pages, cmdline, name):
    maps = {}
    for key in pages.keys():
        page = pages[key]
        start = page["start"]
        end = page["end"]
        if cmdline in page["objfile"]:
            key = f"{hex(start)}_{hex(end)}"
            tmpfile = f"/tmp/{name}_{key}"
            gdb.execute(
                f"dump binary memory {tmpfile} {hex(start)} {hex(end)}", to_string=True
            ).splitlines()
            with open(tmpfile, "rb") as f:
                maps[key] = {
                    "tmpfile": tmpfile,
                    "hash": hashlib.sha256(f.read()).hexdigest(),
                }

    return maps


def dump_flags(mask):
    return "".join(
        [
            "r" if mask & 4 else "-",
            "w" if mask & 2 else "-",
            "x" if mask & 1 else "-",
        ]
    )


gdb.execute("starti")

pid = gdb.inferiors()[0].pid
cmdline = gdb.current_progspace().filename
basename = os.path.basename(cmdline)

start_pages = proc_pid_maps(pid)
start_maps = dump_maps(start_pages, cmdline, f"{basename}_start")

gdb.execute("catch syscall exit exit_group")
gdb.execute("c")

end_pages = proc_pid_maps(pid)
end_maps = dump_maps(end_pages, cmdline, f"{basename}_end")

for key in end_maps.keys():
    if key not in start_maps or start_maps[key]["hash"] != end_maps[key]["hash"]:
        gdb.write(f"Mismatch! {end_maps[key]['tmpfile']}\n")
        if key in start_pages:
            page = start_pages[key]
            start = page["start"]
            end = page["end"]
            gdb.write(
                f"   start: {hex(start)} {hex(end)} {dump_flags(page['flags'])}\n"
            )
        if key in end_pages:
            page = end_pages[key]
            start = page["start"]
            end = page["end"]
            gdb.write(
                f"     end: {hex(start)} {hex(end)} {dump_flags(page['flags'])}\n"
            )
