#!/usr/bin/env python3

import gdb
import sys

ptid = (-1, -1, -1)


def u32(n):
    return n & 0xFFFFFFFF


class PathBreakpoint(gdb.Breakpoint):
    def __init__(self):
        gdb.Breakpoint.__init__(
            self,
            f"*path_openat",
            gdb.BP_BREAKPOINT,
            temporary=True,
        )
        self.hasThreadWP = False

    def stop(self):
        global ptid
        sptid = gdb.selected_thread().ptid
        path = (
            str(gdb.parse_and_eval("(char *)nd->name->name"))
            .split()[1]
            .strip()
            .strip('"')
        )
        if path == "/tmp/o.png":
            ptid = sptid
            print(
                f"[PathBP] ptid={ptid[0]},{ptid[1]},{ptid[2]} path={path}",
                file=sys.stderr,
            )
            return True
        return False


class ThreadWatchpoint(gdb.Breakpoint):
    def __init__(self):
        gdb.Breakpoint.__init__(
            self, f"$rax == 0xfffffff3", gdb.BP_WATCHPOINT, temporary=False
        )

    def stop(self):
        global ptid
        if ptid[1] != -1:
            sptid = gdb.selected_thread().ptid
            if sptid[1] == ptid[1]:
                rip = int(str(gdb.parse_and_eval("$rip")).split()[0], 16)
                print(
                    f"[ThreadWP] ptid={sptid[0]},{sptid[1]},{sptid[2]} rip={hex(rip)}",
                    file=sys.stderr,
                )
                return True
        return False


#gdb.execute("set can-use-hw-watchpoints 0")
ThreadWatchpoint()
PathBreakpoint()

# * 198  Thread 1002 (evince-thumbnai)  path_openat (nd=nd@entry=0xffffc90002babdd0, op=op@entry=0xffffc90002babee4, flags=flags@entry=65) at fs/namei.c:3346
# >>> python print(gdb.selected_thread().ptid)
# (42000, 1002, 0)
