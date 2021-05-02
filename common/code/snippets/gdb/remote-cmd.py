#!/usr/bin/env python3

# Defines a gdb command that executes a shell command on the target remote.

# Usage:
# - sh: `gdb -x remote-cmd.py`
# - gdb: `source remote-cmd.py`

# Limitations:
# - Symbols not resolved on `call` command
#     - Mitigation: use loaded addresses
# - Huge slowdown during loading of child's remote library symbols
#     - Mitigation: preload addresses, then disable automatic symbol loading
# - Shell command output executed from `call` gdb command not echoed
#     - Mitigation: Capture in temporary file, then read to memory and print

import gdb
import re
import os

if "TMP_FILE" in os.environ:
    TMP_FILE = os.environ["TMP_FILE"]
else:
    TMP_FILE = "/tmp/123"


def address(symbol):
    # FIXME: Why none of these contain the symbol?
    # - gdb.lookup_symbol('fork')
    # - gdb.lookup_global_symbol('fork')
    # - gdb.selected_frame().find_sal().symtab.objfile.lookup_global_symbol('fork')
    # - for objfile in gdb.objfiles():
    #       if objfile.lookup_static_symbol('fork') or objfile.lookup_global_symbol('fork'):
    #           [...]
    address_string = gdb.execute(f"info address {symbol}", to_string=True)
    match = re.match(
        f'Symbol "{symbol}" is at ([0-9a-fx]+) .*', address_string, re.IGNORECASE
    )
    if match and len(match.groups()) > 0:
        return match.groups()[0]

    raise RuntimeError(f'Could not retrieve address for symbol "{symbol}".')


class RemoteCmd(gdb.Command):
    def __init__(self):
        gdb.execute("set detach-on-fork off")
        gdb.execute("set follow-fork-mode parent")

        self.addresses = {}

        super(RemoteCmd, self).__init__("rcmd", gdb.COMMAND_USER)

    def load_addresses(self):
        for symbol in [
            "close",
            "execl",
            "fork",
            "free",
            "lseek",
            "malloc",
            "open",
            "read",
        ]:
            if symbol not in self.addresses:
                self.addresses[symbol] = address(symbol)

    def output(self):
        # From `fcntl-linux.h`
        O_RDONLY = 0
        gdb.execute(
            f'set $fd = (int){self.addresses["open"]}("{TMP_FILE}", {O_RDONLY})'
        )

        # From `stdio.h`
        SEEK_SET = 0
        SEEK_END = 2
        gdb.execute(f'set $len = (int){self.addresses["lseek"]}($fd, 0, {SEEK_END})')
        gdb.execute(f'call (int){self.addresses["lseek"]}($fd, 0, {SEEK_SET})')
        if int(gdb.convenience_variable("len")) <= 0:
            gdb.write("No output was captured.")
            return

        gdb.execute(f'set $mem = (void*){self.addresses["malloc"]}($len)')
        gdb.execute(f'call (int){self.addresses["read"]}($fd, $mem, $len)')
        gdb.execute("p/s (char*)$mem")

        gdb.execute(f'call (int){self.addresses["close"]}($fd)')
        gdb.execute(f'call (int){self.addresses["free"]}($mem)')

    def invoke(self, arg, from_tty):
        try:
            self.load_addresses()

            is_auto_solib_add = gdb.parameter("auto-solib-add")
            gdb.execute("set auto-solib-add off")

            parent_inferior = gdb.selected_inferior()
            gdb.execute(f'set $child_pid = (int){self.addresses["fork"]}()')
            child_pid = gdb.convenience_variable("child_pid")
            child_inferior = list(
                filter(lambda x: x.pid == child_pid, gdb.inferiors())
            )[0]
            gdb.execute(f"inferior {child_inferior.num}")

            try:
                gdb.execute(
                    f'call (int){self.addresses["execl"]}("/bin/sh", "sh", "-c", "exec {arg} >{TMP_FILE} 2>&1", (char*)0)'
                )
            except gdb.error as e:
                if (
                    "The program being debugged exited while in a function called from GDB"
                    in str(e)
                ):
                    pass
                else:
                    raise e
            finally:
                gdb.execute(f"inferior {parent_inferior.num}")
                gdb.execute(f"remove-inferiors {child_inferior.num}")

            self.output()
        finally:
            gdb.execute(f'set auto-solib-add {"on" if is_auto_solib_add else "off"}')


RemoteCmd()
