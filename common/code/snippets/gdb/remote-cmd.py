#!/usr/bin/env python3

# Defines a gdb command that executes a shell command on the target remote.

# Usage:
# - sh: `gdb -x remote-cmd.py`
# - gdb: `source remote-cmd.py`

# Limitations:
# - Symbols are not resolved on gdb `call` command: we need to call
#   libc functions by address, which requires loading addresses beforehand;
# - Requires libc debug info to be installed, otherwise symbols
#   can't be retrieved;
# - Huge slowdown can be experienced during automatic loading of child's
#   remote library symbols: instead, we can preload addresses using the
#   parent process, then disable automatic symbol loading;
# - Shell command output executed from gdb `call` command is not echoed
#   in the gdb terminal: however, we can capture it in a remote
#   temporary file, then read to memory and print.

import gdb
import re
import traceback
import uuid


class RemoteCmd(gdb.Command):
    def __init__(self):
        self.addresses = {}

        self.tmp_file = f'/tmp/{uuid.uuid4().hex}'
        gdb.write(f"Using tmp output file: {self.tmp_file}.\n")

        gdb.execute("set detach-on-fork off")
        gdb.execute("set follow-fork-mode parent")

        gdb.execute("set max-value-size unlimited")
        gdb.execute("set pagination off")
        gdb.execute("set print elements 0")
        gdb.execute("set print repeats 0")

        super(RemoteCmd, self).__init__("rcmd", gdb.COMMAND_USER)

    def preload(self):
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
            self.load(symbol)

    def load(self, symbol):
        if symbol not in self.addresses:
            address_string = gdb.execute(f"info address {symbol}", to_string=True)
            match = re.match(
                f'Symbol "{symbol}" is at ([0-9a-fx]+) .*', address_string, re.IGNORECASE
            )
            if match and len(match.groups()) > 0:
                self.addresses[symbol] = match.groups()[0]
            else:
                raise RuntimeError(f'Could not retrieve address for symbol "{symbol}".')

        return self.addresses[symbol]

    def output(self):
        # From `fcntl-linux.h`
        O_RDONLY = 0
        gdb.execute(
            f'set $fd = (int){self.load("open")}("{self.tmp_file}", {O_RDONLY})'
        )

        # From `stdio.h`
        SEEK_SET = 0
        SEEK_END = 2
        gdb.execute(f'set $len = (int){self.load("lseek")}($fd, 0, {SEEK_END})')
        gdb.execute(f'call (int){self.load("lseek")}($fd, 0, {SEEK_SET})')
        if int(gdb.convenience_variable("len")) <= 0:
            gdb.write("No output was captured.")
            return

        gdb.execute(f'set $mem = (void*){self.load("malloc")}($len)')
        gdb.execute(f'call (int){self.load("read")}($fd, $mem, $len)')
        gdb.execute('printf "%s\\n", (char*) $mem')

        gdb.execute(f'call (int){self.load("close")}($fd)')
        gdb.execute(f'call (int){self.load("free")}($mem)')

    def invoke(self, arg, from_tty):
        try:
            self.preload()

            is_auto_solib_add = gdb.parameter("auto-solib-add")
            gdb.execute("set auto-solib-add off")

            parent_inferior = gdb.selected_inferior()
            gdb.execute(f'set $child_pid = (int){self.load("fork")}()')
            child_pid = gdb.convenience_variable("child_pid")
            child_inferior = list(
                filter(lambda x: x.pid == child_pid, gdb.inferiors())
            )[0]
            gdb.execute(f"inferior {child_inferior.num}")

            try:
                gdb.execute(
                    f'call (int){self.load("execl")}("/bin/sh", "sh", "-c", "exec {arg} >{self.tmp_file} 2>&1", (char*)0)'
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
        except Exception as e:
            gdb.write("".join(traceback.TracebackException.from_exception(e).format()))
            raise e
        finally:
            gdb.execute(f'set auto-solib-add {"on" if is_auto_solib_add else "off"}')


RemoteCmd()
