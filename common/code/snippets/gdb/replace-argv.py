#!/usr/bin/env python3

# Defines a gdb command that replaces an argument passed to the debugged process

import gdb
import re
import traceback


class ReplaceArgCmd(gdb.Command):
    def __init__(self):
        self.needle = b"REPLACE_ME"
        super(ReplaceArgCmd, self).__init__("rargv", gdb.COMMAND_USER)

    def invoke(self, replacement_arg, from_tty):
        try:
            inf = gdb.inferiors()[0]
            rsp = gdb.parse_and_eval("$rsp")
            argc = int.from_bytes(inf.read_memory(rsp, 0x8), byteorder="little")
            print(f"argc: {argc}")

            for i in range(argc):
                argvp = rsp + ((i + 1) * 0x8)
                argp = int.from_bytes(inf.read_memory(argvp, 0x8), byteorder="little")

                arg = b""
                arg_chunk_i = 0
                while b"\x00" not in arg:
                    arg += inf.read_memory(
                        argp + ((arg_chunk_i) * 0x100), 0x100
                    ).tobytes()
                    arg_chunk_i += 1
                arg = re.sub(b"\x00.*", b"\x00", arg)
                print(f"argv[{i}] @ {hex(argvp)} -> {hex(argp)} -> {arg}")

                if self.needle in arg:
                    arg = re.sub(
                        self.needle + b".*",
                        bytes(replacement_arg, encoding="latin-1") + b"\x00",
                        arg,
                    )
                    inf.write_memory(argp, arg, len(arg))
                    print(f"Replaced argv[{i}]!")

        except Exception as e:
            gdb.write("".join(traceback.TracebackException.from_exception(e).format()))
            raise e


ReplaceArgCmd()
