from __future__ import print_function

import struct
import gdb


def log():

    # Get the inferior.
    try:
        inferior = gdb.selected_inferior()
    except RuntimeError:
        return
    if not inferior or not inferior.is_valid():
        return

    # Look up the 'crash_log' symbol.
    crash_log_symbol, _ = gdb.lookup_symbol('crash_log')
    if not crash_log_symbol:
        return

    # Dereference the pointer to the crash log.
    crash_log = crash_log_symbol.value().dereference()
    if crash_log.address == 0:
        return

    # Check whether there is any new data in the ring buffer.
    read = crash_log['read']
    write = crash_log['write']
    if read == write:
        return

    # Calculate the relative positions of the new log data.
    data = crash_log['data']
    mask = crash_log['mask']
    length = write - read
    size = mask + 1
    read_index = read & mask
    write_index = write & mask

    # Sanity check length.
    if length > 16 * 1024:
        return

    # Read the log data from the inferior.
    if write_index <= read_index:
        tail_bytes = inferior.read_memory(data + read_index, size - read_index)
        head_bytes = inferior.read_memory(data, write_index)
        bytes = tail_bytes + head_bytes
    else:
        bytes = inferior.read_memory(data + read_index, length)
    bytes = str(bytes)

    # Write the log data back to the user.
    bytes = ''.join(['log: ' + line + '\n' for line in bytes.splitlines()])
    gdb.write(bytes)

    # Update the read pointer to consume the data.
    inferior.write_memory(crash_log['read'].address, struct.pack("=I", write), 4)


def log_hook(event):
    log()


class Log(gdb.Command):
    """
    Inline logging for embeddeded programs

    Reads data from an in-memory ring buffer and displays
    it to the user. See ring_buffer.c and crash.c for
    details.

    Use 'log hook' and 'log unhook' to hook the stop event.
    """

    def __init__(self):
        super(Log, self).__init__(
            "log",
            gdb.COMMAND_SUPPORT,
            gdb.COMPLETE_NONE,
            True
        )


    def invoke(self, arg, from_tty):

        # Check for hook.
        if arg and arg == 'hook':
            gdb.events.stop.connect(log_hook)
            return

        # Check for unhook.
        if arg and arg == 'unhook':
            gdb.events.stop.disconnect(log_hook)
            return

        # Validate argument.
        if arg:
            gdb.write('usage: log [hook|unhook]\n')
            return

        log()


Log()
