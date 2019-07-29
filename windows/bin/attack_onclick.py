#!/usr/bin/env python3

import gdb
import subprocess
class AttachOnClick(gdb.Command):
    def __init__(self):
        super(AttachOnClick, self).__init__('attach_onclick', gdb.COMMAND_RUNNING, gdb.COMPLETE_NONE)

    def invoke(self, arg, from_tty):
        if not from_tty:
            print('Only supported in interactive mode (from tty)')
            return
        if arg:
            print('No arguments supported')
            return
        xprop = subprocess.Popen(['xprop'], stdout=subprocess.PIPE)
        awk = subprocess.Popen(['awk', '/^_NET_WM_PID/{print $3}'], stdin=xprop.stdout, stdout=subprocess.PIPE)
        xprop.stdout.close()
        try:
            bpid = awk.communicate(timeout=60)[0]
        except subprocess.TimeoutExpired:
            print('No click within 60 seconds, giving up')
            xprop.terminate()
            awk.terminate()
            awk.wait(1)
            xprop.wait(1)
            return
        awk.wait(1)
        xprop.wait(1)
        spid = bpid.decode('ASCII').strip()
        if not spid:
            print('No pid could be obtained')
            return
        cmd = 'attach ' + spid
        gdb.execute(cmd, True)

AttachOnClick()

end
