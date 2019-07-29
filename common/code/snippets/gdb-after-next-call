import gdb

def callstack_depth():
    depth = 1
    frame = gdb.newest_frame()
    while frame is not None:
        frame = frame.older()
        depth += 1
    return depth

class StepToNextCall (gdb.Command):
    def __init__ (self):
        super (StepToNextCall, self).__init__ ("step-to-next-call", 
                                               gdb.COMMAND_OBSCURE)

    def invoke (self, arg, from_tty):
        start_depth = current_depth =callstack_depth()

        # step until we're one step deeper
        while current_depth == start_depth:
            SILENT=True
            gdb.execute("step", to_string=SILENT)
            current_depth = callstack_depth()

        # display information about the new frame
        gdb.execute("frame 0")

StepToNextCall() 
