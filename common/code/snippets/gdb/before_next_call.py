import gdb

class StepBeforeNextCall (gdb.Command):
    def __init__ (self):
        super (StepBeforeNextCall, self).__init__ ("step-before-next-call",
                                                   gdb.COMMAND_OBSCURE)

    def invoke (self, arg, from_tty):
        arch = gdb.selected_frame().architecture()

        while True:
            current_pc = addr2num(gdb.selected_frame().read_register("pc"))
            disa = arch.disassemble(current_pc)[0]
            if "call" in disa["asm"]: # or startswith ?
                break

            SILENT=True
            gdb.execute("stepi", to_string=SILENT)

        print("step-before-next-call: next instruction is a call.")
        print("{}: {}".format(hex(int(disa["addr"])), disa["asm"]))

def addr2num(addr):
    try:
        return int(addr)  # Python 3
    except:
        return long(addr) # Python 2

StepBeforeNextCall()
