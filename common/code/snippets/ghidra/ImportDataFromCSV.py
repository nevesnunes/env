# TODO write a description for this script
# @author
# @category _NEW_
# @keybinding
# @menupath
# @toolbar

# from ghidra.app.cmd.disassemble import ArmDisassembleCommand
from ghidra.app.cmd.disassemble import DisassembleCommand
from ghidra.program.model.symbol.SourceType import *
import string
from ghidra.program.model.data import StringDataType

functionManager = currentProgram.getFunctionManager()

f = askFile("Give me a file to open", "Go baby go!")

for line in list(file(f.absolutePath))[1:]:  # note, cannot use open(), since that is in GhidraScript
    # "Data","Location","Type","Size"
    pieces = line.split('","')

    try:
        size = int(pieces[3].strip().strip('"'), 10)
        try:
            start = long("0x" + pieces[1].strip('"'), 16)
            start_addr = toAddr(start)
        except:
            start = pieces[1].strip('"')
            start_addr = currentProgram.getAddressFactory().getAddress(start)

        currentProgram.getListing().clearCodeUnits(start_addr, start_addr, False)
        createAsciiString(start_addr, size)
    except Exception as e:
        print(e)
