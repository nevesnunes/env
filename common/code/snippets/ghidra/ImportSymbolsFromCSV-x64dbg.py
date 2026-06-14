#TODO write a description for this script
#@author 
#@category _NEW_
#@keybinding 
#@menupath 
#@toolbar 

from ghidra.app.cmd.disassemble import ArmDisassembleCommand
from ghidra.program.model.symbol.SourceType import *
import string
from ghidra.program.model.data import StringDataType

functionManager = currentProgram.getFunctionManager()

f = askFile("Give me a file to open", "Go baby go!")

for line in list(file(f.absolutePath))[1:]:  # note, cannot use open(), since that is in GhidraScript   
    
    pieces = line.split(',')
    if "Export" not in pieces[1]:
        continue

    try:
        name = pieces[3].strip().strip('"')
        address = toAddr(long("0x" + pieces[0].strip('"'), 16))
    
        if name:
            func = functionManager.getFunctionAt(address)
    
            if func is not None:
                old_name = func.getName()
                func.setName(name, USER_DEFINED)
                print("Renamed function {} to {} at address {}".format(old_name, name, address))
            else:
                #func = createFunction(address, name)
                cmd = ArmDisassembleCommand(address,None,True)
                cmd.applyTo(currentProgram)
                print("Created function {} at address {}".format(name, address))
        #elif "Label" in function_or_label:
        #    createLabel(address, name, False)
        #    print("Created label {} at address {}".format(name, address))
        #elif "string" in function_or_label:
        #    length = long(pieces[3].strip().strip('"'), 10)
        #    createAsciiString(address, length)
        #    print("Created string with length {} at address {}".format(length, address))
        #else:
        #    raise RuntimeError("Could not parse function_or_label = " + function_or_label)
    except Exception as e:
        print(e)
