#!/usr/bin/env python3

# Retrieve a Function (ghidra.program.model.listing.Function) object for a
#     named function.
# Important Note - This example will not work for functions that are
#                  dynamically loaded (such as from a .dll or .so).
functionName = "foo"
funList = getGlobalFunctions(functionName)
if len(funList) == 0:
    print("No functions named "{}" were found. To test this script manually rename"
          " one function to "{}"".format(functionName, functionName))
    exit()
elif len(funList) > 1:
    print("More than one function with the name "{}" found. Picking the first one "
          "found for this example".format(functionName))
    funObj = funList[0]
else:
    funObj = funList[0]
# Get the Address (ghidra.program.model.address.Address) object for the entry point of
#     a function
funObjAddr = funObj.getEntryPoint()
# How to create an address object for an specified address
newAddrObj = currentProgram.getMinAddress().getNewAddress(0x1234)
# Find number of references
print("There are {} references".format(funObj.getSymbol().getReferenceCount()))
# Get all references to a function, print address of the reference and function
#     containing the reference
# getReferencesTo returns a java array of ghidra.program.model.symbol.Reference
#     objects, the list() method coverts the java array into a python list
refList = list(getReferencesTo(funObjAddr))
print("{} references to function {}n".format(len(refList), funObj.getName()))
for ref in refList:
    # ref is an object of type ghidra.program.model.symbol.Reference
    print("Reference to function {} at address 0x{:016x} which is within "
          "function {}".format(funObj.getName(),
                               ref.getFromAddress().getOffset(),
                               getFunctionContaining(ref.getFromAddress())))
# Find first and last address of a function
print("Start address for function {} is 0x{:016x}".format(funObj.getName(),
                                                          funObjAddr.getOffset()))
currentAddr = funObjAddr
while (getFunctionContaining(currentAddr) == funObj):
    currentAddr = currentAddr.next()
# At this point currentAddr is past the end of funObj, go to the previous address
print("End address for function {} is 0x{:016x}n".format(
    funObj.getName(),
    currentAddr.previous().getOffset()))
# Easier way to find first and last address for a function
print("startAddr = 0x{:016x}".format(funObj.getBody().getMinAddress().getOffset()))
print("endAddr = 0x{:016x}n".format(funObj.getBody().getMaxAddress().getOffset()))
# Find all assembly instructions, opcodes and associated pcodes for all instructions
#     in a function
# currentInstr is a ghidra.program.model.listing.Instruction object
currentInstr = getInstructionContaining(funObjAddr)
while(getFunctionContaining(currentInstr.getAddress()) == funObj):
    print("Address = 0x{:016x} : bytes = "{}" : Insruction = {}".format(
        currentInstr.getAddress().getOffset(),
        ' '.join("%02x" % (b & 0xff) for b in list(currentInstr.getBytes())),
        currentInstr.toString()))
    currentInstr = currentInstr.getNext()
    print("")
