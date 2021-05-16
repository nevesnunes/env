#!/usr/bin/env python3


def findFunction(functionName):
    """
    Return a function object for a named function (or None on failure).
    :param str functionName: Name of the function to find
    :return: A ghidra.program.model.listing.Function for functionName
             or None if the function is not found
    """
    # first try getGlobalFunctions for functions compiled into the binary
    funList = list(getGlobalFunctions(functionName))
    if funList == []:
        # The function could be dynamic, look for the thunk function stub
        # that calls the external function
        fm = currentProgram.getFunctionManager()
        fi = fm.getFunctions(True)
        while fi.hasNext():
            functionObj = fi.next()
            if functionObj.getName() == functionName:
                print(
                    "Found {} at 0x{:016x}".format(
                        functionName, functionObj.getEntryPoint().getOffset()
                    )
                )
                funList.append(functionObj)
    if len(funList) == 0:
        print("No functions named {} were found".format(functionName))
        return None
    elif len(funList) == 1:
        return funList[0]
    elif len(funList) == 2:
        # functionName is an external function, now pick the correct one.
        #     Typically the false positive that ghidra finds is a placeholder
        #     for the relocation of the imported function. The only function
        #     that calls this false positive function should be the other
        #     item in funList
        #         * For a PE file this false positive function would be within
        #           the Import Address Table (IAT)
        #         * For a ELF file this false positive function would be within
        #           an external block of memory. This is a placeholder address
        #           used by the Global Offsets Table (GOT).
        #     The function that should be returned is located at the address of
        #     functionName that all functions within the binary reference and
        #     the function's body consists of a jump.
        #         * For a PE file the desired function is a thunk function that
        #          jumps to the appropriate entry within the IAT
        #         * For an ELF file the desired function is located within the
        #           Procedure Linkage Table (PLT). This function jumps to an
        #           address contained within the GOT.

        for fun in funList:
            if fun.getBody().getNumAddresses() == 1:
                funList.remove(fun)
        if len(funList) == 1:
            print("Address 0x{:016x}".format(funList[0].getEntryPoint().getOffset()))
            return funList[0]
        return None
    else:
        print(
            "{} matches for a function named {} were found".format(
                len(funList), functionName
            )
        )
        for fun in funList:
            print("Address 0x{:016x}".format(fun.getEntryPoint().getOffset()))
        return None
    return None
