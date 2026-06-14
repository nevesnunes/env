//copy the selected bytes into new address (you'll be prompted).
// note: you can copy small area by copy "Byte String" and paste. (this script is for large (>~150KB) area that can't copy-paste)
// note: this script does not support large area such as over 1GB.
// note: you can make "same view" by defining memory map "byte mapped". (this script is for "mutable" copy, emulating memcpy)
//@author murachue
//@category Memory
//@keybinding 
//@menupath 
//@toolbar 

import ghidra.app.script.GhidraScript;
import ghidra.program.model.util.*;
import ghidra.program.model.reloc.*;
import ghidra.program.model.data.*;
import ghidra.program.model.block.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.scalar.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.address.*;

public class CopyBytes extends GhidraScript {

    public void run() throws Exception {
        AddressRange src = null;
        if(currentSelection != null) {
            src = currentSelection.getFirstRange();
        }
        if(src == null) {
            println("please select source area.");
            return;
        }
        Address dest = askAddress("dstaddr?", String.format("Copy %s-%s(+%x) to?", src.getMinAddress(), src.getMaxAddress(), src.getBigLength()));
        // doc says "inefficient" but how to copy by api?
        setBytes(dest, getBytes(src.getMinAddress(), src.getBigLength().intValue()));
    }

}
