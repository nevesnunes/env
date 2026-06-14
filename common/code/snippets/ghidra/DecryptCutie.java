//TODO write a description for this script
//@author 
//@category _NEW_
//@keybinding 
//@menupath 
//@toolbar 

import ghidra.app.script.GhidraScript;
import ghidra.program.model.mem.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.util.*;
import ghidra.util.task.TaskMonitor;
import ghidra.program.model.reloc.*;
import ghidra.program.model.data.*;
import ghidra.program.model.block.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.scalar.*;
import ghidra.program.model.listing.*;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.*;

public class DecryptCutie extends GhidraScript {

    public void run() throws Exception {
    	Reference[] xrefs = getReferencesTo(toAddr(0x40a820));
    	int xi = 0;
    	for (Reference xref : xrefs) {
    		Address addr = xref.getFromAddress();
    		if (addr.getOffset() < 0x00409ff0 || addr.getOffset() > 0x0040a7a8) {
    			continue;
    		}
    		
    		Address insAddr = toAddr(addr.getOffset());
    		Instruction ins = getInstructionBefore(insAddr);
    		int bufLen = 1000;
			Address strAddr = null;
    		String encrypted = null;
    		int n = 0;
    		for (int i = 0; i < 4; i++) {
    			if (ins.getMnemonicString().equalsIgnoreCase("MOV")) {
	    			if (ins.getDefaultOperandRepresentation(0).equalsIgnoreCase("EDX")) {
	    				n = Integer.decode(ins.getDefaultOperandRepresentation(1));
	    			} else if (ins.getDefaultOperandRepresentation(0).equalsIgnoreCase("ESI")) {
	    				//encrypted = getDataAt(toAddr(Long.decode(ins.getDefaultOperandRepresentation(1))));
	    				strAddr = toAddr(Long.decode(ins.getDefaultOperandRepresentation(1)));
	    			}
    			}
        		insAddr = ins.getAddress();
        		ins = getInstructionBefore(insAddr);
    		}
    		
    		final byte[] buf = new byte[bufLen];
			currentProgram.getMemory().getBytes(strAddr, buf, 0, bufLen);
			encrypted = "";
			for (int j = 0; j < n; j++) {
				encrypted += (char) buf[j];
			}

    		println(hex(xi) + " @" + hex(strAddr.getOffset()) + " = " + decrypt(encrypted, n));
    		xi++;
    	}
    }

	private String decrypt(String encrypted, int n) {
		StringBuilder o = new StringBuilder(encrypted);
		for (int i = 0; i < n; i++) {
			o.setCharAt(i, (char) (o.charAt(i) ^ 0x54));
		}
		return o.toString();
	}

	private String hex(long v) {
		return String.format("0x%02x", v);
	}
}
