//TODO write a description for this script
//@author 
//@category _NEW_
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
import ghidra.program.disassemble.Disassembler;
import ghidra.program.disassemble.DisassemblerMessageListener;
import ghidra.program.model.address.*;

public class DeobfNames extends GhidraScript {

	private static final long NAMES_LST_ADDR = 0xeb5d4;
	private static final long ROM_MAX_ADDR = 0x1fffff;

	public void run() throws Exception {
		Program program = currentProgram;
		Listing listing = program.getListing();
		Disassembler disassembler = Disassembler
				.getDisassembler(currentProgram, monitor, DisassemblerMessageListener.CONSOLE);

		final int maxFuncLen = 100;
		final int minFuncLen = 4;
		final byte[] buf = new byte[maxFuncLen];
		Address lastAddress = getFirstFunction().getEntryPoint().getNewAddress(NAMES_LST_ADDR);
		long lastOffset = lastAddress.getOffset();
		while (lastAddress != null && lastOffset < ROM_MAX_ADDR) {
			currentProgram.getMemory().getBytes(lastAddress, buf, 0, 4);
			long nextOffset = ((long) buf[0] & 0xFF) << 24;
			nextOffset += ((long) buf[1] & 0xFF) << 16;
			nextOffset += ((long) buf[2] & 0xFF) << 8;
			nextOffset += ((long) buf[3] & 0xFF);
			if (nextOffset < 4) {
				break;
			}

			long lastNameOffset = lastOffset + 4;
			Address lastNameAddress = lastAddress.getNewAddress(lastNameOffset);
			currentProgram.getMemory().getBytes(lastNameAddress, buf, 0, maxFuncLen);
			String funcName = "";
			int nameLen = 0;
			for (byte b : buf) {
				if (b == 0) {
					break;
				}
				funcName += (char) (((int) b & 0xff) - 0x80); // using unsigned
																// value
				nameLen += 1;
			}
			if (nameLen == 0) {
				lastAddress = lastAddress.getNewAddress(lastOffset + nextOffset);
				lastOffset = lastAddress.getOffset();
				
				continue;
			}
			nameLen += 1; // null delimiter

			println(String.format("@0x%x: %s", lastNameOffset, funcName));

			currentProgram.getListing().clearCodeUnits(lastNameAddress,
					lastNameAddress.getNewAddress(lastNameAddress.getOffset() + nameLen),
					false);
			currentProgram.getListing()
					.createData(lastNameAddress, StringDataType.dataType, nameLen);
			createLabel(lastNameAddress, "dobf_" + funcName, true, SourceType.USER_DEFINED);

			lastAddress = lastAddress.getNewAddress(lastOffset + nextOffset);
			lastOffset = lastAddress.getOffset();
		}
	}
}
