//TODO write a description for this script
//@author 
//@category _NEW_
//@keybinding 
//@menupath 
//@toolbar 

import java.io.InputStream;

import javax.swing.plaf.metal.MetalBorders.Flush3DBorder;

import ghidra.app.script.GhidraScript;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.MemoryByteProvider;
import ghidra.program.model.mem.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.util.*;
import ghidra.program.model.reloc.*;
import ghidra.program.model.data.*;
import ghidra.program.model.block.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.scalar.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;

public class AMMDerefs extends GhidraScript {

    public void run() throws Exception {
    	final long base_1 = 0x8751a50;
    	final long base_1_end = 0x8751dd8;
    	final long base_2 = 0x8751ddc;
    	final long base_2_end = 0x8752178;
    	final long base_i = 0x819980c;
    	final long base_1_n = (base_1_end - base_1) / 4;
    	final long base_2_n = (base_2_end - base_2) / 4;
		println(String.format("base tbls n: 0x%X 0x%X", base_1_n, base_2_n));

		ByteProvider provider = new MemoryByteProvider(currentProgram.getMemory(), currentProgram.getImageBase());
		BinaryReader reader = new BinaryReader(provider, true);
		for (int i = 0; i < base_2_n; i++) {
			long entry_2 = reader.readUnsignedInt(base_2 + (i * 4));
			long entry_i = base_i + entry_2;
			println(String.format("0x%X + 0x%X = 0x%X", base_i, entry_2, entry_i));
			for (int j = 0; j < 4; j++) {
				long x = reader.readUnsignedShort(entry_i + (j * 2));
				//print(String.format("%04X ", x));
				if (j == 3 && x < 5) {

					for (int jj = 0; jj < 4; jj++) {
						long xx = reader.readUnsignedShort(entry_i + (jj * 2));
						print(String.format("%04X ", xx));
					}
					print("\n");
				}
			}
			//print("\n");
		}
    }

}
