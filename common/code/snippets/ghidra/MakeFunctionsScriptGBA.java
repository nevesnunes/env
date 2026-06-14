/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
// Script to ask user for a byte sequence that is a common function start
// make functions at those locations
// if code has only one block it asks the user where the data block is and splits the program into 
// code and data blocks
//@category Functions

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.app.cmd.disassemble.*;

public class MakeFunctionsScriptGBA extends GhidraScript {

	
	// Using the provided byte sequence and adddress range, iterate over the addresses and look for instructions!
	public int getFunctions(Address start,Address end,byte[] inst_sequence) {
		int funcCount = 0;
		boolean keepSearching = true;
		// Let the user know which byte sequence we are looking for.
		print("Searchig for byte sequence: " );
		for(byte b: inst_sequence) {
			print(String.format("%02X", b));
		}
		println("");

		// Get the memory space for the current program that we are analyzing.
		Memory memory = currentProgram.getMemory();
		Address currentAddr = start;
		while(keepSearching && (!monitor.isCancelled())&& (start.compareTo(end) <= 0)) {
			// Search the memory region that we provided for our byte sequence
			Address found = memory.findBytes(start, end, inst_sequence, null, true, monitor);
			if(found != null){
				if(getFunctionContaining(found) == null) {
					//Create our command to disassemble code in thumb mode
					ArmDisassembleCommand cmd = new ArmDisassembleCommand(found,null,true);;
					cmd.applyTo(currentProgram);
					if(cmd.getDisassembledAddressSet() != null){
						// Code was properly disassembled, create a function!
						Function func = createFunction(found, null);
						if (func != null) {
							println("Made function at address: " + found.toString());
							// Add the length of our function here so that we don't have to iterate through all of the created code.
							start = found.add(func.getBody().getNumAddresses());
							funcCount++;
							break;
						}
					}
				}
				start = found.add(2);
			// Nothing was found with memory.findBytes, time to bail!
			}else {
				keepSearching = false;
			}
		}		
		return funcCount;
	}
	
	// Give the user an option to choose a start address and end address for the script
	public Address[] getBlockInfo() throws Exception {
		int regionCount = askInt("Get Num of Regions","How many different memory regions would you like to analyze?");
		Address [] blocks = new Address[regionCount*2];
		for (int x = 0;x < regionCount; x+=2) {
			Address startAddress = askAddress("Get Start Address","Please enter the starting address of the region you wish to analyze");
			Address endAddress = askAddress("Get End Address","Please enter the end address for the region you wish to analyze");
			blocks[x] = startAddress;
			blocks[x+1] = endAddress;
		}
		return blocks;
	}
	@Override
	public void run() throws Exception {
		println("GBA Function Generation");
		int foundCount = 0;
		byte [] inst_bytes = new byte[] {0x00,(byte)0xB5};
		Address[] addrBlocks = getBlockInfo();
		for(int inst_byte = 0; inst_byte< 0xFF;inst_byte++) {
			for (int x = 0; x< addrBlocks.length; x += 2) {
				inst_bytes[0] = (byte)inst_byte;
				foundCount += getFunctions(addrBlocks[x],addrBlocks[x+1],inst_bytes);
			}
		}
		//int foundCount = getFunctions
		println("Made "+foundCount+ " functions");
	}

}
