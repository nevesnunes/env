// Searches all instructions for any references to undefined memory addresses.
// Useful for reversing firmware when you are still determining the correct memory mappings.
// Invalid addresses could indicate that you need to add a new segment at that address.
//
// @author starfleetcadet75
// @category Search
// @keybinding
// @menupath
// @toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.symbol.Reference;
import ghidra.util.Msg;
import ghidra.util.SystemUtilities;

public class FindInvalidMemoryReferences extends GhidraScript {
	@Override
	protected void run() throws Exception {
		InstructionIterator instrIter = currentProgram.getListing().getInstructions(true);
		AddressSet set = new AddressSet();

		while (instrIter.hasNext() && !monitor.isCancelled()) {
			Instruction instr = instrIter.next();
			Reference[] refs = instr.getReferencesFrom();

			for (Reference ref : refs) {
				Address dest = ref.getToAddress();

				if (!currentProgram.getMemory().contains(dest) && !dest.isStackAddress()) {
					set.addRange(instr.getMinAddress(), instr.getMaxAddress());
				}
			}
		}

		Address[] addresses = new Address[set.getNumAddressRanges()];
		int i = 0;
		for (AddressRange range : set) {
			addresses[i++] = range.getMinAddress();
		}

		if (SystemUtilities.isInHeadlessMode()) {
			Msg.error(this, "Invalid Memory Addresses Found: " + set.getNumAddressRanges());
		}
		else {
			this.show(addresses);
		}
	}
}
