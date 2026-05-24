//Make interrupt vectors on x86-16/i286. Assumes that vector data was loaded at address 0. 
//@author flib
//@category
//@keybinding 
//@menupath 
//@toolbar 

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.Pointer16DataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;

public class MakeIntVecsX86 extends GhidraScript {

    public void run() throws Exception {
        final Listing lst = currentProgram.getListing();
        final ReferenceManager refMgr = currentProgram.getReferenceManager();

        // Make vector references.
        for (int i = 0; i < 0x400; i += 4) {
            final Address addr = addr(i);
            final byte[] vec = getBytes(addr, 4);
            // 16-bit Real Mode pointer built from 16-bit segment + 16-bit offset.
            final long funcPtr = ((((vec[3] & 0xff) << 12) | ((vec[2] & 0xff) << 4))
                    + ((vec[1] & 0xff) << 8)
                    + (vec[0] & 0xff));
            println(String.format("Vec @ %04x => %06x", i, funcPtr));
            if (funcPtr == 0) {
                continue;
            }

            createData(addr, new Pointer16DataType());

            final Address funcAddr = addr(funcPtr);
            final Reference ref = refMgr.getPrimaryReferenceFrom(addr, 0);
            if (ref != null && !funcAddr.equals(ref.getToAddress())) {
                refMgr.delete(ref);
                refMgr.addOffsetMemReference(addr,
                        funcAddr,
                        true,
                        0,
                        RefType.DATA,
                        SourceType.DEFAULT,
                        0);
            }

            final Instruction instr = lst.getInstructionAt(funcAddr);
            if (instr == null) {
                final DisassembleCommand cmd = new DisassembleCommand(funcAddr, null, true);
                if (!cmd.applyTo(currentProgram) || cmd.getDisassembledAddressSet().isEmpty()) {
                    printerr(String.format("Null instruction @ %06x", funcAddr.getUnsignedOffset()));
                }
            }

            final String funcName = String.format("int_vec_%02x", i / 4);
            Function func = lst.getFunctionAt(funcAddr);
            if (func == null) {
                func = createFunction(funcAddr, funcName);
            } else if (func.getName().startsWith("FUN_")) {
                func.setName(funcName, SourceType.DEFAULT);
            }
        }

        // Add vector references to interrupt calls.
        final InstructionIterator instrIt = lst.getInstructions(true);
        while (instrIt.hasNext() && !monitor.isCancelled()) {
            final Instruction instr = instrIt.next();
            if (!instr.getMnemonicString().equalsIgnoreCase("int")) {
                continue;
            }

            final Address instrAddr = instr.getAddress();
            switch (instr.getInputObjects()[1]) {
                case Scalar s -> {
                    final long vecNum = s.getUnsignedValue();
                    println(String.format("Call @ %06x => int_vec_%02x", instrAddr.getUnsignedOffset(), vecNum));

                    final Reference vecRef = refMgr.getPrimaryReferenceFrom(addr(vecNum * 4), 0);
                    final Reference callerRef = refMgr.addMemoryReference(instrAddr,
                            vecRef.getToAddress(),
                            RefType.CALL_OVERRIDE_UNCONDITIONAL,
                            SourceType.USER_DEFINED,
                            Reference.MNEMONIC);
                    refMgr.setPrimary(callerRef, true);
                }
                default -> printerr(String.format("Unhandled op @ %06x", instrAddr.getUnsignedOffset()));
            }
        }
    }

    private Address addr(final long offset) {
        return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
    }
}
