//Rename functions based on code patterns
//@author flib
//@category
//@keybinding
//@menupath
//@toolbar

import java.util.Arrays;
import java.util.Locale;
import java.util.stream.Collectors;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.VarnodeContext;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

public class AutoRenameFuncs extends GhidraScript {
    @Override
    protected void run() throws Exception {
        try {
            final VarnodeContext vctx = new VarnodeContext(
                    currentProgram,
                    currentProgram.getProgramContext(),
                    currentProgram.getProgramContext(),
                    true);

            FunctionManager fm = currentProgram.getFunctionManager();
            AddressSetView asv = new AddressSet(addr(0xf0000), addr(0xfffff));
            FunctionIterator funcIt = fm.getFunctions(asv, true);
            while (funcIt.hasNext()) {
                monitor.checkCancelled();

                var dec = new DecompInterface();
                dec.setOptions(new DecompileOptions());
                dec.openProgram(currentProgram);

                Function func = funcIt.next();
                if (!func.getName().startsWith("FUN_")) {
                    continue;
                }

                var decFuncRes = dec.decompileFunction(func, 10, monitor);
                var highFunc = decFuncRes.getHighFunction();
                if (highFunc != null) {
                    var pcodeIt = highFunc.getPcodeOps();
                    while (pcodeIt.hasNext()) {
                        PcodeOpAST op = pcodeIt.next();
                        if (rename(vctx, func, op)) {
                            break;
                        }
                    }
                } else {
                    Instruction instr = currentProgram.getListing()
                            .getInstructionAt(func.getBody().getMinAddress());
                    long maxOffs = func.getBody().getMaxAddress().getUnsignedOffset();
                    while (instr != null && instr.getMinAddress().getUnsignedOffset() <= maxOffs) {
                        if (!func.getBody().contains(instr.getMinAddress())) {
                            continue;
                        }

                        if (instr.getMnemonicString().equalsIgnoreCase("out") && instr.getPcode().length > 0) {
                            PcodeOp op = instr.getPcode()[0];
                            if (rename(vctx, func, op)) {
                                break;
                            }
                        }

                        instr = instr.getNext();
                    }
                }
            }
        } catch (final Exception ex) {
            printerr(ex.getMessage());
            printerr(Arrays.stream(ex.getStackTrace())
                    .map(el -> String.format("    %s", el.toString()))
                    .collect(Collectors.joining("\n")));
        }
    }

    private boolean rename(final VarnodeContext vctx, final Function func, final PcodeOp op) {
        if (op == null || op.getNumInputs() < 3) {
            return false;
        }

        String opMnemonic = op.getMnemonic();
        String opName = null;
        try {
            opName = currentProgram.getLanguage().getUserDefinedOpName((int) op.getInput(0).getOffset());
        } catch (final Exception ex) {
            return false;
        }

        String reNotScalar = "^(\\?|[A-Z]).*";
        if (opMnemonic.equals("CALLOTHER") && opName.equals("out")) {
            String val1 = val(vctx, op.getInput(1));
            String val2 = val(vctx, op.getInput(2));
            if (val1.matches(reNotScalar) || val2.matches(reNotScalar)) {
                return false;
            }

            String originalName = func.getName();
            String assignedName = Names.assign(String.format("w_io_%s_%s", val1, val2));
            try {
                func.setName(assignedName, SourceType.USER_DEFINED);
            } catch (DuplicateNameException | InvalidInputException e) {
                return false;
            }

            println(String.format("%s: %s %s,%s => %s",
                    originalName,
                    opName,
                    val1,
                    val2,
                    assignedName));

            return true;
        }

        return false;
    }

    private Address addr(long offset) {
        return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
    }

    private String val(final VarnodeContext vctx, final Varnode vnode) {
        if (vnode == null) {
            return "?";
        } else if (vnode.isRegister()) {
            final Register reg = vctx.getRegister(vnode);
            return String.format("%s", reg.getName().toUpperCase(Locale.ROOT));
        } else if (vnode.isConstant()) {
            return String.format(vnode.getOffset() > 0xff ? "%04x" : "%02x", vnode.getOffset());
        }
        return "?";
    }

    private static class Names {
        private static long counter = 1;

        static String assign(final String candidate) {
            return String.format("%s_a%d", candidate, counter++);
        }
    }
}
