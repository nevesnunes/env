//Make memory references from register values inferred in caller functions. 
//@author flib
//@category
//@keybinding 
//@menupath 
//@toolbar 

import java.util.HashSet;
import java.util.Set;

import ghidra.app.plugin.core.analysis.ConstantPropagationContextEvaluator;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Reference;
import ghidra.program.util.ContextEvaluator;
import ghidra.program.util.SymbolicPropogator;
import ghidra.program.util.VarnodeContext;
import ghidra.util.exception.CancelledException;

public class MakeUnaffRegMemRefs extends GhidraScript {

    public void run() throws Exception {
        final var lst = currentProgram.getListing();
        final var refMgr = currentProgram.getReferenceManager();

        if (currentProgram == null) {
            printerr("No program loaded.");
            return;
        }
        if (currentAddress == null) {
            printerr("No address selected.");
            return;
        }
        final Function currentFunc = lst.getFunctionContaining(currentAddress);
        if (currentFunc == null) {
            printerr("No function defined for selected address.");
            return;
        }

        final Address startAddr = currentFunc.getBody().getMinAddress();
        final Address endAddr = currentFunc.getBody().getMaxAddress();
        for (Reference ref : refMgr.getReferencesTo(startAddr)) {
            final Instruction refInstr = lst.getInstructionAt(ref.getFromAddress());
            if (refInstr == null || !refInstr.getFlowType().isCall()) {
                continue;
            }
            println(String.format("@ %06x -(called-at)-> %06x",
                    startAddr.getUnsignedOffset(),
                    ref.getFromAddress().getUnsignedOffset(),
                    refInstr.getFlowType().getName()));

            final var refFunc = lst.getFunctionContaining(ref.getFromAddress());
            final var regVals = resolveRegs(refFunc, refFunc.getBody().getMinAddress(), ref.getFromAddress(), Set.of());
            println(regVals.toString());

            for (Set<RegisterValue> flowRegVals : regVals) {
                resolveRegs(currentFunc, startAddr, endAddr, flowRegVals);
            }
        }
    }

    private Set<Set<RegisterValue>> resolveRegs(final Function func,
                                                final Address startAddr,
                                                final Address endAddr,
                                                final Set<RegisterValue> startRegVals) throws CancelledException {
        final Set<Set<RegisterValue>> regVals = new HashSet<>();
        final ContextEvaluator eval = new ConstantPropagationContextEvaluator(monitor, true) {
            @Override
            public boolean evaluateContextBefore(VarnodeContext context, Instruction instr) {
                if (instr.getAddress().getUnsignedOffset() == startAddr.getUnsignedOffset()) {
                    for (RegisterValue regVal : startRegVals) {
                        context.setRegisterValue(regVal);
                    }
                }

                return super.evaluateContextBefore(context, instr);
            }

            @Override
            public boolean evaluateContext(VarnodeContext context, Instruction instr) {
                if (instr.getAddress().getUnsignedOffset() == endAddr.getUnsignedOffset()) {
                    final Set<RegisterValue> flowRegVals = new HashSet<>();
                    for (String regName : currentProgram.getLanguage().getRegisterNames()) {
                        final Register reg = currentProgram.getLanguage().getRegister(regName);
                        if (reg.isProcessorContext()) {
                            continue;
                        }

                        final RegisterValue regVal = context.getRegisterValue(reg);
                        if (regVal == null || regVal.getUnsignedValue() == null) {
                            continue;
                        }

                        flowRegVals.add(regVal);
                    }
                    regVals.add(flowRegVals);
                }

                return super.evaluateContext(context, instr);
            }
        };
        SymbolicPropogator symEval = new SymbolicPropogator(currentProgram, true);
        symEval.flowConstants(func.getEntryPoint(), new AddressSet(startAddr, endAddr), eval, true, getMonitor());

        return regVals;
    }
}
