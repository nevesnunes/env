//Make memory references from register values inferred in caller functions. 
//@author flib
//@category
//@keybinding 
//@menupath 
//@toolbar 

import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import ghidra.app.plugin.core.analysis.ConstantPropagationContextEvaluator;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.ContextEvaluator;
import ghidra.program.util.SymbolicPropogator;
import ghidra.program.util.VarnodeContext;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;

public class MakeUnaffRegMemRefsRecur extends GhidraScript {

    /**
     * Resolve callers up to this maximum depth of nesting.
     */
    final private static int MAX_DEPTH = 1;

    /**
     * Function call referenced addresses, from caller to set of callees.
     */
    final private Map<Address, Set<Address>> edges = new HashMap<>();

    /**
     * Function callee addresses to be traversed.
     */
    final private Set<Address> seenCalleeAddrs = new HashSet<>();

    /**
     * Function data types as set before traversal.
     */
    final private Map<Address, DataType> originalFuncDataTypes = new HashMap<>();

    Listing lst;
    ReferenceManager refMgr;

    @Override
    public void run() throws Exception {
        lst = currentProgram.getListing();
        refMgr = currentProgram.getReferenceManager();

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

        final Set<Address> roots = populateEdges(currentFunc);

        final Map<Address, Set<Set<RegisterValue>>> cachedRegVals = new HashMap<>();
        final Deque<Address> q = new ArrayDeque<>();
        roots.forEach(q::push);
        while (!q.isEmpty()) {
            final var refAddr = q.pop();
            final var refFunc = lst.getFunctionContaining(refAddr);
            final var startAddr = refFunc.getBody().getMinAddress();
            final boolean isLastAddr = startAddr.getUnsignedOffset() == currentFunc
                    .getBody().getMinAddress().getUnsignedOffset();
            final var endAddr = isLastAddr
                    ? refFunc.getBody().getMaxAddress()
                    : refAddr;
            final var startRegVals = cachedRegVals.getOrDefault(refAddr, Set.of(Set.of()));
            for (var startFlowRegVals : startRegVals) {
                if (isLastAddr) {
                    println(String.format("Resolved @ %06x => %s", startAddr.getUnsignedOffset(), startFlowRegVals));
                }

                final var regVals = resolveRegs(refFunc, startAddr, endAddr, startFlowRegVals);
                edges.computeIfPresent(refAddr, (k, v) -> {
                    v.forEach(x -> {
                        cachedRegVals.computeIfAbsent(x, ignoredKey -> new HashSet<>());
                        cachedRegVals.get(x).addAll(regVals);
                    });
                    return v;
                });
            }

            edges.computeIfPresent(refAddr, (k, v) -> {
                v.forEach(q::push);
                return v;
            });
        }
    }

    private Set<Address> populateEdges(final Function func) {
        final Set<Address> roots = new HashSet<>();
        Deque<Address> q = new ArrayDeque<>();
        q.push(func.getBody().getMinAddress());
        int i = 0;
        while (i++ < MAX_DEPTH) {
            roots.clear();
            final Deque<Address> qNext = new ArrayDeque<>();
            while (!q.isEmpty()) {
                final Address addr = q.pop();
                for (Reference ref : refMgr.getReferencesTo(addr)) {
                    final Instruction refInstr = lst.getInstructionAt(ref.getFromAddress());
                    if (refInstr == null || !refInstr.getFlowType().isCall()) {
                        continue;
                    }
                    println(String.format("#%d @ %06x -(called-at)-> %06x",
                            i,
                            addr.getUnsignedOffset(),
                            ref.getFromAddress().getUnsignedOffset(),
                            refInstr.getFlowType().getName()));

                    final var refFunc = lst.getFunctionContaining(ref.getFromAddress());
                    if (refFunc == null) {
                        continue;
                    }

                    edges.computeIfAbsent(refInstr.getAddress(), ignoredKey -> new HashSet<>());
                    edges.get(refInstr.getAddress()).add(addr);
                    seenCalleeAddrs.add(refInstr.getAddress());
                    roots.add(refInstr.getAddress());
                    qNext.push(refFunc.getBody().getMinAddress());
                }
            }
            q = qNext;
        }

        return roots;
    }

    private Set<Set<RegisterValue>> resolveRegs(final Function func,
                                                final Address startAddr,
                                                final Address endAddr,
                                                final Set<RegisterValue> startRegVals) throws CancelledException {
        final Set<Set<RegisterValue>> endRegVals = new HashSet<>();
        final ContextEvaluator eval = new ConstantPropagationContextEvaluator(monitor, true) {
            @Override
            public boolean evaluateContextBefore(VarnodeContext context, Instruction instr) {
                if (instr.getAddress().getUnsignedOffset() == startAddr.getUnsignedOffset()) {
                    for (RegisterValue regVal : startRegVals) {
                        context.setRegisterValue(regVal);
                    }
                }

                if (!seenCalleeAddrs.contains(instr.getAddress()) && instr.getFlowType().isCall()) {
                    // SymbolicPropagator only follows call flow for inline functions.
                    final Function callee = Arrays.stream(instr.getReferencesFrom())
                            .filter(ref -> ref.getReferenceType().isCall())
                            .map(ref -> lst.getFunctionAt(ref.getToAddress()))
                            .findFirst()
                            .orElseThrow();
                    if (!callee.isInline()) {
                        originalFuncDataTypes.put(callee.getBody().getMinAddress(), callee.getReturnType());
                        try {
                            callee.setInline(true);
                            callee.setReturnType(VoidDataType.dataType, SourceType.USER_DEFINED);
                        } catch (final InvalidInputException ex) {
                            printerr(ex.getMessage());
                        }
                    }
                }

                return super.evaluateContextBefore(context, instr);
            }

            @Override
            public boolean evaluateContext(VarnodeContext context, Instruction instr) {
                if (instr.getAddress().getUnsignedOffset() == endAddr.getUnsignedOffset()) {
                    final Set<RegisterValue> flowRegVals = regVals(context);
                    endRegVals.add(flowRegVals);
                }

                return super.evaluateContext(context, instr);
            }

            private Set<RegisterValue> regVals(VarnodeContext context) {
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

                return flowRegVals;
            }
        };
        SymbolicPropogator symEval = new SymbolicPropogator(currentProgram, true);
        symEval.flowConstants(func.getEntryPoint(),
                addressSetWithCallees(func, startAddr, endAddr),
                eval,
                true,
                getMonitor());

        originalFuncDataTypes.forEach((addr, dataType) -> {
            final Function callee = lst.getFunctionAt(addr);
            try {
                callee.setInline(false);
                callee.setReturnType(dataType, SourceType.USER_DEFINED);
            } catch (final InvalidInputException ex) {
                printerr(ex.getMessage());
            }
        });

        return endRegVals;
    }

    private AddressSet addressSetWithCallees(final Function func,
                                             final Address startAddr,
                                             final Address endAddr) {
        final AddressSet addrSet = new AddressSet(startAddr, endAddr);

        final Set<Address> seenAddrs = new HashSet<>();
        final Deque<Function> q = new ArrayDeque<>();
        func.getCalledFunctions(getMonitor()).forEach(q::push);
        while (!q.isEmpty()) {
            final Function callee = q.pop();
            if (seenAddrs.contains(callee.getBody().getMinAddress())) {
                continue;
            }
            seenAddrs.add(callee.getBody().getMinAddress());

            addrSet.addRange(callee.getBody().getMinAddress(), callee.getBody().getMaxAddress());
            callee.getCalledFunctions(getMonitor()).forEach(q::push);
        }

        return addrSet;
    }
}
