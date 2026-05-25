//Make function parameters from input registers. 
//@author flib
//@category
//@keybinding 
//@menupath 
//@toolbar 

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import ghidra.app.cmd.function.UpdateFunctionCommand;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.block.SimpleBlockModel;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.QWordDataType;
import ghidra.program.model.data.UnsignedInteger3DataType;
import ghidra.program.model.data.UnsignedInteger5DataType;
import ghidra.program.model.data.UnsignedInteger6DataType;
import ghidra.program.model.data.UnsignedInteger7DataType;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.ContextEvaluator;
import ghidra.program.util.ContextEvaluatorAdapter;
import ghidra.program.util.SymbolicPropogator;
import ghidra.program.util.VarnodeContext;
import ghidra.util.exception.InvalidInputException;

public class MakeFuncParams extends GhidraScript {

    final Map<String, Set<String>> ignoredRegs = Map.of(
            "x86",
            Set.of("CS", "DS", "ES", "FS", "GS", "SS"));

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
        final var currentFunc = lst.getFunctionContaining(currentAddress);
        if (currentFunc == null) {
            printerr("No function defined for selected address.");
            return;
        }

        final Map<Address, Set<Address>> srcToDstAddrs = new HashMap<>();
        final var funcAddrSet = addressSetWithCallees(currentFunc,
                currentFunc.getBody().getMinAddress(),
                currentFunc.getBody().getMaxAddress());
        final var bbModel = new SimpleBlockModel(currentProgram);
        final var bbIt = bbModel.getCodeBlocksContaining(funcAddrSet, monitor);
        while (bbIt.hasNext()) {
            final var bbBlock = bbIt.next();
            final var bbDestRefIt = bbBlock.getDestinations(monitor);
            while (bbDestRefIt.hasNext()) {
                final var bbRef = bbDestRefIt.next();
                final var src = bbRef.getReferent();
                final var dst = bbRef.getReference();
                srcToDstAddrs.computeIfAbsent(src, ignoredKey -> new HashSet<>());
                srcToDstAddrs.get(src).add(dst);
                println(String.format("@ (%06x..%06x) %06x -> %06x",
                        bbBlock.getMinAddress().getUnsignedOffset(),
                        bbBlock.getMaxAddress().getUnsignedOffset(),
                        src.getUnsignedOffset(),
                        dst.getUnsignedOffset()));
            }
        }

        final Map<Address, Integer> writtenBeforeReads = new HashMap<>();
        final Map<Address, Integer> readBeforeWrites = new HashMap<>();
        final Map<Address, Map<Address, Integer>> nextDstToWrittenRegs = new HashMap<>();
        final ContextEvaluator eval = new ContextEvaluatorAdapter() {
            @Override
            public boolean evaluateContextBefore(VarnodeContext context, Instruction instr) {
                srcToDstAddrs.computeIfPresent(instr.getAddress(), (k, v) -> {
                    v.forEach(dst -> nextDstToWrittenRegs.put(dst, new HashMap<>(writtenBeforeReads)));
                    return v;
                });
                nextDstToWrittenRegs.computeIfPresent(instr.getAddress(), (k, v) -> {
                    writtenBeforeReads.clear();
                    writtenBeforeReads.putAll(v);
                    return v;
                });

                for (PcodeOp op : instr.getPcode()) {
                    for (Varnode in : op.getInputs()) {
                        if (in.isRegister()) {
                            final var inReg = context.getRegister(in);
                            if (isIgnored(inReg)) {
                                continue;
                            }

                            if (isReadBeforeWrites(writtenBeforeReads, inReg, in.getSize())) {
                                println(String.format("@ %06x (%s) => %s",
                                        instr.getAddress().getUnsignedOffset(),
                                        op.toString(),
                                        inReg.getName()));
                                readBeforeWrites.compute(inReg.getAddress(), (k, v) -> {
                                    final var newSize = in.getSize();
                                    return (v == null || v < newSize)
                                            ? newSize
                                            : v;
                                });
                            }
                        }
                    }

                    final var out = op.getOutput();
                    if (out != null && out.isRegister()) {
                        writtenBeforeReads.put(out.getAddress(), out.getSize());
                    }
                }

                return super.evaluateContextBefore(context, instr);
            }
        };
        SymbolicPropogator symEval = new SymbolicPropogator(currentProgram, true);
        symEval.flowConstants(currentFunc.getEntryPoint(),
                funcAddrSet,
                eval,
                true,
                getMonitor());

        final VarnodeContext vctx = new VarnodeContext(
                currentProgram,
                currentProgram.getProgramContext(),
                currentProgram.getProgramContext(),
                true);
        println(readBeforeWrites.keySet().stream()
                .map(addr -> vctx.getRegister(new Varnode(addr, readBeforeWrites.get(addr))).getName())
                .collect(Collectors.joining(",")));

        // TODO:
        // ~/opt/ghidra.git/Ghidra/Features/Base/src/main/java/ghidra/app/cmd/function/NewFunctionStackAnalysisCmd.java
        // ~/opt/ghidra.git/Ghidra/Features/Base/ghidra_scripts/MakeStackRefs.java

        Variable retVar = null;
        final List<ParameterImpl> params = new ArrayList<>();
        readBeforeWrites.entrySet().stream().forEach(entry -> {
            try {
                final var reg = vctx.getRegister(new Varnode(entry.getKey(), entry.getValue()));
                final var param = new ParameterImpl(null, toDataRef(entry.getValue()), reg, currentProgram);
                params.add(param);
            } catch (final InvalidInputException ex) {
                throw new RuntimeException(ex);
            }
        });
        final var cmd = new UpdateFunctionCommand(currentFunc,
                FunctionUpdateType.CUSTOM_STORAGE,
                null,
                retVar,
                params,
                SourceType.USER_DEFINED,
                true);
        cmd.applyTo(currentProgram);
    }

    private DataType toDataRef(Integer value) {
        return switch (value) {
            case 1 -> ByteDataType.dataType;
            case 2 -> WordDataType.dataType;
            case 3 -> UnsignedInteger3DataType.dataType;
            case 4 -> DWordDataType.dataType;
            case 5 -> UnsignedInteger5DataType.dataType;
            case 6 -> UnsignedInteger6DataType.dataType;
            case 7 -> UnsignedInteger7DataType.dataType;
            case 8 -> QWordDataType.dataType;
            default -> PointerDataType.dataType;
        };
    }

    private boolean isReadBeforeWrites(final Map<Address, Integer> writtenBeforeReads,
                                       final Register inReg,
                                       final int size) {
        final var addr = inReg.getAddress();
        if (writtenBeforeReads.containsKey(addr)) {
            var storedSize = writtenBeforeReads.get(addr);
            if (storedSize <= size) {
                return false;
            }
            int targetSize = storedSize - size;
            while (targetSize > 0) {
                final var targetAddr = inReg.getAddress().add(size);
                if (writtenBeforeReads.containsKey(targetAddr)) {
                    final var targetStoredSize = writtenBeforeReads.get(targetAddr);
                    if (targetSize >= targetStoredSize) {
                        targetSize -= targetStoredSize;
                    }
                } else {
                    return true;
                }
            }
            return false;
        }
        return true;
    }

    private boolean isIgnored(final Register inReg) {
        final String isa = currentProgram.getLanguageID().getIdAsString().split(":")[0].toLowerCase();
        if (ignoredRegs.getOrDefault(isa, Collections.emptySet()).contains(inReg.getName())) {
            return true;
        }
        return inReg == currentProgram.getCompilerSpec().getStackPointer()
                || inReg == currentProgram.getLanguage().getProgramCounter()
                || inReg.isDefaultFramePointer()
                || inReg.isHidden()
                || inReg.isProcessorContext()
                || inReg.isZero();
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
