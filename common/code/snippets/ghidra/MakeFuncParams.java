//Make function parameters from input registers. 
//@author flib
//@category
//@keybinding 
//@menupath 
//@toolbar 

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
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
import ghidra.program.model.lang.Language;
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

    private static final int PATTERN_REG = 0;
    private static final int PATTERN_REG_SP = 1;

    private static final Map<String, Set<String>> IGNORED_REGS = Map.of(
            "x86",
            Set.of("CS", "DS", "ES", "FS", "GS", "SS"));
    private static final Map<String, Map<String, List<PatternElement>>> PATTERNS = Map.of(
            "x86:16",
            Map.of("push",
                    List.of(
                            PatternElement.builder().opcode(PcodeOp.COPY).in(PATTERN_REG).build(),
                            PatternElement.builder().opcode(PcodeOp.INT_SUB).in(PATTERN_REG_SP).build(),
                            PatternElement.builder().opcode(PcodeOp.CALLOTHER).build(),
                            PatternElement.builder().opcode(PcodeOp.STORE).build())));

    Language lang;
    Listing lst;
    ReferenceManager refMgr;

    @Override
    public void run() throws Exception {
        lang = currentProgram.getLanguage();
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

        final Set<Address> terminalAddrs = new HashSet<>();
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

            final var instrIr = lst.getInstructions(bbBlock, true);
            while (instrIr.hasNext()) {
                final var instr = instrIr.next();
                if (Arrays.stream(instr.getPcode())
                        .anyMatch(pcode -> pcode.getOpcode() == PcodeOp.RETURN)) {
                    terminalAddrs.add(instr.getAddress());
                }
            }
        }
        print(terminalAddrs.toString());

        final Map<Address, Integer> writtenBeforeReads = new HashMap<>();
        final Map<Address, Integer> readBeforeWrites = new HashMap<>();
        final Map<Address, Map<Address, Integer>> nextDstToWrittenRegs = new HashMap<>();
        final ContextEvaluator eval = new ContextEvaluatorAdapter() {
            @Override
            public boolean evaluateContextBefore(VarnodeContext context, Instruction instr) {
                nextDstToWrittenRegs.computeIfPresent(instr.getAddress(), (k, v) -> {
                    writtenBeforeReads.clear();
                    writtenBeforeReads.putAll(v);
                    println(String.format("@ %06x <= [%s]",
                            instr.getAddress().getUnsignedOffset(),
                            writtenBeforeReads.keySet().stream()
                                    .map(addr -> context
                                            .getRegister(new Varnode(addr, writtenBeforeReads.get(addr)))
                                            .getName())
                                    .collect(Collectors.joining(","))));
                    return v;
                });

                final boolean isStackPush = isStackPush(instr);
                for (PcodeOp op : instr.getPcode()) {
                    for (Varnode in : op.getInputs()) {
                        if (in.isRegister()) {
                            final var inReg = context.getRegister(in);
                            if (isStackPush || isIgnored(inReg)) {
                                continue;
                            }

                            if (isReadBeforeWrites(writtenBeforeReads, inReg, in.getSize())) {
                                println(String.format("@ %06x [%s] => %s [%s]",
                                        instr.getAddress().getUnsignedOffset(),
                                        op.toString(),
                                        inReg.getName(),
                                        writtenBeforeReads.keySet().stream()
                                                .map(addr -> context
                                                        .getRegister(new Varnode(addr, writtenBeforeReads.get(addr)))
                                                        .getName())
                                                .collect(Collectors.joining(","))));
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

                srcToDstAddrs.computeIfPresent(instr.getAddress(), (k, v) -> {
                    v.forEach(dst -> nextDstToWrittenRegs.put(dst, new HashMap<>(writtenBeforeReads)));
                    return v;
                });

                return super.evaluateContextBefore(context, instr);
            }
        };
        SymbolicPropogator symEval = new SymbolicPropogator(currentProgram, true);
        symEval.flowConstants(currentFunc.getEntryPoint(),
                funcAddrSet,
                eval,
                true,
                getMonitor());

        println(String.format("R-b4-W: [%s]",
                readBeforeWrites.keySet().stream()
                        .map(addr -> lang.getRegister(addr, readBeforeWrites.get(addr)).getName())
                        .collect(Collectors.joining(", "))));

        // TODO:
        // ~/opt/ghidra.git/Ghidra/Features/Base/src/main/java/ghidra/app/cmd/function/NewFunctionStackAnalysisCmd.java
        // ~/opt/ghidra.git/Ghidra/Features/Base/ghidra_scripts/MakeStackRefs.java

        final var mergedReadBeforeWrites = mergeRegs(readBeforeWrites);
        println(String.format("Merged: %s", mergedReadBeforeWrites));

        Variable retVar = null;
        final List<ParameterImpl> params = new ArrayList<>();
        for (Register reg : mergedReadBeforeWrites) {
            try {
                final var name = String.format("p_%s", reg.getName().toUpperCase());
                final var param = new ParameterImpl(name, toDataRef(reg.getNumBytes()), reg, currentProgram);
                params.add(param);
            } catch (final InvalidInputException ex) {
                throw new RuntimeException(ex);
            }
        }
        final var cmd = new UpdateFunctionCommand(currentFunc,
                FunctionUpdateType.CUSTOM_STORAGE,
                null,
                retVar,
                params,
                SourceType.USER_DEFINED,
                true);
        cmd.applyTo(currentProgram);
    }

    private Set<Register> mergeRegs(Map<Address, Integer> readBeforeWrites) {
        final var sorted = new TreeMap<>(new Comparator<Address>() {
            @Override
            public int compare(Address a1, Address a2) {
                return (int) (a1.getUnsignedOffset() - a2.getUnsignedOffset());
            }
        });
        sorted.putAll(readBeforeWrites);

        final var merged = new TreeSet<>(new Comparator<Register>() {
            @Override
            public int compare(Register r1, Register r2) {
                final var addrDiff = (int) (r1.getAddress().getUnsignedOffset() - r2.getAddress().getUnsignedOffset());
                if (addrDiff == 0) {
                    return r1.getNumBytes() - r2.getNumBytes();
                }
                return addrDiff;
            }
        });
        Register r1 = null;
        for (final var entry : sorted.entrySet()) {
            final var addr = entry.getKey();
            final var size = (int) entry.getValue();
            final var r2 = lang.getRegister(addr, size);
            if (r1 == null) {
                r1 = r2;
                continue;
            } else if (r1.getAddress().add(r1.getNumBytes()).equals(r2.getAddress())) {
                final var r12 = lang.getRegister(r1.getAddress(), r1.getNumBytes() + size);
                if (r12 != null) {
                    r1 = r12;
                } else {
                    merged.add(r1);
                    r1 = r2;
                }
            } else {
                merged.add(r1);
                r1 = r2;
            }
            if (r1 != null) {
                merged.add(r1);
                r1 = null;
            }
        }
        if (r1 != null) {
            merged.add(r1);
        }

        return merged;
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

    private Map<String, List<PatternElement>> patternMap() {
        final var proc = lang.getLanguageDescription().getProcessor().toString().toLowerCase();
        final var size = lang.getLanguageDescription().getSize();
        final var isa = String.format("%s:%d", proc, size);
        final var patternMap = PATTERNS.get(isa);
        if (patternMap == null) {
            throw new RuntimeException(String.format("TODO: Pattern for '%s'", isa));
        }
        return patternMap;
    }

    private boolean isStackPush(final Instruction instr) {
        return isPattern(instr, patternMap().get("push"));
    }

    private boolean isPattern(final Instruction instr, final List<PatternElement> pattern) {
        final var pcode = instr.getPcode();
        final var pcodeLen = pcode.length;
        if (pcodeLen < pattern.size()) {
            return false;
        }

        for (int i = 0; i < pcode.length; i++) {
            if (pcode[i].getOpcode() != pattern.get(i).opcode()) {
                return false;
            }

            if (pcode[i].getNumInputs() < pattern.get(i).in().size()) {
                return false;
            }
            for (int j = 0; j < pattern.get(i).in().size(); j++) {
                final var inPattern = pattern.get(i).in().get(j);
                final var in = pcode[i].getInput(j);
                switch (inPattern) {
                    case PATTERN_REG:
                        if (!in.isRegister()) {
                            return false;
                        }
                        break;
                    case PATTERN_REG_SP:
                        final var sp = currentProgram.getCompilerSpec().getStackPointer();
                        if (!in.isRegister() || !in.getAddress().equals(sp.getAddress())) {
                            return false;
                        }
                        break;
                }
            }
        }

        return true;
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
                    targetSize -= writtenBeforeReads.get(targetAddr);
                } else {
                    return true;
                }
            }
            return false;
        }
        return true;
    }

    private boolean isIgnored(final Register inReg) {
        final String proc = lang.getLanguageDescription().getProcessor().toString().toLowerCase();
        if (IGNORED_REGS.getOrDefault(proc, Collections.emptySet()).contains(inReg.getName())) {
            return true;
        }
        return inReg == currentProgram.getCompilerSpec().getStackPointer()
                || inReg == lang.getProgramCounter()
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

    private record PatternElement(int opcode, List<Integer> in) {
        public static Builder builder() {
            return new Builder();
        }

        public static class Builder {
            private int opcode = -1;
            private List<Integer> in = new ArrayList<>();

            public Builder opcode(int opcode) {
                this.opcode = opcode;
                return this;
            }

            public Builder in(int in) {
                this.in.add(in);
                return this;
            }

            public PatternElement build() {
                return new PatternElement(opcode, in);
            }
        }
    }
}
