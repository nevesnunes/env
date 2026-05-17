//Backwards taint tracking for selected instruction
//@author flib
//@category
//@keybinding
//@menupath
//@toolbar

import static ghidra.program.model.pcode.PcodeOp.BOOL_AND;
import static ghidra.program.model.pcode.PcodeOp.BOOL_NEGATE;
import static ghidra.program.model.pcode.PcodeOp.BOOL_OR;
import static ghidra.program.model.pcode.PcodeOp.BOOL_XOR;
import static ghidra.program.model.pcode.PcodeOp.CAST;
import static ghidra.program.model.pcode.PcodeOp.CALLOTHER;
import static ghidra.program.model.pcode.PcodeOp.COPY;
import static ghidra.program.model.pcode.PcodeOp.FLOAT_ABS;
import static ghidra.program.model.pcode.PcodeOp.FLOAT_ADD;
import static ghidra.program.model.pcode.PcodeOp.FLOAT_CEIL;
import static ghidra.program.model.pcode.PcodeOp.FLOAT_DIV;
import static ghidra.program.model.pcode.PcodeOp.FLOAT_FLOOR;
import static ghidra.program.model.pcode.PcodeOp.FLOAT_MULT;
import static ghidra.program.model.pcode.PcodeOp.FLOAT_NAN;
import static ghidra.program.model.pcode.PcodeOp.FLOAT_NEG;
import static ghidra.program.model.pcode.PcodeOp.FLOAT_ROUND;
import static ghidra.program.model.pcode.PcodeOp.FLOAT_SQRT;
import static ghidra.program.model.pcode.PcodeOp.FLOAT_SUB;
import static ghidra.program.model.pcode.PcodeOp.INDIRECT;
import static ghidra.program.model.pcode.PcodeOp.INT_ADD;
import static ghidra.program.model.pcode.PcodeOp.INT_AND;
import static ghidra.program.model.pcode.PcodeOp.INT_CARRY;
import static ghidra.program.model.pcode.PcodeOp.INT_DIV;
import static ghidra.program.model.pcode.PcodeOp.INT_LEFT;
import static ghidra.program.model.pcode.PcodeOp.INT_MULT;
import static ghidra.program.model.pcode.PcodeOp.INT_NEGATE;
import static ghidra.program.model.pcode.PcodeOp.INT_OR;
import static ghidra.program.model.pcode.PcodeOp.INT_REM;
import static ghidra.program.model.pcode.PcodeOp.INT_RIGHT;
import static ghidra.program.model.pcode.PcodeOp.INT_SBORROW;
import static ghidra.program.model.pcode.PcodeOp.INT_SCARRY;
import static ghidra.program.model.pcode.PcodeOp.INT_SDIV;
import static ghidra.program.model.pcode.PcodeOp.INT_SEXT;
import static ghidra.program.model.pcode.PcodeOp.INT_SREM;
import static ghidra.program.model.pcode.PcodeOp.INT_SRIGHT;
import static ghidra.program.model.pcode.PcodeOp.INT_SUB;
import static ghidra.program.model.pcode.PcodeOp.INT_XOR;
import static ghidra.program.model.pcode.PcodeOp.INT_ZEXT;
import static ghidra.program.model.pcode.PcodeOp.LOAD;
import static ghidra.program.model.pcode.PcodeOp.MULTIEQUAL;
import static ghidra.program.model.pcode.PcodeOp.STORE;
import static ghidra.program.model.pcode.PcodeOp.UNIMPLEMENTED;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.SimpleBlockModel;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.util.VarnodeContext;
import ghidra.util.exception.CancelledException;

public class BackTaint extends GhidraScript {
    @Override
    protected void run() throws Exception {
        if (currentProgram == null) {
            printerr("No program loaded.");
            return;
        }

        final AddressSetView addressSetView = currentSelection;
        if (addressSetView == null || addressSetView.isEmpty()) {
            printerr("No address selected.");
            return;
        }
        if (addressSetView.getFirstRange().getLength() > 2) {
            printerr(String.format(
                    "More than one address selected: %08x..%08x.",
                    addressSetView.getMinAddress().getUnsignedOffset(),
                    addressSetView.getMaxAddress().getUnsignedOffset()));
            return;
        }

        final VarnodeContext vctx = new VarnodeContext(
                currentProgram,
                currentProgram.getProgramContext(),
                currentProgram.getProgramContext(),
                true);

        final CodeBlockIterator bbIt = new SimpleBlockModel(currentProgram)
                .getCodeBlocksContaining(addressSetView, monitor);
        if (bbIt.hasNext()) {
            final CodeBlock bb = bbIt.next();
            if (bbIt.hasNext()) {
                printerr("More than one code block in selected address.");
                return;
            }

            handleCodeBlock(vctx, bb);
        }
    }

    private void handleCodeBlock(final VarnodeContext vctx, final CodeBlock bb)
            throws CancelledException {
        final Deque<Instruction> backInstructions = new ArrayDeque<>();
        final InstructionIterator instructionIt = currentProgram.getListing()
                .getInstructions(bb, true);
        while (instructionIt.hasNext()) {
            monitor.checkCancelled();
            final Instruction instr = instructionIt.next();
            if (instr.getAddress().getUnsignedOffset() <= currentAddress.getUnsignedOffset()) {
                backInstructions.push(instr);
            }
        }

        Varnode sinkVnode = null;
        Address sinkAddr = null;
        final Map<Varnode, Address> taintedVnodes = new HashMap<>();
        if (backInstructions.isEmpty()) {
            printerr(String.format(
                    "Empty code block @ %08x.",
                    currentAddress.getUnsignedOffset()));
            return;
        }
        final Map<Address, Set<Address>> taintedMemoryReads = new HashMap<>();
        final Map<Address, Set<Address>> taintedMemoryWrites = new HashMap<>();
        final Set<Address> nextBBs = new HashSet<>();

        boolean isFirstPcodeOp = true;
        while (!backInstructions.isEmpty()) {
            final Instruction instr = backInstructions.pop();
            println(String.format(
                    "%08x instr: %s",
                    instr.getAddress().getUnsignedOffset(),
                    instr));

            final ReferenceIterator refIt = instr.getReferenceIteratorTo();
            while (refIt.hasNext()) {
                final Reference ref = refIt.next();
                if (ref.isMemoryReference()) {
                    nextBBs.add(ref.getFromAddress());
                }
            }

            // Clear temporary variables from previous pcodeOps.
            taintedVnodes.keySet().stream()
                    .filter(vnode -> vnode.isUnique())
                    .forEach(taintedVnodes::remove);

            for (final PcodeOp pcodeOp : instr.getPcode()) {
                log(vctx, pcodeOp);

                final Varnode dst = out(pcodeOp);
                if (isFirstPcodeOp) {
                    for (final Varnode vnode : pcodeOp.getInputs()) {
                        println(String.format("........ + %s", fmt(vctx, vnode)));
                        taintedVnodes.put(vnode, instr.getAddress());
                    }
                    sinkVnode = dst;
                    sinkAddr = instr.getAddress();
                    isFirstPcodeOp = false;
                    continue;
                }

                if (taintedVnodes.isEmpty()) {
                    printerr("No more tainted vnodes while iterating code block.");
                    return;
                }

                // TODO: Model stack for push/pop macros used as function prologue/epilogue.
                switch (pcodeOp.getOpcode()) {
                    case LOAD:
                        // TODO: Resolve segmented reg/mem values from ctx?
                        if (pcodeOp.getNumInputs() == 2 && pcodeOp.getInput(1).isAddress()) {
                            taintedMemoryReads.computeIfAbsent(
                                    dst.getAddress(),
                                    k -> new HashSet<>());
                            taintedMemoryReads.get(pcodeOp.getInput(1).getAddress())
                                    .add(instr.getAddress());
                        }
                        taint(vctx, taintedVnodes, instr, pcodeOp, dst);
                        break;
                    case STORE:
                        if (taintedVnodes.containsKey(dst) && dst.isAddress()) {
                            taintedMemoryWrites.computeIfAbsent(
                                    dst.getAddress(),
                                    k -> new HashSet<>());
                            taintedMemoryWrites.get(dst.getAddress())
                                    .add(instr.getAddress());
                        }
                        taint(vctx, taintedVnodes, instr, pcodeOp, dst);
                        break;
                    case CALLOTHER:
                        // Assume userops unconditionally read all inputs.
                        // TODO: Process hooks from .pspec files, keyed by language id.
                        taint(vctx, taintedVnodes, instr, pcodeOp, dst);
                        break;
                    case CAST, COPY, INDIRECT, MULTIEQUAL,
                            BOOL_AND, BOOL_NEGATE, BOOL_OR, BOOL_XOR,
                            FLOAT_ABS, FLOAT_ADD, FLOAT_CEIL, FLOAT_DIV,
                            FLOAT_FLOOR, FLOAT_MULT, FLOAT_NAN, FLOAT_NEG,
                            FLOAT_ROUND, FLOAT_SQRT, FLOAT_SUB,
                            INT_ADD, INT_AND, INT_CARRY, INT_DIV,
                            INT_LEFT, INT_MULT, INT_NEGATE, INT_OR,
                            INT_REM, INT_RIGHT, INT_SBORROW, INT_SCARRY,
                            INT_SDIV, INT_SEXT, INT_SREM, INT_SRIGHT,
                            INT_SUB, INT_XOR, INT_ZEXT:
                        taint(vctx, taintedVnodes, instr, pcodeOp, dst);
                        break;
                    case UNIMPLEMENTED:
                        printerr(String.format(
                                "Unimplemented opcode: %s.",
                                PcodeOp.getMnemonic(pcodeOp.getOpcode())));
                        break;
                    default:
                        printerr(String.format(
                                "Unhandled opcode: %s.",
                                PcodeOp.getMnemonic(pcodeOp.getOpcode())));
                        return;
                }
            }
        }

        if (backInstructions.isEmpty() && nextBBs.isEmpty()) {
            // TODO: prev instr is CALL?
        }

        println(String.format(
                "Sources contributing to sink '%s' @ %08x:",
                fmt(vctx, sinkVnode),
                sinkAddr.getUnsignedOffset()));
        taintedVnodes.forEach((vnode, addr) -> {
            println(String.format(
                    "< %s @ %08x",
                    fmt(vctx, vnode),
                    addr.getUnsignedOffset()));
        });

        println(String.format(
                "Mem R=[%s] W=[%s]",
                taintedMemoryReads.entrySet().stream()
                        .map(entry -> String.format("%08x @ %s",
                                entry.getKey().getUnsignedOffset(),
                                entry.getValue().stream()
                                        .map(addr -> String.format("%08x",
                                                addr.getUnsignedOffset()))
                                        .collect(Collectors.joining(","))))
                        .collect(Collectors.joining(",")),
                taintedMemoryWrites.entrySet().stream()
                        .map(entry -> String.format("%08x @ %s",
                                entry.getKey().getUnsignedOffset(),
                                entry.getValue().stream()
                                        .map(addr -> String.format("%08x",
                                                addr.getUnsignedOffset()))
                                        .collect(Collectors.joining(","))))
                        .collect(Collectors.joining(","))));
        println(String.format(
                "Next bb addresses: %s",
                nextBBs.stream()
                        .map(addr -> String.format("%08x", addr.getUnsignedOffset()))
                        .collect(Collectors.joining(","))));
    }

    private void taint(final VarnodeContext vctx,
            final Map<Varnode, Address> taintedVnodes,
            final Instruction instr,
            final PcodeOp pcodeOp,
            final Varnode dst) {
        if (taintedVnodes.containsKey(dst)) {
            taintedVnodes.remove(dst);
            println(String.format("........ - %s", fmt(vctx, dst)));

            for (final Varnode src : pcodeOp.getInputs()) {
                if (!src.isConstant()) {
                    taintedVnodes.put(src, instr.getAddress());
                    println(String.format("........ + %s", fmt(vctx, src)));
                }
            }
        }
    }

    private Address addr(final long offset) {
        return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
    }

    private Varnode out(final PcodeOp pcodeOp) {
        if (pcodeOp.getOpcode() == STORE) {
            return pcodeOp.getInput(1);
        }
        return pcodeOp.getOutput();
    }

    private void log(final VarnodeContext vctx, final PcodeOp pcodeOp) {
        println(String.format("........ pcode: %s", pcodeOp));
        for (final Varnode vnode : pcodeOp.getInputs()) {
            println(String.format("........ < %s", fmt(vctx, vnode)));
        }
        println(String.format("........ > %s", fmt(vctx, out(pcodeOp))));
    }

    private String fmt(final VarnodeContext vctx, Varnode vnode) {
        if (vnode == null) {
            return "null";
        } else if (vnode.isRegister()) {
            final Register reg = vctx.getRegister(vnode);
            return String.format("reg=%s", reg.getName());
        } else if (vnode.isAddress()) {
            return String.format(
                    "addr=%08x (%s)",
                    vnode.getAddress().getUnsignedOffset(),
                    getDataContaining(vnode.getAddress()));
        } else if (vnode.isConstant()) {
            return String.format("const=%08x", vnode.getOffset());
        } else if (vnode.isUnique()) {
            return String.format("uniq=%08x", vnode.getOffset());
        }
        return vnode.toString();
    }
}
