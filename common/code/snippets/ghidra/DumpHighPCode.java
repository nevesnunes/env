//Dump High P-Code for a given function
//@author flib
//@category
//@keybinding
//@menupath
//@toolbar

import java.util.Arrays;
import java.util.Comparator;
import java.util.PriorityQueue;
import java.util.Set;
import java.util.stream.Collectors;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.SequenceNumber;
import ghidra.program.model.pcode.Varnode;

public class DumpHighPCode extends GhidraScript {
    @Override
    protected void run() throws Exception {
        Address funcAddr = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(0);
        Function func = currentProgram.getListing().getFunctionAt(funcAddr);

        Set.of("firstpass", "decompile").forEach(action -> {
            println(String.format("=== %s", action));

            var dec = new DecompInterface();
            dec.setOptions(new DecompileOptions());
            dec.setSimplificationStyle(action);
            dec.openProgram(currentProgram);

            var decFuncRes = dec.decompileFunction(func, 10, monitor);
            var highFunc = decFuncRes.getHighFunction();
            if (highFunc != null) {
                var sorted = new PriorityQueue<>(new Comparator<PcodeOp>() {
                    @Override
                    public int compare(PcodeOp o1, PcodeOp o2) {
                        int addrDiff = (int) (o1.getSeqnum().getTarget().getUnsignedOffset()
                                - o2.getSeqnum().getTarget().getUnsignedOffset());
                        return addrDiff == 0
                                ? o1.getSeqnum().getOrder() - o2.getSeqnum().getOrder()
                                : addrDiff;
                    }
                });
                var pcodeIt = highFunc.getPcodeOps();
                while (pcodeIt.hasNext()) {
                    sorted.add(pcodeIt.next());
                }
                while (!sorted.isEmpty()) {
                    var op = sorted.poll();
                    println(fmt(highFunc, op));
                }
            }
        });
    }

    private String fmt(HighFunction highFunc, PcodeOp op) {
        final StringBuilder sb = new StringBuilder();
        sb.append(String.format("0x%08x:%d: ",
                op.getSeqnum().getTarget().getUnsignedOffset(),
                op.getSeqnum().getOrder()));
        var out = op.getOutput();
        if (out != null) {
            sb.append(String.format("%s = ", fmt(out)));
        }
        sb.append(String.format("%s(", op.getMnemonic()));
        if (op.getNumInputs() > 0) {
            sb.append(Arrays.stream(op.getInputs()).map(in -> fmt(in)).collect(Collectors.joining(", ")));
        }
        sb.append(")");
        if (op.getOpcode() == PcodeOp.INDIRECT) {
            var sq = new SequenceNumber(op.getSeqnum().getTarget(),
                    (int) op.getInput(op.getNumInputs() == 1
                            ? 0
                            : 1)
                            .getOffset());
            var iop = highFunc.getPcodeOp(sq);
            if (iop != null) {
                sb.append(String.format(" -> %s", fmt(highFunc, iop)));
            }
        }
        return sb.toString();
    }

    private String fmt(Varnode vnode) {
        if (vnode == null) {
            return "(null)";
        } else if (vnode.isRegister()) {
            final Register reg = currentProgram.getLanguage().getRegister(vnode.getAddress(), vnode.getSize());
            final String name = (reg == null)
                    ? String.format("r0x%x:%d", vnode.getAddress().getUnsignedOffset(), vnode.getSize())
                    : reg.getName();
            final StringBuilder sb = new StringBuilder();
            sb.append(name);
            if (vnode.getDef() != null) {
                sb.append(String.format("(0x%08x:%d)",
                        vnode.getDef().getSeqnum().getTarget().getUnsignedOffset(),
                        vnode.getDef().getSeqnum().getOrder()));
            }
            return sb.toString();
        } else if (vnode.isAddress()) {
            return String.format("0x%08x", vnode.getAddress().getUnsignedOffset());
        } else if (vnode.isUnique()) {
            return String.format("u0x%08x(0x%08x:%d)",
                    vnode.getOffset(),
                    vnode.getDef().getSeqnum().getTarget().getUnsignedOffset(),
                    vnode.getDef().getSeqnum().getOrder());
        }
        return String.format("0x%x", vnode.getOffset());
    }
}
