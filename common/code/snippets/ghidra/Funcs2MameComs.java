//Dump function address ranges as MAME debug script comments
//@author flib
//@category
//@keybinding
//@menupath
//@toolbar

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolType;

public class Funcs2MameComs extends GhidraScript {

    @Override
    public void run() throws Exception {
        Path outFile = Paths.get(String.format(
                "%s/%s.mame.txt",
                System.getProperty("user.home"),
                currentProgram.getName()));
        Files.write(outFile, new byte[0], StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
        FileWriter fw = new FileWriter(outFile.toString(), true);
        try (BufferedWriter bw = new BufferedWriter(fw)) {
            var symbols = currentProgram.getSymbolTable().getAllSymbols(true);
            while (symbols.hasNext()) {
                var symbol = symbols.next();
                if (symbol.getSymbolType() != SymbolType.FUNCTION) {
                    continue;
                }

                var symAddr = symbol.getAddress();
                if (symAddr.getAddressSpace().isOverlaySpace()) {
                    continue;
                }

                if (symbol.getSource().isLowerPriorityThan(SourceType.IMPORTED)) {
                    continue;
                }

                println(String.format(
                        "Function '%s' @ 0x%08x",
                        symbol.getName(),
                        symAddr.getUnsignedOffset()));

                var func = currentProgram.getFunctionManager().getFunctionAt(symAddr);
                var instrs = currentProgram.getListing().getInstructions(func.getBody(), true);
                while (instrs.hasNext() && !monitor.isCancelled()) {
                    var instr = instrs.next();
                    long instrOfs = instr.getAddress().getUnsignedOffset();
                    bw.write(String.format(
                            "comadd %x,%s+%04x%n",
                            instrOfs,
                            symbol.getName(),
                            instrOfs - symAddr.getUnsignedOffset()));
                }
            }
        }
    }
}
