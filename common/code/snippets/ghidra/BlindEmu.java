//Emulation script for scoring how code logic matches up with an ISA blind guess
//@author flib
//@category
//@keybinding
//@menupath
//@toolbar

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;

import db.Transaction;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;

public class BlindEmu extends GhidraScript {
    @Override
    protected void run() throws Exception {
        List<String> languageIds = languageIds();
        languageIds.forEach(languageId -> {
            println(String.format("Guessing '%s'.", languageId));
            EmulatorHelper cpu = null;
            try {
                cpu = cpu(languageId);
                int line_i = 0;
                while (!monitor.isCancelled()) {
                    boolean ok = cpu.step(monitor);
                    if (!ok) {
                        printerr(cpu.getLastError());
                        break;
                    }
                    println(dump(cpu));
    
                    line_i++;
                    if (line_i > 10) {
                        break;
                    }
                }
            } catch (final Exception ex) {
                printerr(ex.getMessage());
            } finally {
                cpu.dispose();
            }
        });
    }

    private List<String> languageIds() {
        // TODO:
        // INFO  BlindEmu.java> Guessing '6502:LE:16:default'. (GhidraScript)  
        // ERROR BlindEmu.java> Cannot invoke "ghidra.program.model.mem.MemoryBlock.setPermissions(boolean, boolean, boolean)" 
        //                      because the return value of "ghidra.program.model.mem.Memory.getBlock(ghidra.program.model.address.Address)" is null (GhidraScript)  
        /*
        List<String> languageIds = new ArrayList<String>();
        try (BufferedReader reader = Files.newBufferedReader(new File("/tmp/langs").toPath(), StandardCharsets.UTF_8)) {
            String line;
            while ((line = reader.readLine()) != null) {
                languageIds.add(line);
            }
        } catch (final Exception ex) {
            printerr(ex.getMessage());
        }

        return languageIds;
        */
        return List.of("SuperH4:LE:32:default", "z80:LE:16:default");
    }

    private EmulatorHelper cpu(String languageId) throws Exception {
        SleighLanguage language = (SleighLanguage) getLanguage(new LanguageID(languageId));
        Program program = new ProgramDB(String.format("blind_%s", languageId), language,
                language.getDefaultCompilerSpec(), this);

        byte[] code = new byte[0x1000];
        currentProgram.getMemory().getBytes(addr(0), code);
        try (Transaction tx = program.openTransaction("Init")) {
            AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
            Address entry = space.getAddress(0);
            Memory mem = program.getMemory();
            mem.createInitializedBlock(".text", entry, 0x1000, (byte) 0, monitor, false);
            mem.setBytes(entry, code);
            mem.getBlock(addr(0)).setPermissions(true, false, true);
        }

        EmulatorHelper cpu = new EmulatorHelper(program);

        return cpu;
    }

    private Instruction explore(EmulatorHelper emu, Address addr) {
        Instruction ins = emu.getProgram().getListing().getInstructionAt(addr);
        if (ins == null) {
            Address nextAddr = addr(addr.getUnsignedOffset() + 1);
            emu.getProgram().getListing().clearCodeUnits(addr, nextAddr, false);
            DisassembleCommand cmd = new DisassembleCommand(addr, null, true);
            if (!cmd.applyTo(emu.getProgram()) || cmd.getDisassembledAddressSet().isEmpty()) {
                // printerr(String.format("Null disasm @ 0x%08x", addr.getUnsignedOffset()));
            }
            ins = emu.getProgram().getListing().getInstructionAt(addr);
            if (ins == null) {
                // printerr(String.format("Null instruction after disasm @ 0x%08x", addr.getUnsignedOffset()));
            }
        }

        return ins;
    }

    private Address addr(long offset) {
        return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
    }

    private String dump(EmulatorHelper emu) {
        long pc = emu.getExecutionAddress().getUnsignedOffset();
        explore(emu, addr(pc));

        CodeUnit cu = emu.getProgram().getListing().getCodeUnitAt(addr(pc));
        StringBuilder sb = new StringBuilder();
        sb.append(String.format("%08x %-32s", pc, cu));

        return sb.toString();
    }
}
