//Emulation script for scoring how code logic matches up with an ISA blind guess
//@author flib
//@category
//@keybinding
//@menupath
//@toolbar

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Scanner;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.app.plugin.processors.sleigh.SleighLanguageProvider;
import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.util.task.TaskMonitor;

public class BlindEmu extends GhidraScript {
    @Override
    protected String decorate(final String message) {
        return message;
    }

    @Override
    protected void run() throws Exception {
        SleighLanguageProvider provider = SleighLanguageProvider.getSleighLanguageProvider();
        List<String> languageIds = List.of("SuperH4:LE:32:default", "z80:LE:16:default");

        try (Scanner scanner = new Scanner(System.in)) {
            while (true) {
                run(provider, languageIds);

                println("Retry [y/N]? ");
                String line = scanner.nextLine();
                if (!(line.contains("y") || line.contains("Y"))) {
                    break;
                }
            }
        }
    }

    private void run(SleighLanguageProvider provider, List<String> languageIds) {
        languageIds.forEach(languageId -> {
            println(String.format("Guessing '%s'.", languageId));
            Emulatable emu = null;
            try {
                emu = Emulatable.emu(languageId, provider);
                int line_i = 0;
                while (!monitor.isCancelled()) {
                    println(dump(emu));

                    boolean ok = emu.cpu.step(monitor);
                    if (!ok) {
                        printerr(emu.cpu.getLastError());
                        break;
                    }

                    line_i++;
                    if (line_i > 10) {
                        break;
                    }
                }
            } catch (final Exception ex) {
                printerr(ex.getMessage());
            } finally {
                emu.prg.endTransaction(emu.tx, true);
                emu.prg.release(emu.consumer);
                emu.cpu.dispose();
            }
        });
    }

    @SuppressWarnings("unchecked")
    private List<String> languageIds(SleighLanguageProvider provider) throws Exception {
        final Field fieldLanguages = Arrays
                .asList(SleighLanguageProvider.class.getDeclaredFields()).stream()
                .filter(field -> field.getName().equals("languages"))
                .findFirst()
                .orElseThrow(() -> new RuntimeException("Field `languages` not found"));
        fieldLanguages.setAccessible(true);
        final LinkedHashMap<LanguageID, SleighLanguage> languages = (LinkedHashMap<LanguageID, SleighLanguage>) fieldLanguages
                .get(provider);
        return languages.keySet().stream().map(id -> id.getIdAsString()).toList();
    }

    private SleighLanguageProvider provider() throws Exception {
        final SleighLanguageProvider provider = SleighLanguageProvider.getSleighLanguageProvider();

        final Method methodCreateLanguages = Arrays.asList(provider.getClass().getDeclaredMethods())
                .stream()
                .filter(m -> m.getName().equals("createLanguages"))
                .filter(m -> m.getParameters().length == 0)
                .findFirst()
                .orElseThrow(() -> new RuntimeException("Method `createLanguages` not found"));
        methodCreateLanguages.setAccessible(true);
        methodCreateLanguages.invoke(provider);

        return provider;
    }

    private Instruction explore(Emulatable emu, Address addr) {
        Instruction ins = emu.prg.getListing().getInstructionAt(addr);
        if (ins == null) {
            Address nextAddr = addr(emu.prg, addr.getUnsignedOffset() + 1);
            emu.prg.getListing().clearCodeUnits(addr, nextAddr, false);
            DisassembleCommand cmd = new DisassembleCommand(addr, null, true);
            if (!cmd.applyTo(emu.prg) || cmd.getDisassembledAddressSet().isEmpty()) {
                // printerr(String.format("Null disasm @ 0x%08x", addr.getUnsignedOffset()));
            }
            ins = emu.prg.getListing().getInstructionAt(addr);
            if (ins == null) {
                // printerr(String.format("Null instruction after disasm @ 0x%08x", addr.getUnsignedOffset()));
            }
        }

        return ins;
    }

    private static Address addr(Program prg, long offset) {
        return prg.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
    }

    private String dump(Emulatable emu) {
        long pc = emu.cpu.getExecutionAddress().getUnsignedOffset();
        explore(emu, addr(emu.prg, pc));

        StringBuilder sb = new StringBuilder();

        Listing listing = emu.prg.getListing();

        Disassembler dis = Disassembler.getDisassembler(
                emu.prg,
                TaskMonitor.DUMMY,
                null);
        dis.disassemble(addr(emu.prg, pc), null);
        Instruction instr = listing.getInstructionAt(addr(emu.prg, pc));
        sb.append(String.format("%08x: %-8s%n",
                instr.getAddress().getOffset(),
                instr.getMnemonicString()));

        CodeUnit cu = listing.getCodeUnitAt(addr(emu.prg, pc));
        sb.append(String.format("%08x %-32s", pc, cu));

        return sb.toString();
    }

    public record Emulatable(Program prg, Integer tx, EmulatorHelper cpu, Object consumer) {
        public static Emulatable emu(String languageId, SleighLanguageProvider provider) throws Exception {
            SleighLanguage language = (SleighLanguage) provider.getLanguage(new LanguageID(languageId));
            String id = String.format("blind_%s", languageId);
            Object consumer = new Object();
            Program prg = new ProgramDB(id, language, language.getDefaultCompilerSpec(), consumer);
            Integer tx = prg.startTransaction(id);

            // byte[] code = new byte[0x1000];
            // currentProgram.getMemory().getBytes(addr(prg, 0), code);
            byte[] code = HexFormat.of().parseHex("ff30130a4dba1dce");
            AddressSpace space = prg.getAddressFactory().getDefaultAddressSpace();
            Address entry = space.getAddress(0);
            Memory mem = prg.getMemory();
            mem.createInitializedBlock(".text", entry, 0x1000, (byte) 0, TaskMonitor.DUMMY, false);
            mem.setBytes(entry, code);
            mem.getBlock(addr(prg, 0)).setPermissions(true, true, true);

            EmulatorHelper cpu = new EmulatorHelper(prg);

            return new Emulatable(prg, tx, cpu, consumer);
        }
    }
}
