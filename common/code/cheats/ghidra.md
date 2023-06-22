# +

- [disassembly \- Python Script to get disassembled output of an EXE file \- Reverse Engineering Stack Exchange](https://reverseengineering.stackexchange.com/questions/22377/python-script-to-get-disassembled-output-of-an-exe-file)
- [GitHub \- TorgoTorgo/ghidra\-findcrypt: Ghidra analysis plugin to locate cryptographic constants](https://github.com/TorgoTorgo/ghidra-findcrypt)

# function ID (FID)

- `Tools > Function ID > Populate FidDb from programs`
- [GitHub \- NWMonster/ApplySig: Apply IDA FLIRT signatures for Ghidra](https://github.com/NWMonster/ApplySig)
- https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/FunctionID/data/building_fid.txt
- https://github.com/NationalSecurityAgency/ghidra-data/blob/master/FunctionID/FID.md
- https://blog.threatrack.de/2019/09/20/ghidra-fid-generator/
- https://raw-data.gitlab.io/post/ghidra_fid/

1. Enable FunctionID plugin
2. Create new empty database
3. Populate database with program (I get 6783 results added to the database)
4. When I load in another binary (using the same functions), I use Set Active databases
5. I turned on "Always apply FID Label" in the analyzer's settings

> In my code browser when i go to File -> Configure... I do not see an option for Function ID (there are only sections Ghidra Core, Debugger, Miscellaneous, Developer, and Experimental), and under the experimental plugins there's no option for FidDebugPlugin. However, Function ID is availble under Tools -> Function ID. What could cause that? 
> I found it, they moved it to developer

# data types (GDT)

- https://reversing.technology/2021/06/16/ghidra_DWARF_gdt.html

# symbols

### export

- Window > Symbol Table > [Select lines and open context menu] > Export to CSV...

### import

- Window > Script Manager > ImportSymbolScript.py
    - [Import labels from text file · Issue \#170 · NationalSecurityAgency/ghidra · GitHub](https://github.com/NationalSecurityAgency/ghidra/issues/170)

### PDB

- File > Load PDB File...
    - Config > Add https://msdl.microsoft.com/download/symbols/
    - For ntoskrnl: ntkrnlmp.pdb
    - On linux: createPdbXmlFiles.bat

# extension build

```bash
gradle -PGHIDRA_INSTALL_DIR="$HOME/opt/ghidra_9.2.3_PUBLIC" buildExtension
cp dist/*.zip "$HOME/opt/ghidra_9.2.3_PUBLIC/Extensions/Ghidra/"
```

# import project

1. File > Import... > Existing project
2. GhidraDev > Link Ghidra...

# debug project

1. If "Multiple modules collided with same name", then remove installed extension || temporarily move from ~/.ghidra/
2. Run > Debug Configrations... > Classpath 
    - Bootstrap Entries || User Entries > Add project...
3. Debug (Ghidra instance is launched from Eclipse)

- https://reverseengineering.stackexchange.com/questions/24951/how-to-launch-and-debug-ghidra-from-eclipse-with-two-modules-im-developing-at-t/

# configuration

- Script Manager
    - Pick: ResolveX86orX64LinuxSyscallsScript
- CodeBrowser > Edit > Tool Options > Decompiler > Analysis
    - Unpick: Eliminate unreachable code
- CodeBrowser > Function Call Trees (Incoming + Outgoing Calls)

# bad disassembly

1. Select instructions > Clear Code Block
2. Select bytes (starting at expected offset) > Disassemble

# slow analysis

```bash
./analyzeHeadless $ghidra_database/ $database_name -process '*' -recursive
```

- https://ghidra.re/ghidra_docs/analyzeHeadlessREADME.html

# stack

Listing > Edit the Listing fields > Instruction Data > Add Field > Stack Depth

# type recovery

- File > Export Program > Export As C/C++

```c
typedef unsigned char undefined;
typedef unsigned char byte;
typedef unsigned int dword;
typedef unsigned int uint;
typedef unsigned char uint3[3];
typedef unsigned char undefined1;
typedef unsigned short undefined2;
typedef unsigned int undefined4;
typedef unsigned long long undefined8;
typedef unsigned short ushort;
typedef unsigned short word;
```

- [Ghidra CONCAT Implementations · GitHub](https://gist.github.com/SeanPesce/57200f694674d73cac4704f11a8eb90b)

# scripting

- https://ghidra.re/ghidra_docs/api/ghidra/program/flatapi/FlatProgramAPI.html
- https://ghidra.re/ghidra_docs/api/ghidra/program/model/address/Address.html
    - https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/program/model/address/Address.java

### pcode

- https://www.riverloopsecurity.com/blog/2019/05/pcode/
- https://swarm.ptsecurity.com/guide-to-p-code-injection/

# emulation

- [GitHub \- Nalen98/GhidraEmu: Native Pcode emulator](https://github.com/Nalen98/GhidraEmu)
- [First Look: Ghidra 10.3 Emulator](https://www.reddit.com/r/ghidra/comments/13gng9p/first_look_ghidra_103_emulator/)
    > Probably the best use case so far has been pcodetest which takes C code that tries to create junit tests for SLEIGH processor module validation. They gave an introduction at RECON 2019. The difficulty here is one size fits all: it's one C source base and you can't guarantee the coverage of asm produced from ISA to ISA with the compiler. It may not generate all the instructions or even whole classes of them. It may not generate enough variety in register usage, which for register based languages like SLEIGH, that is important to test. Some of the more interesting instructions, and typically the harder ones to implement in SLEIGH, sometimes don't even have a C counterpart.

# add cpu architecture / processor module

```sh
# Compile SLEIGH specifications
cd ~/code/ghidra_workspace/foo/data
ant -f buildLanguage.xml
```

- https://swarm.ptsecurity.com/creating-a-ghidra-processor-module-in-sleigh-using-v8-bytecode-as-an-example/
- https://spinsel.dev/2020/06/17/ghidra-brainfuck-processor-1.html
- ~/code/doc/reversing/Implementing\ a\ New\ CPU\ Architecture\ for\ Ghidra.pdf
- [GitHub \- oberoisecurity/ghidra\-processor\-module\-generator: A step towards automating the creation of Ghidra processor modules](https://github.com/oberoisecurity/ghidra-processor-module-generator)

- https://htmlpreview.github.io/?https://github.com/NationalSecurityAgency/ghidra/blob/master/GhidraDocs/languages/index.html
- https://ghidra.re/courses/languages/html/sleigh.html
    - https://github.com/NationalSecurityAgency/ghidra/tree/master/Ghidra/Framework/SoftwareModeling/src/main/antlr/ghidra/sleigh/grammar
- https://github.com/NationalSecurityAgency/ghidra/tree/master/Ghidra/Framework/SoftwareModeling/data/languages
- https://github.com/NationalSecurityAgency/ghidra/tree/master/Ghidra/Features/Decompiler/src/main/doc
- https://github.com/NationalSecurityAgency/ghidra/tree/master/Ghidra/Processors

### testing

- [ghidra/Ghidra/Extensions/SleighDevTools/pcodetest at master · NationalSecurityAgency/ghidra · GitHub](https://github.com/NationalSecurityAgency/ghidra/tree/master/Ghidra/Extensions/SleighDevTools/pcodetest)
- [What is pcodeTest · Issue \#833 · NationalSecurityAgency/ghidra · GitHub](https://github.com/NationalSecurityAgency/ghidra/issues/833)
    - [recon2019](https://github.com/NationalSecurityAgency/ghidra/wiki/files/recon2019.pdf)
    > These tests have a corresponding compiled pcodetest binary which must be created before the tests can be run. We did not want to compile and store these test binaries within the repository. The C source which must be built separately for each test can be found within the Ghidra SleighDevTools extension module. This extension must be installed/unpacked to access the source which also include python build scripts. You will need to obtain the appropriate cross-build toolchain and adjust the build scripts for your environment before building the pcodetest binary. There is a README file but as you will see it is rather involved and not well documented.

- [ghidra/TRICORE\_BE\_O0\_EmulatorTest\.java at da94eb86bd2b89c8b0ab9bd89e9f0dc5a3157055 · NationalSecurityAgency/ghidra · GitHub](https://github.com/NationalSecurityAgency/ghidra/blob/da94eb86bd2b89c8b0ab9bd89e9f0dc5a3157055/Ghidra/Processors/tricore/src/test.processors/java/ghidra/test/processors/TRICORE_BE_O0_EmulatorTest.java)
- [GT\-3041\_emteere Added emulation tests and minor changes to calling · NationalSecurityAgency/ghidra@0a517e6 · GitHub](https://github.com/NationalSecurityAgency/ghidra/commit/0a517e6864c4ccee059c1241c7d10b04cb679c9e)

# change data string encoding

1. Select bytes
2. Open: Context menu > Data > String
3. Open: Context menu > Data > Settings > Charset

# multiple files with same memory map

1. File > Add to program
2. Memory Map > Add Memory Block
    - Length: file size
    - Overlay: check
    - File Bytes: added file
    - File Offset: 0

# bindiff

1. Load PDB symbols (if available)
1. Export... > Binary BinExport (v2) for BinDiff
1. bindiff primary.BinExport secondary.BinExport, take primary_vs_secondary.BinDiff
1. bindiff --ui
1. Diffs > Add Existing Diff...

- https://reverseengineering.stackexchange.com/questions/22372/do-i-need-to-have-ida-pro-to-use-the-bindiff-tool
