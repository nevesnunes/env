# +

- [disassembly \- Python Script to get disassembled output of an EXE file \- Reverse Engineering Stack Exchange](https://reverseengineering.stackexchange.com/questions/22377/python-script-to-get-disassembled-output-of-an-exe-file)

# function ID (FID)

- `Tools > Function ID > Populate FidDb from programs`
- [GitHub \- NWMonster/ApplySig: Apply IDA FLIRT signatures for Ghidra](https://github.com/NWMonster/ApplySig)
- https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/FunctionID/data/building_fid.txt
- https://blog.threatrack.de/2019/09/20/ghidra-fid-generator/
- https://raw-data.gitlab.io/post/ghidra_fid/

# data types (GDT)

- https://reversing.technology/2021/06/16/ghidra_DWARF_gdt.html

# extension build

```bash
gradle -PGHIDRA_INSTALL_DIR="$HOME/opt/ghidra_9.2.3_PUBLIC" buildExtension
cp dist/*.zip "$HOME/opt/ghidra_9.2.3_PUBLIC/Extensions/Ghidra/"
```

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

# scripting

- https://ghidra.re/ghidra_docs/api/ghidra/program/flatapi/FlatProgramAPI.html
- https://ghidra.re/ghidra_docs/api/ghidra/program/model/address/Address.html
    - https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/program/model/address/Address.java

### pcode

- https://www.riverloopsecurity.com/blog/2019/05/pcode/

# emulation

- [GitHub \- Nalen98/GhidraEmu: Native Pcode emulator](https://github.com/Nalen98/GhidraEmu)

# add cpu architecture / processor module

- https://swarm.ptsecurity.com/creating-a-ghidra-processor-module-in-sleigh-using-v8-bytecode-as-an-example/
- https://spinsel.dev/2020/06/17/ghidra-brainfuck-processor-1.html

- https://ghidra.re/courses/languages/html/sleigh.html
- https://github.com/NationalSecurityAgency/ghidra/tree/master/Ghidra/Framework/SoftwareModeling/data/languages
- https://github.com/NationalSecurityAgency/ghidra/tree/master/Ghidra/Features/Decompiler/src/main/doc

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

1. Export... > Binary BinExport (v2) for BinDiff
2. bindiff primary.BinExport secondary.BinExport, take primary_vs_secondary.BinDiff
3. bindiff --ui
4. Diffs > Add Existing Diff...

- https://reverseengineering.stackexchange.com/questions/22372/do-i-need-to-have-ida-pro-to-use-the-bindiff-tool
