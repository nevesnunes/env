# +

- [GitHub \- NWMonster/ApplySig: Apply IDA FLIRT signatures for Ghidra](https://github.com/NWMonster/ApplySig)
- [disassembly \- Python Script to get disassembled output of an EXE file \- Reverse Engineering Stack Exchange](https://reverseengineering.stackexchange.com/questions/22377/python-script-to-get-disassembled-output-of-an-exe-file)

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
