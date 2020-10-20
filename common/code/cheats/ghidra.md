# +

https://reverseengineering.stackexchange.com/questions/22377/python-script-to-get-disassembled-output-of-an-exe-file

# configuration

- Script Manager
    - Pick: ResolveX86orX64LinuxSyscallsScript
- CodeBrowser > Edit > Tool Options > Decompiler > Analysis
    - Unpick: Eliminate unreachable code
- CodeBrowser > Function Call Trees (Incoming + Outgoing Calls)

# bad disassembly

1. Select instructions > Clear Code Block
2. Select bytes (starting at expected offset) > Disassemble


