# FLIRT

- [GitHub \- Maktm/FLIRTDB: A community driven collection of IDA FLIRT signature files](https://github.com/Maktm/FLIRTDB)

- [Investigating IDA Lumina feature ](https://www.synacktiv.com/en/publications/investigating-ida-lumina-feature.html)
- [IDA F\.L\.I\.R\.T\. Technology: In\-Depth &\#8211; Hex Rays](https://www.hex-rays.com/products/ida/tech/flirt/in_depth/)
- https://reverseengineering.stackexchange.com/questions/175/what-is-a-flirt-signature

```bash
# Generate FLIRT signatures
# References: https://www.ccso.com/faq.html
# Alternatives: https://github.com/fireeye/flare-ida/blob/master/python/flare/idb2pat.py
plb foo.lib foo.pat
sigmake foo.pat foo.sig
```

# Binary search

- [!] hex string with spaces

# Decompilation

- Views > Open subviews > Pseudocode (`F5`)
- [!] "positive sp value has been found" => change offset (`Alt-k`)

# Config

- Options > General > Disassembly > Number of opcode bytes (Graph) = 8
- Views > Open subviews > Cross references

# Data

- change size: move cursor to line at address to change (no visual select), then press `d`

# Symbols

### Rename

```
idc.MakeName(idc.GetOperandValue(0x123772cd, 0), 'dynamic_3')
```

- [Introduction to IDAPython](http://www.openrce.org/articles/full_view/11)
- https://github.com/idapython/src/tree/master/examples
- https://www.hex-rays.com/products/ida/support/idapython_docs/
- https://www.hex-rays.com/products/ida/support/sdkdoc/

### Watcom

1. Generate "Object Table" + "Addr Info"
    ```bash
    wdump -Dx -a FOO.EXE
    ```
2. For each name in "Addr Info", match segment with object index, take "relocation base address" and add to symbol's offset
3. For each symbol name + modified offset, generate IDC commands
    ```
    MakeName(0x14B540, "foo1");
    MakeName(0x14B544, "foo2");
    ```
- [!] Only 200 pasted and run at a time...
- :) Automatic demangled names in comment

### Turbo / Borland

```bash
# Turbo Debugger
TD.EXE
# Turbo Dump
TDUMP.EXE
```

- [GitHub \- ramikg/tdinfo\-parser: Turbo/Borland debug information parser for IDA](https://github.com/ramikg/tdinfo-parser)
