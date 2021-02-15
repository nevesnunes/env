# +

- [WasmExplorer - convert c / wat / firefox asm](https://mbebenita.github.io/WasmExplorer/)

# documentation, specification

- [Text Format &\#8212; WebAssembly 1\.1](https://webassembly.github.io/spec/core/text/index.html)

# decompiling

- Firefox: F12 > Debugger > Sources = `wasm://`

```bash
# text format
wasm2wat app.wasm -o app.wat

# javascript (FIXME: loop, label, goto...)
wasm-decompile app.wasm -o app.dcmp
awk '
/:/ {
    gsub(":[[:alpha:]]+", "", $0)
    gsub(":{[^}]*}", "", $0)
    print
    next
}
{ print }
' app.dcmp > app.js

# c
wasm2c app.wasm -o app.c
gcc -m32 -fno-PIC -Os -c -fno-reorder-functions -fno-inline-functions-called-once -fno-inline-small-functions app.c
```

# optimizing temporary variables

- [Closure Compiler Service](https://closure-compiler.appspot.com)
    - [GitHub \- google/closure\-compiler: A JavaScript checker and optimizer\.](https://github.com/google/closure-compiler)
- [GitHub \- facebook/prepack: A JavaScript bundle optimizer\.](https://github.com/facebook/prepack)

# optimizing size

- compilers - tinygo
