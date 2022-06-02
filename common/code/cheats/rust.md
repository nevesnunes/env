# +

- https://play.rust-lang.org/
- [GitHub \- immunant/c2rust: Migrate C code to Rust](https://github.com/immunant/c2rust)

# Docs

- https://doc.rust-lang.org/stable/std/?search=
- https://doc.rust-lang.org/src/core/fmt/mod.rs.html
    - https://github.com/rust-lang/rust/tree/master/library/core/src

# Build

```bash
rustc foo.rs

cargo install --path .
# ||
cargo install --force --path .
# ||
cargo build -j 2 --release

# compiler output
# e.g. https://stackoverflow.com/questions/46388386/what-exactly-does-derivedebug-mean-in-rust
cargo +nightly rustc -- -Zunstable-options --pretty=expanded
```

### Toolchains

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# version pinning
rustup install 1.52.0
cargo +1.52.0 run
```

# Deploy

```bash
rustc -C opt-level=3

# compiled without debug info
cargo web deploy --release
```

# Unsafe

- https://github.com/rust-lang/unsafe-code-guidelines/
- https://doc.rust-lang.org/nomicon/intro.html
- https://crates.io/crates/bytemuck
    - `pub fn foo<T: Pod>(data: &T) -> Result<&[u8], Error>`

# Assembly

- `main()` passed as argument to `lang_start()`:
   ```
   lea    rdi, [rip - 0x5e]
   call   std::rt::lang_start
   ```
- `ud2` instruction after panic! calls in diverging functions
    - [ Can we stop generating illegal instructions? · Issue \#1454 · rust\-lang/rfcs · GitHub](https://github.com/rust-lang/rfcs/issues/1454)

### Demangle

```bash
cargo install rustfilt
objdump -d foo | grep -Po '(?<=<)_Z.*(?=>)' | rustfilt
objdump -d foo | grep -Po '(?<=<)_Z.*(?=>)' | while read -r i; do { echo "$i" | rustfilt; echo "$i"; } | paste -sd" "; done
# (gdb) disassemble _ZN4core3fmt9Arguments6new_v117h501368407ffcb59bE
```

- https://rust-lang.github.io/rfcs/2603-rust-symbol-name-mangling-v0.html

### structs

- format str
    ```fasm
    sub    rsp,0x38
    lea    rdi,[rsp+0x8] ; local var for new object
    lea    rsi,[rip+0x39d20] ; pointer to str
    ...
    call   0x55555555b990 ; <_ZN4core3fmt9Arguments6new_v117h501368407ffcb59bE>
    lea    rdi,[rsp+0x8] ; read initialized new object (contains str)
    ```
- custom
    ```fasm
    ; [u16; 8]
    ; [1,2,3,4,5,6,7,8]
    sub     rsp, 32
    mov     word ptr [rsp + 16], 1 ; reserved 2*8 bytes for result
    mov     word ptr [rsp + 18], 2
    mov     word ptr [rsp + 20], 3
    mov     word ptr [rsp + 22], 4
    mov     word ptr [rsp + 24], 5
    mov     word ptr [rsp + 26], 6
    mov     word ptr [rsp + 28], 7
    mov     word ptr [rsp + 30], 8
    mov     rax, qword ptr [rsp + 16] ; copy 2*8 bytes to result
    mov     qword ptr [rsp], rax
    mov     rax, qword ptr [rsp + 24]
    mov     qword ptr [rsp + 8], rax
    add     rsp, 32
    ret
    ```

- https://stackoverflow.com/questions/62146473/understanding-assembly-generated-from-simple-rust-struct

# Windows support

- [Add Windows support by Jokler · Pull Request \#9 · dtolnay/cargo\-llvm\-lines · GitHub](https://github.com/dtolnay/cargo-llvm-lines/pull/9/files)

# Case studies

- [Down the Stack: Compiled Rust Part 1 \- You Learn Something New Everyday 💭](https://blog.ryanlevick.com/down-the-stack-part-1/)
