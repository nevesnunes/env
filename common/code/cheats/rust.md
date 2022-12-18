# +

- https://play.rust-lang.org/
- [GitHub \- immunant/c2rust: Migrate C code to Rust](https://github.com/immunant/c2rust)

# Docs

- https://doc.rust-lang.org/stable/std/?search=
- https://doc.rust-lang.org/src/core/fmt/mod.rs.html
    - https://github.com/rust-lang/rust/tree/master/library/core/src

# Bootstrap

```sh
cargo new --bin foo
cargo build
cargo run
```

```toml
# The development profile, used for `cargo build`
[profile.dev]
opt-level = 0  # Controls the --opt-level the compiler builds with
debug = true   # Controls whether the compiler passes `-g`

# The release profile, used for `cargo build --release`
[profile.release]
opt-level = 3
debug = false
```

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

# for `#![feature]`
rustup install nightly
cargo +nightly build
```

# Deploy

```bash
rustc -C opt-level=3

# compiled without debug info
cargo web deploy --release
```

# Debug

```sh
rustc -g

# Backtrace on panics
RUST_BACKTRACE=1 ./foo

# Pretty-printing for rust types
rust-gdb
```

```rust
#![feature(backtrace)]
use std::backtrace::Backtrace;

fn main() {
    println!("Custom backtrace: {}", Backtrace::force_capture());
}
```

- symbols outside current crate
    - https://sourceware.org/gdb/onlinedocs/gdb/Rust.html
    ```gdb
    print extern x::y
    ```

# Design

```rust
fn print_all(all: Vec<i32>) {
    for (i, a) in all.iter().enumerate() {
        println!("{}: {}", i, a);
    }
}
fn double_all(all: &mut Vec<i32>) {
    for a in all.iter_mut() {
        *a += *a;
    }
}

fn pointer_ops() {
    // owning (aka unique) pointer (move semantics)
    let x = 3;
    let mut y = Box::new(x);
    *y = 45;
    println!("x is still {}", x);

    // borrowed pointer
    let mut x = 5;            // type: i32
    {
        let y = &x;           // type: &i32
        //x = 4;              // Error - x has been borrowed
        println!("{}", x);    // Ok - x can be read
    }
    x = 4;                    // OK - y no longer exists
}

struct Node {
    parent: Option<Rc<Node>>,
    value: i32
}
fn is_root(node: Node) -> bool {
    match node.parent {
        Some(_) => false,
        None => true
    }
    // node.parent.is_none()
}

fn mut_field_in_immut_obj(x: Rc<RefCell<S>>) {
    {
        let s = x.borrow();
        println!("the field, twice {} {}", s.field, x.borrow().field);
        // let s = x.borrow_mut(); // Error - we've already borrowed the contents of x
    }

    let mut s = x.borrow_mut(); // OK, the earlier borrows are out of scope
    s.field = 45;
    // println!("The field {}", x.borrow().field); // Error - can't mut and immut borrow
    println!("The field {}", s.field);
}

let a: [i32; 4] = [1, 2, 3, 4];
let b: &[i32] = &a;   // Slice of the whole array.
let c = &a[1..3];     // The middle two elements, &[i32].
let v = vec![1, 2, 3, 4];      // A Vec<i32> with length 4.
let v: Vec<i32> = Vec::new();  // An empty vector of i32s.
```

### Unsafe

```rust
// raw pointer
let mut x = 5;
let x_p: *mut i32 = &mut x;
println!("x+5={}", add_5(x_p));

fn add_5(p: *mut i32) -> i32 {
    unsafe {
        if !p.is_null() { // Note that *-pointers do not auto-deref, so this is
                          // a method implemented on *i32, not i32.
            *p + 5
        } else {
            -1            // Not a recommended error handling strategy.
        }
    }
}
```

- https://github.com/rust-lang/unsafe-code-guidelines/
- https://doc.rust-lang.org/nomicon/intro.html
- https://crates.io/crates/bytemuck
    - `pub fn foo<T: Pod>(data: &T) -> Result<&[u8], Error>`

### Pattern Matching

```rust
enum Op {
    Double(x),
    Multiply(x, y),
}
fn double_or_multiply(input: Op) {
    match input {
        Double(x) => x * 2,
        Multiply(x, y) => x * y,
    }
}
```

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
