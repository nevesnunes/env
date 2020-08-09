# Build

```bash
cargo install --path .
# ||
cargo build -j 2 --release
```

# Deploy

```bash
# compiled without debug info
cargo web deploy --release
```

# Windows support

- [Add Windows support by Jokler · Pull Request \#9 · dtolnay/cargo\-llvm\-lines · GitHub](https://github.com/dtolnay/cargo-llvm-lines/pull/9/files)
