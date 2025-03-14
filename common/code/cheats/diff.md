# +

- [GitHub \- Wilfred/difftastic: a structural diff that understands syntax 🟥🟩](https://github.com/Wilfred/difftastic/)
- [GitHub \- dandavison/delta: A syntax\-highlighting pager for git, diff, grep, and blame output](https://github.com/dandavison/delta)

```bash
# multiple files
diff --from-file source1 target2 target3

# find identical files matching input file
f=foo; find . -type f -exec sh -c 'diff -q '{}' '"$f"' >/dev/null && echo '{} \;

# external comparison of image revisions
diff-img foo.png <(git show HEAD^:foo.png)

# binary diff
biodiff 1 2
dhex 1 2
cmp -l 1 2
binwalk -W 1 2
diff -u <(xxd 1) <(xxd 2)
```

# types

- text: `diff`
    - library: `diff-match-patch`
- binary: `dhex`
    - structured: `kaitai -> gron -> diff`
- image: `magick`
- audio: `chromaprint/src/cmd/fpcalc -> diff`
