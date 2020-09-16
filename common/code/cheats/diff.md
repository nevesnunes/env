# +

```bash
# multiple files
diff --from-file source1 target2 target3

# find identical files matching input file
f=foo; find . -type f -exec sh -c 'diff -q '{}' '"$f"' >/dev/null && echo '{} \;

# external comparison of image revisions
diff-img foo.png <(git show HEAD^:foo.png)

# binary diff
cmp -l 1 2
diff -Nauwq <(xxd 1) <(xxd 2)
```

# types

- text: `diff`
    - library: `diff-match-patch`
- binary: `dhex`
    - structured: `kaitai -> gron -> diff`
- image: `magick`
- audio: `chromaprint/src/cmd/fpcalc -> diff`
