# diff-bisect

[ ] bootstrap git repo
[ ] run diff on 2 files
    [ ] parse blocks of changed lines
    [ ] foreach block, create patch, apply patch, commit
[ ] run git-bisect

### handling structured data

! some issues require changing related but unmodified lines
=> ? mutate values based on element count
    xref. fuzzing
    e.g. 
    ```
    file1: <foo bar=3><!--3 elements--></foo>
    file2: <foo bar=3><!--9 elements--></foo>
    =>
    file3: <foo bar=9><!--9 elements--></foo>
    ```
