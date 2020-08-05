# markdown

preserve whitespace: +line_blocks
    https://pandoc.org/MANUAL.html#pandocs-markdown

convert from html without empty tags or attributes:

```bash
pandoc --lua-filter="$HOME/code/snippets/pandoc/remove-attr.lua" --from=html --to=gfm-raw_html-native_divs-native_spans --wrap=none a.html -o a.md
```
