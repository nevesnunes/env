# markdown

preserve whitespace: `+line_blocks`

- https://pandoc.org/MANUAL.html#pandocs-markdown

convert from html without empty tags or attributes:

```bash
pandoc --lua-filter="$HOME/code/snippets/pandoc/remove-attr.lua" --from=html --to=gfm-raw_html-native_divs-native_spans --wrap=none a.html -o a.md
```

### anchors

```markdown
<a name="foo">foo</a>
...
- [foo](#foo)
```

# Filters

- http://scorreia.com/software/panflute/
- https://stackoverflow.com/questions/40993488/convert-markdown-links-to-html-with-pandoc
- [How to convert markdown link to html using Pandoc · GitHub](https://gist.github.com/dixonsiu/28c473f93722e586e6d53b035923967c)

# Convert to word document with template

- https://opensource.com/article/19/5/convert-markdown-to-word-pandoc

# Styles processed

- [\-\-reference\-docx and \-\-reference\-odt doesn&\#39;t work · Issue \#2341 · jgm/pandoc · GitHub](https://github.com/jgm/pandoc/issues/2341)
- https://pandoc.org/MANUAL.html#options-affecting-specific-writers
- https://pandoc.org/MANUAL.html#fenced-code-blocks

# Common Styles

- First Paragraph

```bash
# Dependencies:
# pacman -S mingw-w64-x86_64-wkhtmltopdf-git
pandoc --from=markdown --to=html5 --self-contained -c ~/code/web/styles/github.css -o out.html foo.md
pandoc --from=markdown --to=html5 --self-contained -c ~/code/web/styles/github.css --pdf-engine-opt=--enable-local-file-access -o out.pdf foo.md
pandoc --from=markdown --to=odt --reference-odt=a.odt -o out.odt foo.md
pandoc --from=markdown --to=docx --reference-doc=a.docx -o out.docx foo.md

pandoc -t odt foo.md -o foo.odt
# || with template
pandoc --print-default-data-file reference.odt > custom-reference.odt
pandoc -t odt foo.md --reference-odt="$(realpath custom-reference.odt)" -o foo.odt
```

# Convert from word document

- [Convert a Word Document into MD · GitHub](https://gist.github.com/vzvenyach/7278543)

```bash
pandoc -f docx -t markdown -o test.md test.docx
# ||
unoconv -f html test.docx
pandoc -f html -t markdown -o test.md test.html

# From html with css
css_file=$(mktemp) && \
  awk 'BEGIN{print "<style type=\"text/css\">"} {print} END{print "</style>"}' ~/env-repo/common/code/web/styles/github.css > "$css_file" && \
  pandoc --from=html --to=html5 -H "$css_file" /tmp/a.html > /tmp/a2.html && \
  o /tmp /a2.html
```

# References

- https://devilgate.org/blog/2012/07/02/tip-using-pandoc-to-create-truly-standalone-html-files/
- https://superuser.com/questions/1349187/pandoc-how-to-get-pagebreak-between-title-block-and-the-table-of-contents
