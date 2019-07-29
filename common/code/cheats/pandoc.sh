# Convert to word document with template
# https://opensource.com/article/19/5/convert-markdown-to-word-pandoc

# Styles processed
# https://github.com/jgm/pandoc/issues/2341
# https://pandoc.org/MANUAL.html#options-affecting-specific-writers

# Common Styles
# - First Paragraph

pandoc -t odt filename.md -o filename.odt
# vs
pandoc --print-default-data-file reference.odt > custom-reference.odt
pandoc -t odt file-name.md --reference-odt="$(realpath custom-reference.odt)" -o file-name.odt

# Convert from word document
# https://gist.github.com/vzvenyach/7278543

pandoc -f docx -t markdown -o test.md test.docx
# ||
unoconv -f html test.docx
pandoc -f html -t markdown -o test.md test.html
