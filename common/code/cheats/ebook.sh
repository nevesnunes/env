#!/bin/sh

# Dump objects, streams
f=a.pdf && { \
  peepdf "$f" | \
  grep 'Objects ([0-9]*):' | \
  sed 's/.*\[\(.*\)\]/\1/; s/\([0-9]\+\)\(, \)\?/object \1\n/g' | \
  peepdf "$f" -i
} 2>/dev/null
f=a.pdf && { \
  peepdf "$f" | \
  grep 'Streams ([0-9]*):' | \
  sed 's/.*\[\(.*\)\]/\1/; s/\([0-9]\+\)\(, \)\?/stream \1\n/g' | \
  peepdf "$f" -i
} 2>/dev/null

# Fault-tolerant render
mutool draw -r 300 -o output.png

# Add bookmarks / outline / table of contents
djvused ./foo.djvu -e 'set-outline ./outline.txt' -s
k2pdfopt -mode copy -n -toclist ./toclist.txt ./foo.pdf -o ./output.pdf

# Merge
pdf-stapler sel ./*.pdf output.pdf
# ||
pdftk preface.pdf toc.pdf ch*.pdf index.pdf cat output book.pdf
