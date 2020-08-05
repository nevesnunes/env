#!/bin/sh

# dump objects, streams
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
