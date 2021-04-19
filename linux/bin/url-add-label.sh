#!/bin/sh

echo "$*" \
  | grep -qiE "\[.*\]\(.*\)" \
  && printf '%s' "$*" \
  && exit 0

# Escape characters for markdown
# Alternative: (?<=<title>)(.*)(?=</title>)
# - Does not match title tags with attributes, but `grep` doesn't allow lookbehind assertion without fixed length, such as: (?<=<title[^>]*>)(.*)(?=</title>)
title=$(curl \
  -H 'User-Agent: Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:72.0) Gecko/20100101 Firefox/72.0' \
  --location \
  --silent \
  -- "$*" \
  | grep -m 1 -iPo '<title[^>]*>\K(.*)(?=</title>)' \
  | sed 's/\[/(/g; s/\]/)/g; s/\([\|\*\.`_{}()#+-]\)/\\\1/g')

# Use basename without extension for non-url input
test -z "$title" \
  && title=$(basename -- "$*" \
  | sed 's/\.[^\.]*$//')

printf '%s' "[$title]($*)"
