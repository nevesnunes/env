#!/bin/sh

echo "$*" \
  | grep -qiE "\[.*\]\(.*\)" \
  && printf '%s' "$*" \
  && exit 0

# Escape characters for markdown
title=$(curl --location --silent -- "$*" \
  | grep -iPo '(?<=<title>)(.*)(?=</title>)' \
  | sed 's/\[/(/g; s/\]/)/g; s/\([\|\*\.`_{}()#+-]\)/\\\1/g')

# Use basename without extension for non-url input
test -z "$title" \
  && title=$(basename -- "$*" \
  | sed 's/\.[^\.]*$//')

printf '%s' "[$title]($*)"
