#!/bin/sh

target=${1:-/tmp/1}

(trap 'rm -f "$target"' EXIT INT QUIT TERM && \
  vim "$target" && \
  pandoc \
    --wrap=none \
    --from html \
    --to "$(printf '%s+' \
        markdown_strict \
        ascii_identifiers-auto_identifiers \
        backtick_code_blocks \
        blank_before_header \
        blank_before_blockquote \
        multiline_tables | \
        sed 's/.$//')" \
    "$target" | \
  vim -)
