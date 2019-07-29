#!/usr/bin/env bash

set -eu

file_md=$1
file_css=$2

file_html="${file_md%.*}.html"
pandoc \
		--standalone \
		--toc \
		-V "toctitle:'Title'" \
		--self-contained \
		--to html5 \
		-H "$file_css" \
		-o "$file_html" "$file_md"
