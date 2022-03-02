#!/bin/sh

# Checks a markdown file for changes, converts to a html file, and serves it.

set -eu

session=$1
[ -n "$session" ]
shift
md_file=$(realpath "$*")
[ -f "$md_file" ]

# Avoid overwritting files from another running session.
[ ! -f index.html ]
lock_file=/tmp/lock.make-md.$session
[ ! -f "$lock_file" ]
touch "$lock_file"
trap 'rm -f ./index.html "$lock_file"; jobs -p | xargs -I{} kill {} 2>/dev/null' EXIT INT QUIT TERM

# Serve in same directory as source files to ensure 
# resources with relative paths are loaded.
cd "$(dirname "$md_file")"
python3 -m http.server 6080 &
firefox 'http://localhost:6080/index.html'

echo "$md_file" | entr -n pandoc --from=markdown --to=html5 --self-contained -c ~/code/web/styles/github.css /_ -o index.html
