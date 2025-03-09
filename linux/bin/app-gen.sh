#!/usr/bin/env sh

set -e

app=$1
name=${2:-$app}
cmd=${3:-$app}

file="${HOME}/.local/share/applications/$app.desktop"
cat >"$file" <<EOL
[Desktop Entry]
Name=$name
Exec=$cmd
Terminal=false
Type=Application
Categories=Application;
EOL
