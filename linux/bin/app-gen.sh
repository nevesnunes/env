#!/usr/bin/env bash

file="${HOME}/.local/share/applications/${1}.desktop" 
cat >"$file" <<EOL
[Desktop Entry]
Name=${1}
Exec=${1}
Terminal=false
Type=Application
Categories=Application;
EOL
