#!/usr/bin/env bash

set -eu

[ -f "$1" ]

file="out.html" 
cat >"$file" <<EOL
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
</head>
<body>
EOL

while read -r i; do
  echo "$i" >>"$file"
  echo "<hr>" >>"$file"
done < "$1"

cat >>"$file" <<EOL
</body>
</html>
EOL
