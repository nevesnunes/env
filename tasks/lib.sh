#!/bin/sh

sync_debian_packages() {
  sudo apt update
  sudo apt install -y $(paste -sd' ' "$1")
}

sync_python_packages() {
  pip install --user --upgrade pip
  pip install --user $(paste -sd' ' "$1")
}

sync_git() {
  while read -r i; do
    target=$HOME/$(echo "$i" | cut -d':' -f1)
    url=$(echo "$i" | sed 's/[ \t\/]*$//g')
    repo=$(echo "$url" | cut -d':' -f2-)
    name=$(echo "${url##*/}" | sed 's/\.git$//g')
    mkdir -p "$target"
    cd "$target"
    if [ ! -d "$name" ]; then
      git clone --depth=1 "$repo" "$name"
    else
      cd "$name" && git pull && git fetch --tags
    fi
  done < "$1"
}
