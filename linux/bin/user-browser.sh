#!/usr/bin/env sh

if ! command -v user-browser; then
  for app in firefox chromium google-chrome; do
    cmd=$(command -v "$app")
    if [ -x "$cmd" ]; then
      ln -s "$cmd" ~/bin/user-browser
      break
    fi
  done
fi

# FIXME: For hi-res monitors: `exec env GDK_DPI_SCALE=1.5 user-browser`
exec user-browser
