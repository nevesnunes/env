#!/usr/bin/env sh

set -eu

ROFI_VERSION=$(rofi -version | sed 's/[^0-9]*\([0-9]*\.[0-9]*\).*/\1/g')
if [ "$(echo "$ROFI_VERSION >= 1.4" | bc)" = 1 ]; then
  exec rofi "$@" -matching fuzzy -theme ~/.local/share/themes/Uhita.rasi
else
  exec rofi "$@"
fi
