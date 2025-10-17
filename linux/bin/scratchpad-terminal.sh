#!/usr/bin/env sh

SCRATCHPAD_TERMINAL_OLD_LC_ALL=$LC_ALL
export SCRATCHPAD_TERMINAL_OLD_LC_ALL
SCRATCHPAD_TERMINAL_OLD_LANG=$LANG
export SCRATCHPAD_TERMINAL_OLD_LANG
SCRATCHPAD_LANG=${SCRATCHPAD_LANG:-C}

if [ -n "$SCRATCHPAD_TERMINAL_ACTIVE" ]; then
  exec env LC_ALL="$SCRATCHPAD_LANG" LANG="$SCRATCHPAD_LANG" "$@"
fi

if command -v "$SCRATCHPAD_TERMINAL_EXE" > /dev/null 2>&1; then
  exe=$SCRATCHPAD_TERMINAL_EXE
else
  # Disfavour `gnome-terminal`, as it sets the title with too much delay, causing a race with `devilspie2`...
  for i in uxterm urxvt gnome-terminal; do
    if command -v "$i" > /dev/null 2>&1; then
      exe=$i
      break
    fi
  done
fi
if [ -z "$exe" ]; then
  exe=$(command -v user-terminal | xargs -n1 readlink)
fi

title=${SCRATCHPAD_TERMINAL_TITLE:-"scratchpad"}
if echo "$exe" | grep -qi gnome-terminal; then
  exec env SCRATCHPAD_TERMINAL_ACTIVE=1 LC_ALL="$SCRATCHPAD_LANG" LANG="$SCRATCHPAD_LANG" "$exe" --geometry "80x20+0+0" --title "$title" -- "$@"
else
  exec env SCRATCHPAD_TERMINAL_ACTIVE=1 LC_ALL="$SCRATCHPAD_LANG" LANG="$SCRATCHPAD_LANG" "$exe" -geometry "80x20+0+0" -title "$title" -e "$@"
fi
