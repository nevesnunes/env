#!/usr/bin/env sh

SCRATCHPAD_TERMINAL_OLD_LC_ALL=$LC_ALL
export SCRATCHPAD_TERMINAL_OLD_LC_ALL
SCRATCHPAD_TERMINAL_OLD_LANG=$LANG
export SCRATCHPAD_TERMINAL_OLD_LANG
SCRATCHPAD_LANG=${SCRATCHPAD_LANG:-C}

title=${SCRATCHPAD_TERMINAL_TITLE:-"scratchpad"}
if [ -n "$SCRATCHPAD_TERMINAL_ACTIVE" ]; then
  exec env LC_ALL="$SCRATCHPAD_LANG" LANG="$SCRATCHPAD_LANG" "$@"
elif readlink "$(command -v user-terminal)" | grep -qi gnome-terminal; then
  exec env SCRATCHPAD_TERMINAL_ACTIVE=1 LC_ALL="$SCRATCHPAD_LANG" LANG="$SCRATCHPAD_LANG" gnome-terminal --geometry "80x20+0+0" --title "$title" -- "$@"
else
  exec env SCRATCHPAD_TERMINAL_ACTIVE=1 LC_ALL="$SCRATCHPAD_LANG" LANG="$SCRATCHPAD_LANG" urxvt -geometry "80x20+0+0" -title "$title" -e "$@"
fi
