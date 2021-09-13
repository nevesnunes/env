#!/bin/sh

command -v xdotool >/dev/null 2>&1 \
  && xdotool getactivewindow windowminimize

exec env \
  SRB2WADDIR="$HOME/games/unix/SRB2-v229-Full" \
  HOME="$HOME/games/data" \
  ~/games/unix/SRB2/bin/Linux64/Release/lsdl2srb2
