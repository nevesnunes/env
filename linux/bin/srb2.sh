#!/bin/sh

exec env \
  SRB2WADDIR="$HOME/games/unix/SRB2-v229-Full" \
  HOME="$HOME/games/data" \
  ~/games/unix/SRB2/bin/Linux64/Release/lsdl2srb2
