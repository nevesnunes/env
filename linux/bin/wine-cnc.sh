#!/usr/bin/env sh

set -eux

iso_dir=$(set -- '/run/media/fn/'*'/FN-NUX/share/games/Command & Conquer' && \
  echo "$1")
[ -d "$iso_dir" ]
mount_dir=$(realpath ~/media/cdrom)
[ -d "$mount_dir" ]
wine_dir=$(realpath ~/share/wine32)
[ -d "$wine_dir" ]

mount | grep -q "$mount_dir" || \
  sudo mount -o loop "$iso_dir"/cnc-gdi.iso \
  "$mount_dir"
rm -f "$wine_dir"/dosdevices/d:
ln -fs "$mount_dir" \
  "$wine_dir"/dosdevices/d:
rm -f "$wine_dir"/dosdevices/d::
ln -fs "$iso_dir"/cnc-gdi.iso \
  "$wine_dir"/dosdevices/d::

env \
  WINEDLLOVERRIDES="ddraw=n,b" \
  WINEARCH=win32 \
  WINEPREFIX="$wine_dir" \
  schedtool -a 0x2 -e \
  wine /run/media/fn/FATSO/games/win/CNC95/C\&C95.EXE
