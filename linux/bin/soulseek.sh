#!/usr/bin/env sh

set -eux

preload=
for i in \
    libQt5Gui \
    libQt5Network \
    libQt5Multimedia \
    libQt5Widgets \
    libQt5XcbQpa \
    libQt5Core \
    libqxcb \
    ; do
  for path in \
      /usr/lib64/"$i".so.5 \
      /usr/lib64/"$i".so \
      /usr/lib/x86_64-linux-gnu/"$i".so.5 \
      /usr/lib/x86_64-linux-gnu/"$i".so \
      /usr/lib/x86_64-linux-gnu/qt5/plugins/platforms/"$i".so \
      ; do
    if [ -f "$path" ]; then
      preload="$preload $path"
      break
    fi
  done
done

exec env QT_DEBUG_PLUGINS=1 LD_PRELOAD="$preload $(realpath ~/opt/soulseek/lib/libQt5Core.so.5)" ~/opt/soulseek/SoulseekQt
