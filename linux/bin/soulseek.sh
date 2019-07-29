#!/usr/bin/env sh

exec env LD_PRELOAD="/usr/lib64/libQt5Core.so /usr/lib64/libQt5XcbQpa.so.5 /usr/lib64/libQt5Widgets.so /usr/lib64/libQt5Multimedia.so.5 /usr/lib64/libQt5Network.so /usr/lib64/libQt5Gui.so ""$(realpath ~/opt/soulseek/lib/libQt5Core.so.5)" ~/opt/soulseek/SoulseekQt
