#!/bin/sh

export PATH=/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin:$HOME/.local/bin
exec env GTK2_RC_FILES=$HOME/.local/share/themes/Adwaitix-Dark/gtk-2.0/gtkrc GTK_THEME=Adwaita:dark viewnior "$@"
