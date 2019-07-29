#!/bin/bash

if [ -t 0 ]; then
	SUDO=sudo
else
	SUDO="gksu -u $(whoami)"
fi
echo $SUDO
set -e

DEST=/mnt/stor/vm/skype

if [ ! -d "$DEST" ];then
    $SUDO mkdir -p "$DEST/var/lib/pacman/";
    echo $SUDO skype lib32-gtk2 | $SUDO pacman --arch x86_64 --root "$DEST" --cachedir /var/cache/pacman/pkg --config /etc/pacman.conf -Sy - --noconfirm
    $SUDO systemd-nspawn -D "$DEST" groupadd skype
    $SUDO systemd-nspawn -D "$DEST" useradd -g skype -G video,audio skype
    $SUDO mkdir -p $DEST/home/skype/.config/pulse
    $SUDO cp ~/.config/pulse/cookie $DEST/home/skype/.config/pulse/
    $SUDO cp ~/.Xauthority $DEST/home/skype/
    $SUDO chmod 755 -R $DEST/home/skype/
    $SUDO chown -R 1000:1000 $DEST/home/skype/
fi

$SUDO systemd-nspawn -D "$DEST" \
    --bind=/tmp/.X11-unix \
    --bind=/run/user/1000/pulse \
    --bind=/dev/snd \
    --bind=/dev/video0 \
    --bind=/etc/machine-id \
    --bind=/dev/shm \
    --share-system sudo \
    -u skype \
    env DISPLAY=:0 PULSE_SERVER=unix:/run/user/1000/pulse/native skype
