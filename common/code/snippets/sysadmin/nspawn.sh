systemd-nspawn --setenv=DISPLAY=:0 \
    --setenv=XAUTHORITY=~/.Xauthority \
    --bind-ro=$HOME/.Xauthority:/root/.Xauthority \
    --bind=/tmp/.X11-unix \
    -D ~/containers/firefox \
    firefox
