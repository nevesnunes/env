d=$DISPLAY
if [ -z "$d" ]; then
  d=$(ps aeux | \
    grep "^$(id -n -u).*DISPLAY=[\.0-9A-Za-z:]*" | \
    sed "s/.*DISPLAY=\([0-9A-Za-z:]*\).*/\1/g" | \
    head -n1)
fi
if [ -z "$d" ]; then
  echo "DISPLAY not set!"
  exit 1
fi
cat <<EOF >"$HOME/.local/share/systemd/env"
DBUS_SESSION_BUS_ADDRESS=/dev/null
DISPLAY=$d
PATH=/usr/local/nopshim:$PATH
EOF
