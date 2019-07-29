
PID=$(pgrep -o gnome-session -u "USER")
export DBUS_SESSION_BUS_ADDRESS=$(sudo grep -z DBUS_SESSION_BUS_ADDRESS /proc/$PID/environ|cut -d= -f2-)
