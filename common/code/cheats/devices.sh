# KERNEL=="ttyACM*", ATTRS{idVendor}=="2341", NAME="network_interface"
# SYMLINKS+=...
udevadm test "$(udevadm info -q path -n /dev/ttyACM0)"

# https://unix.stackexchange.com/questions/25776/detecting-headphone-connection-disconnection-in-linux

cat > /etc/systemd/system/systemd-udev-monitor.service <<EOF
[Unit]
Description=udev Monitoring
DefaultDependencies=no
Wants=systemd-udevd.service
After=systemd-udevd-control.socket systemd-udevd-kernel.socket
Before=sysinit.target systemd-udev-trigger.service

[Service]
Type=simple
ExecStart=/usr/bin/sh -c "/usr/sbin/udevadm monitor --udev --env > /udev_monitor.log"

[Install]
WantedBy=sysinit.target
EOF
