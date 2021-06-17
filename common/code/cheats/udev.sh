# Find all device paths for input devices (e.g. mouse, keyboard), take $DEVPATH
udevadm trigger --dry-run --verbose --subsystem-match=hid \
  | xargs -I{} udevadm test --action="change" {} 2>&1 \
  | grep '^run:' \
  | sort -u

# Take any device's ACTION, SUBSYSTEM, DEVTYPE...
sudo udevadm control --log-priority=debug
udevadm monitor --environment --udev
udevadm monitor --property

# Take given device's SUBSYSTEM, DRIVER, ATTR...
udevadm info --attribute-walk "$DEVPATH_OR_NAME"

# Validate matched rules
udevadm test --action="add" "$DEVPATH"

/usr/bin/udevil mount -o %o %v
/usr/bin/udisksctl mount --options %o --block-device %v

pkaction -v --action-id org.freedesktop.udisks2.filesystem-mount 
pkaction -v --action-id org.freedesktop.udisks2.filesystem-mount-system
udisksctl monitor
udevadm info --export-db
cat /proc/self/mountinfo
cat /etc/fstab
