/usr/bin/udevil mount -o %o %v
/usr/bin/udisksctl mount --options %o --block-device %v

sudo udevadm control --log-priority=debug
udevadm monitor --property
udevadm info --attribute-walk "$DEVNAME"
udevadm test --action="add" "$DEVPATH"

pkaction -v --action-id org.freedesktop.udisks2.filesystem-mount 
pkaction -v --action-id org.freedesktop.udisks2.filesystem-mount-system
udisksctl monitor
udevadm info --export-db
cat /proc/self/mountinfo
cat /etc/fstab
