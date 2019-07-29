udisksctl power-off -b /dev/sdX

# ---

while read -r i; do
  sudo udisks --unmount "$i"
  sudo udisks --detach "${i//[0-9]/}"
  sleep 2
  sudo pm-suspend
done <<< "$(df | grep -io '/dev/sdb[0-9]')"

# ---

echo suspend > /sys/bus/usb/devices/the_usb_where_hdd_is_plugged_in_here/power/level
echo on > /sys/bus/usb/devices/the_usb_where_hdd_is_plugged_in_here/power/level
