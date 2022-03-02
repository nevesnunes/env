# reports

- [disk-benchmarks](./reports/disk-benchmarks.md)

# force check

```bash
tune2fs -c199 -C200 /dev/sda1
# ||
sudo touch /forcefsck
```

# debug

```bash
# Monitor disk io [read, write]
iostat -dx
iotop -ao
pidstat -dl 20
auditctl -S sync -S fsync -S fdatasync -a exit,always
# Given: `procfs`
cat /proc/12345/vmstat
# Given: `blktrace`
btrace /dev/sdX

# Activity under load
dd if=/dev/zero of=/tmp/testfile count=1 bs=900M
sudo dd if=/dev/sda3 of=/dev/null count=3 bs=100M

# Activity on state changes
# Validation
hdparm -C /dev/sdb2
# unmount and prevent automatic mounts
systemctl stop udisks2
# standby
hdparm -y /dev/sdb2
# sleep
hdparm -Y /dev/sdb2

# Check driver handling disk
dmesg | grep sdb

# Trace
# References:
# - https://listman.redhat.com/archives/libvir-list/2011-February/msg01181.html
trace-cmd start \
    -p blk \
    -e workqueue_queue_work \
    -e workqueue_activate_work \
    -e workqueue_execute_start \
    -e workqueue_execute_end
echo 1 > /sys/block/sdb/trace/enable
# [...]
trace-cmd stop
trace-cmd extract
```

# monitor health/reliability (smart)

```bash
# Input: sudo fdisk -l
smartctl -A /dev/sda
# Expect: zero/low count for codes 1, 7, 195

# Track spindowns
smartctl -a /dev/sda | grep Load_Cycle_Count

# Track self-tests
# References:
# - https://unix.stackexchange.com/questions/202400/smartmontools-how-can-i-know-if-there-is-any-smartctl-test-running-on-my-hard-d
smartctl -a /dev/sda | grep execution
smartctl -c /dev/sda | grep execution

# Disable self-tests
# Note: 
# - Requires spin-down (e.g. standby mode) to stop current running self-test
# - Check which mode prevents spin-up by self-test daemon
# - Check if maximum number of skipped checks is set
#   - man smartd.conf
#   - /etc/smartmontools/smartd.conf
#     - DEVICESCAN -H -m root -M exec /usr/libexec/smartmontools/smartdnotify -n standby,10,q
# References:
# - https://forums.opensuse.org/showthread.php/467466-disabling-SMART-for-HDD-s
smartctl --smart=off /dev/sdb
systemctl stop smartd

# Time Limited Error Recovery (TLER) / Command Completion Time Limit (CCTL)
# - e.g. read retry timeout of 5s:
smartctl -l scterc,50,50 /dev/sda

# Avoid data link kernel timeout on long tests
# References:
# - https://superuser.com/questions/766943/smart-test-never-finishes
# - https://sourceforge.net/p/smartmontools/mailman/smartmontools-support/thread/539B7800.9040001@obluda.cz/
watch -d -n 60 smartctl -a /dev/sdb
# ||
while true; do dd if=/dev/sdb2 of=/dev/null count=1; sleep 60; done

# Alternative: Active scan
# - https://wiki.archlinux.org/title/badblocks#Read-write_test_(non-destructive)
badblocks -nsv /dev/sdaX
```

# power-saving

```bash
# Disable idle-spindown
for disk in /dev/sd?; do /sbin/hdparm -q -S 0 "$disk"; done

# Disable power management
for disk in /dev/sd?; do /sbin/hdparm -B 255 "$disk"; done
```

- [Bug \#952556 “\(Precise\) \(Hardware\-killer\) HD restarts every few s\.\.\.” : Bugs : hdparm package : Ubuntu](https://bugs.launchpad.net/ubuntu/+source/hdparm/+bug/952556)
- [Bug \#59695 “High frequency of load/unload cycles on some hard di\.\.\.” : Bugs : acpi\-support package : Ubuntu](https://bugs.launchpad.net/ubuntu/+source/acpi-support/+bug/59695)
    - https://ata.wiki.kernel.org/index.php/Known_issues#Drives_which_perform_frequent_head_unloads_under_Linux
    - http://paul.luon.net/journal/2005/11/24/broken-hdds/
        - https://listman.redhat.com/archives/fedora-list/2005-March/msg00463.html
- https://documents.westerndigital.com/content/dam/doc-library/en_us/assets/public/western-digital/product/internal-drives/wd-blue-hdd/data-sheet-wd-blue-pc-hard-drives-2879-771436.pdf
    - => Load_Cycle_Count < 300,000

# swap

- `top`: press `f` > select `SWAP`
- `htop`: press `S` > Columns > Available Columns > select `NSWAP` > press `F5`
