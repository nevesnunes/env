# reports

- [disk-benchmarks](./reports/disk-benchmarks.md)

# monitor health/reliability

```bash
# Input: sudo fdisk -l
sudo smartctl -A /dev/sda
# Expect: zero/low count for codes 1, 7, 195
```

# force check

```bash
tune2fs -c199 -C200 /dev/sda1
# ||
sudo touch /forcefsck
```

# swap

top - press `f` > select `SWAP`
htop - press `S` > Columns > Available Columns > select `NSWAP` > press `F5`

# debug

```bash
# monitor disk io [read, write]
iostat -dx
iotop -ao
pidstat -dl 20
auditctl -S sync -S fsync -S fdatasync -a exit,always

cat /proc/12345/vmstat

# package = blktrace
btrace /dev/sdX

# activity/load
dd if=/dev/zero of=/tmp/testfile count=1 bs=900M
sudo dd if=/dev/sda3 of=/dev/null count=3 bs=100M

# Time Limited Error Recovery (TLER) / Command Completion Time Limit (CCTL)
# - e.g. read retry timeout of 5s:
smartctl -l scterc,50,50 /dev/sda
```

# power-saving

```bash
# Track spindowns
smartctl -a /dev/sda | grep Load_Cycle_Count

# Disable idle-spindown
for disk in /dev/sd?; do /sbin/hdparm -q -S 0 "$disk"; done

# Disable power management
for disk in /dev/sd?; do /sbin/hdparm -B 255 "$disk"; done
```

- [Bug \#952556 “\(Precise\) \(Hardware\-killer\) HD restarts every few s\.\.\.” : Bugs : hdparm package : Ubuntu](https://bugs.launchpad.net/ubuntu/+source/hdparm/+bug/952556)
