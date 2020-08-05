# reports

[disk-benchmarks](./reports/disk-benchmarks.md)

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
iostat -dx
sudo iotop -ao

cat /proc/12345/vmstat

# package = blktrace
btrace /dev/sdX

# activity/load
dd if=/dev/zero of=/tmp/testfile count=1 bs=900M
sudo dd if=/dev/sda3 of=/dev/null count=3 bs=100M
```


