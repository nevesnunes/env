# disk-benchmarks

### Setup 1

- `sdb`: Toshiba Hard Disk (DT01ABA300, 5940 rpm) connected to USB3.0 hub
- `sdc`: SanDisk SSD (SD9SN8W512G) connected to USB2.0 hub

Benchmarks:

```bash
(cd /run/media/fn/TOSHIBA-EXT/ && fio --name benchmark --eta-newline=5s --rw=randwrite --size=60g --io_size=100g --blocksize=1024k --ioengine=libaio --fsync=10000 --iodepth=32 --direct=1 --numjobs=1 --runtime=300 --group_reporting > disk-benchmarks/rnd-w-toshiba_ext.txt)
(cd /run/media/fn/SanDisk SSD/ && fio --name benchmark --eta-newline=5s --rw=randwrite --size=60g --io_size=100g --blocksize=1024k --ioengine=libaio --fsync=10000 --iodepth=32 --direct=1 --numjobs=1 --runtime=300 --group_reporting > disk-benchmarks/rnd-w-sandisk_ssd.txt)

diff -Nauw <(grep IOPS rnd-w-toshiba_ext.txt) <(grep IOPS rnd-w-sandisk_ssd.txt) | tail -n +4
```

```diff
-  read: IOPS=10, BW=41.4KiB/s (42.4kB/s)(2484KiB/60034msec)
-  write: IOPS=11, BW=44.2KiB/s (45.3kB/s)(2656KiB/60034msec); 0 zone resets
+  read: IOPS=311, BW=1248KiB/s (1278kB/s)(73.1MiB/60001msec)
+  write: IOPS=312, BW=1249KiB/s (1279kB/s)(73.2MiB/60001msec); 0 zone resets
```

```bash
(cd /run/media/fn/TOSHIBA-EXT/ && fio --name benchmark --eta-newline=5s --rw=write --size=60g --io_size=100g --blocksize=1024k --ioengine=libaio --fsync=10000 --iodepth=32 --direct=1 --numjobs=1 --runtime=300 --group_reporting > disk-benchmarks/seq-w-toshiba_ext_usb3.txt)
(cd /run/media/fn/SanDisk SSD/ && fio --name benchmark --eta-newline=5s --rw=write --size=60g --io_size=100g --blocksize=1024k --ioengine=libaio --fsync=10000 --iodepth=32 --direct=1 --numjobs=1 --runtime=300 --group_reporting > disk-benchmarks/seq-w-sandisk_ssd_usb2.txt)

diff -Nauw <(grep IOPS seq-w-toshiba_ext_usb3.txt) <(grep IOPS seq-w-sandisk_ssd_usb2.txt) | tail -n +4
```

```diff
-  write: IOPS=95, BW=95.6MiB/s (100MB/s)(29.3GiB/313861msec); 0 zone resets
+  write: IOPS=46, BW=46.8MiB/s (49.1MB/s)(13.7GiB/300002msec); 0 zone resets
```

### Setup 2

- Repartition SSD with GPT instead of MBR

Benchmarks:

```bash
(cd /run/media/fn/SanDisk SSD/ && fio --name benchmark --eta-newline=5s --rw=write --size=60g --io_size=100g --blocksize=1024k --ioengine=libaio --fsync=10000 --iodepth=32 --direct=1 --numjobs=1 --runtime=300 --group_reporting > disk-benchmarks/seq-w-sandisk_ssd_gpt.txt)

diff -Nauw <(grep IOPS seq-w-sandisk_ssd.txt) <(grep IOPS seq-w-sandisk_ssd_gpt.txt) | tail -n +4
```

```diff
-  write: IOPS=46, BW=46.8MiB/s (49.1MB/s)(13.7GiB/300002msec); 0 zone resets
+  write: IOPS=47, BW=47.1MiB/s (49.4MB/s)(13.8GiB/300023msec); 0 zone resets
```

### Setup 3

- Both disks connected to USB3.0 hub

Benchmarks:

```bash
(cd /run/media/fn/TOSHIBA-EXT/ && fio --name benchmark --eta-newline=5s --rw=write --size=60g --io_size=100g --blocksize=1024k --ioengine=libaio --fsync=10000 --iodepth=32 --direct=1 --numjobs=1 --runtime=300 --group_reporting > disk-benchmarks/seq-w-toshiba_ext_usb3.txt)
(cd /run/media/fn/SanDisk SSD/ && fio --name benchmark --eta-newline=5s --rw=write --size=60g --io_size=100g --blocksize=1024k --ioengine=libaio --fsync=10000 --iodepth=32 --direct=1 --numjobs=1 --runtime=300 --group_reporting > disk-benchmarks/seq-w-sandisk_ssd.txt)

diff -Nauw <(grep IOPS seq-w-toshiba_ext_usb3_ext_hub.txt) <(grep IOPS seq-w-sandisk_ssd_gpt_usb3_ext_hub.txt) | tail -n +4
```

```diff
-  write: IOPS=131, BW=131MiB/s (137MB/s)(38.4GiB/300005msec); 0 zone resets
+  write: IOPS=391, BW=391MiB/s (410MB/s)(100GiB/261654msec); 0 zone resets
```

### Setup 4

- Hard Disk connected to USB2.0 hub

Benchmarks:

```bash
(cd /run/media/fn/TOSHIBA-EXT/ && fio --name benchmark --eta-newline=5s --rw=write --size=60g --io_size=100g --blocksize=1024k --ioengine=libaio --fsync=10000 --iodepth=32 --direct=1 --numjobs=1 --runtime=300 --group_reporting > disk-benchmarks/seq-w-toshiba_ext_usb2.txt)

diff -Nauw <(grep IOPS seq-w-toshiba_ext_usb2.txt) <(grep IOPS seq-w-toshiba_ext_usb3_ext_hub.txt)
```

```diff
-  write: IOPS=38, BW=38.2MiB/s (40.1MB/s)(11.2GiB/300001msec); 0 zone resets
+  write: IOPS=131, BW=131MiB/s (137MB/s)(38.4GiB/300005msec); 0 zone resets
```

### Validation

```bash
gdisk /dev/sdc
```

> Found valid GPT with protective MBR; using GPT.

```bash
lsusb | sort
```

Expect: same bus among devices

> Bus 003 Device 001: ID 1d6b:0003 Linux Foundation 3.0 root hub
> Bus 003 Device 004: ID 0781:558c SanDisk Corp. Extreme SSD

```bash
sudo smartctl --tolerance=permissive --all /dev/sdb
sudo smartctl --tolerance=permissive --all /dev/sdc --device=sat
```

> No Errors Logged
> [...]
> No self-tests have been logged.  [To run self-tests, use: smartctl -t]

```bash
sudo smartctl --tolerance=permissive --test=short /dev/sdb
# [After waiting suggested time...]
sudo smartctl --tolerance=permissive --all /dev/sdb > smartctl-toshiba_ext.txt
```

> SMART Self-test log structure revision number 1
> Num  Test_Description    Status                  Remaining  LifeTime(hours)  LBA_of_first_error
> # 1  Short offline       Completed without error       00%      4136         -

```bash
sudo smartctl --tolerance=permissive --test=short /dev/sdc --device=sat
# [After waiting suggested time...]
sudo smartctl --tolerance=permissive --all /dev/sdc --device=sat > smartctl-sandisk_ssd.txt
```

> SMART Self-test log structure revision number 1
> Num  Test_Description    Status                  Remaining  LifeTime(hours)  LBA_of_first_error
> # 1  Short offline       Completed without error       00%      1125         -

Versions:

- fio-3.19
- smartctl 7.1 2019-12-30 r5022 [x86_64-linux-5.6.19-300.fc32.x86_64] (local build)
