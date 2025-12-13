# read raw disk image

```bash
mount -t vfat data.img mnt
```

# copy, dump, rip

```bash
# Preconditions:
# - Floppy controller enabled in BIOS
modprobe floppy
mcopy "a:*" .
# Alternatives:
# - [!] Requires merging multiple passes, keeping non-null bytes (i.e. keeping bytes read correctly)
dd if=/dev/fd0 of=out.img conv=noerror,sync iflag=fullblock
# - Block size given by: `badblocks -v /dev/sdb`
dd if=/dev/fd0 of=out.img bs=512 conv=noerror,sync
# - Supports multiple passes
#     - [!] 4 passes ~= 25min
ddrescue -d -r4 /dev/fd0 out.img ddrescue.out.log

# For custom format, e.g. /etc/mediaprm
floppycontrol --resetnow 2
fdrawcmd recalibrate 0
setfdprm /dev/fd0 sect=8 hd ssize=1024 cyl=77
dd if=/dev/fd0 bs=2048 count=616 of=out.img

# Repair
dosfsck data.img
# Alternatives:
# - Norton Utilities 8.0
DISKTOOL /REVIVE

# From DiskDupe image
dd if=image.ddi of=/dev/floppy0 skip=18
# Alternatives:
# - [GitHub \- SergiyKolesnikov/ddi2raw: ddi2raw converts a floppy disk image in DDI \(DiskDupe\) format to a raw floppy disk image\.](https://github.com/SergiyKolesnikov/ddi2raw)
```

Validation (`mcopy`):

```strace
openat(AT_FDCWD, "/dev/fd0", O_RDONLY|O_EXCL) = 3
read(3, "\353<\220MSDOS5.0\0\2\2\1\0\2p\0\240\5\371\3\0\t\0\2\0\0\0\0\0"..., 256) = 256
```

Error (`dd` without `conv` options):

```strace
openat(AT_FDCWD, "/dev/fd0", O_RDONLY)  = 3
dup2(3, 0)                              = 0
close(3)                                = 0
lseek(0, 0, SEEK_CUR)                   = 0
openat(AT_FDCWD, "1", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 3
dup2(3, 1)                              = 1
close(3)                                = 0
mmap(NULL, 143360, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f3be0a1f000
[...]
read(0, "\241`y\1\0=\16\2\0\0u\24\213\25\342\221\1\0\301\372\20\211\323\301\343\4)\323\1\333\353\2"..., 131072) = 131072
write(1, "\241`y\1\0=\16\2\0\0u\24\213\25\342\221\1\0\301\372\20\211\323\301\343\4)\323\1\333\353\2"..., 131072) = 131072
read(0, "0Q\4\0\270\1\0\0\0\203\304\4Z\3031\300Z\303\213\300\203\370\6u\37f\241\2527\2\0f"..., 131072) = 86016
write(1, "0Q\4\0\270\1\0\0\0\203\304\4Z\3031\300Z\303\213\300\203\370\6u\37f\241\2527\2\0f"..., 86016) = 86016
read(0, 0x7f3be0a20000, 131072)         = -1 EIO (Input/output error)
```

- https://superuser.com/questions/1442751/maxiumum-recovery-of-data-from-old-floppy-discs-with-padded-bad-sectors-and-mult

# flux imaging

- [A Guide to Imaging Obscure Floppy Disk Formats](https://zenodo.org/records/13828372)
- [Greaseweazle \| The Decromancer](https://decromancer.ca/greaseweazle/)
- [Pauline, universal Floppy Disk Reader / Simulator \- Share Project \- PCBWay](https://www.pcbway.com/project/shareproject/Pauline__universal_Floppy_Disk_Reader___Simulator.html)

# formats

- 1.44MB 3.5in (IBM)
    - 512 bytes/sector, 1x density, 18 sectors/track, 80 tracks/size
    - 1024 bytes/sector, 2x density, 9 sectors/track, 80 tracks/size
    - `512*2*80*18 = 1474560`
- 1.25MB 3.5in (PC98/X68000)
    - 1024 bytes/sector
    - requires 3-Mode floppy-disk drive
        - http://www.amazon.com/Sony-PCGA-UFD5-VAIO-Floppy-Drive/dp/B00006HNH0
        - https://gamesx.com/wiki/doku.php?id=x68000:writing_3.5_floppies
- [Norsk Data](https://www.ndwiki.org/wiki/ND_floppy_disks)
    - 1024 bytes/sector, 2x density, 8 sectors/track, 77 tracks/side => total capacity 616 pages
    - `1024*2*8*77 = 1261568`
- [List of floppy disk formats \- Wikipedia](https://en.wikipedia.org/wiki/List_of_floppy_disk_formats)

```sh
ufiformat -i /dev/sdb
```

# connections

- 34-pin 5-connector ribbon cable
    - at end: drive letter = a
    - at middle: drive letter = b
- 4-pin white connector from power supply

# case studies

bad reads:

```diff
                   0x0: eb3c905472616365725354000201010002e000400bf00900120002000000 [...] f6f6f6f6f6f6f6f6f6f6 | b'\xeb<\x90TracerST\x00\x02\x01\x01\x00\x02\xe0\x00@\x0b\xf0\t\x00\x12\x00\x02\x00\x00\x00' [...] b'\xf6\xf6\xf6\xf6\xf6\xf6\xf6\xf6\xf6\xf6' [+ 1286104 byte(s)]
-             0x13a000: 000000000000000000000000000000000000000000000000000000000000 [...] 00000000000000000000 | b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' [...] b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' [+ 114648 byte(s)]
+             0x13a000: f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6 [...] f6f6f6f6f6f6f6f6f6f6 | b'\xf6\xf6\xf6\xf6\xf6\xf6\xf6\xf6\xf6\xf6\xf6\xf6\xf6\xf6\xf6\xf6\xf6\xf6\xf6\xf6\xf6\xf6\xf6\xf6\xf6\xf6\xf6\xf6\xf6\xf6' [...] b'\xf6\xf6\xf6\xf6\xf6\xf6\xf6\xf6\xf6\xf6' [+ 114648 byte(s)]
              0x156000: f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6 [...] f6f6f6f6f6f6f6f6f6f6 | b'\xf6\xf6\xf6\xf6\xf6\xf6\xf6\xf6\xf6\xf6\xf6\xf6\xf6\xf6\xf6\xf6\xf6\xf6\xf6\xf6\xf6\xf6\xf6\xf6\xf6\xf6\xf6\xf6\xf6\xf6' [...] b'\xf6\xf6\xf6\xf6\xf6\xf6\xf6\xf6\xf6\xf6' [+ 73688 byte(s)]
```

```
dd: error reading '/dev/fd0': Input/output error
0+0 records in
0+0 records out
0 bytes copied, 4.72931 s, 0.0 kB/s

read(0, 0x55853375d000, 2048)           = -1 EIO (Input/output error)

# getfdprm /dev/fd0
get geometry parameters: No such device

openat(AT_FDCWD, "/dev/fd0", O_ACCMODE) = 3
ioctl(3, FDGETPRM, 0x5555abd2f2c0)      = -1 ENODEV (No such device)

# fdrawcmd recalibrate 0
raw cmd: Operation not supported

openat(AT_FDCWD, "/dev/fd0", O_ACCMODE|O_NONBLOCK) = 3
ioctl(3, FDRAWCMD, 0x7fff93c2b540)      = -1 EOPNOTSUPP (Operation not supported)
```
