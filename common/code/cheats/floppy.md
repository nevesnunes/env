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
