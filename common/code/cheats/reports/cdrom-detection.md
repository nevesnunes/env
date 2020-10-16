# cdrom-detection

Consider a disk image that fails to be mounted:

```bash
sudo mount -o loop foo.iso ~/media/cdrom/
# mount: /home/foo/media/cdrom: wrong fs type, bad option, bad superblock on /dev/loop0, missing codepage or helper program, or other error.
```

In this case, the file is actually a Yellow Book CD-ROM Mode 1 image. Detection is poor among common file type detection tools. The following files were tested:

- foo.iso: Base CD-ROM image
- foo.iso-chunk-10-1C5B4F2F: Removed first Synchronization Field (0x10 bytes)
- foo.iso-chunk-9300-1C5B4F2F: Removed bytes up to System Area
- foo.iso-zeroed: Removed bytes up to System Area, concatenated after 0x8000 null bytes
- foo.iso-iat: ISO 9660 image output by `iat`

```bash
file -k foo.iso
# foo.iso: data
binwalk foo.iso
# 4880          0x1310          ISO 9660 Primary Volume,
ksv foo.iso ~/opt/kaitai_struct/formats/filesystem/iso9660.ksy
# Unexpected fixed contents: got 00 00 00 00 00, was waiting for 43 44 30 30 31

file -k foo.iso-chunk-10-1C5B4F2F
# foo.iso-chunk-10-1C5B4F2F: ISO 9660 CD-ROM filesystem data (raw 2352 byte sectors)
# Apple Driver Map, blocksize 512, blockcount 808482, devtype 1, devid 1, driver count 0, contains[@0x200]: Apple Partition Map, map block count 2, start block 1, block count 2, name MRKS, type Apple_partition_map, valid, allocated, readable, contains[@0x400]: Apple Partition Map, map block count 2, start block 5408, block count 803074, name Toast 3.5.5J PPC HFS Optimizer, type Apple_HFS, valid, allocated, readable dBase III DBT, version number 0, next free block index 152133, 1st item "PM"
binwalk foo.iso-chunk-10-1C5B4F2F
# 4864          0x1300          ISO 9660 Primary Volume,

file -k foo.iso-chunk-9300-1C5B4F2F
# foo.iso-chunk-9300-1C5B4F2F: data
binwalk foo.iso-chunk-9300-1C5B4F2F
# 49434         0xC11A          Ubiquiti firmware header, third party, ~CRC32: 0x0, version: "=Foo.EXE"
# 51760         0xCA30          Microsoft executable, portable (PE)
# 52418         0xCCC2          Copyright string: "Copyright 1988-1995 Apple Computer Inc. All Rights Reserved."
# [...]

file -k foo.iso-zeroed
# foo.iso-zeroed: ISO 9660 CD-ROM filesystem data 'FOO'
binwalk foo.iso-zeroed
# 0             0x0             ISO 9660 Primary Volume,

file -k foo.iso-iat
# foo.iso-iat: ISO 9660 CD-ROM filesystem data 'FOO'
# Apple Driver Map, blocksize 512, blockcount 808482, devtype 1, devid 1, driver count 0, contains[@0x200]: Apple Partition Map, map block count 2, start block 1, block count 2, name MRKS, type Apple_partition_map, valid, allocated, readable, contains[@0x400]: Apple Partition Map, map block count 2, start block 5408, block count 803074, name Toast 3.5.5J PPC HFS Optimizer, type Apple_HFS, valid, allocated, readable dBase III DBT, version number 0, next free block index 152133, 1st item "PM"
binwalk foo.iso-iat
# 0             0x0             ISO 9660 Primary Volume,
```

The difference between a CD-ROM image and an ISO image is only evidenced with `iat`, althought it only references technical details, without specifying the underlying file format:

```bash
diff -au <(iat --debug -i foo.iso) <(iat --debug -i foo.iso-iat)
```

Output:

```diff
 Iso9660 Analyzer Tool v0.1.7
 Pregap	: (0)
-Block	: (2352)
-Size	: (475746096) bytes
-Mode 1 at (0)	00:02:00
+Block	: (2048)
+Size	: (414255104) bytes
 TYPE		: (1)
 ID		: CD001
 VERSION		: (1)
```
