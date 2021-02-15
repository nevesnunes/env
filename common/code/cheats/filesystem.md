# metadata

```bash
# modify creation time
inode_number=
debugfs -w -R "set_inode_field $inode_number crtime 200001010101.11" /dev/sdb1
```

- https://www.anmolsarma.in/post/linux-file-creation-time/

# memory-mapped temporary files

```bash
shm_dir=$(mktemp -p /dev/shm/)
dd if=/dev/zero of="$shm_dir" bs=500M count=1
# xref. `top` - used memory increased by 500M
# ref. https://superuser.com/questions/45342/when-should-i-use-dev-shm-and-when-should-i-use-tmp

mount -t tmpfs -o size=500M tmpfs /mnt/ramdisk
# ref. https://unix.stackexchange.com/questions/188536/how-to-make-a-temporary-file-in-ram

mknod -m 660 /dev/ramdisk b 1 1
chown root:disk /dev/ramdisk
dd if=/dev/zero of=/dev/ramdisk bs=1k count=4k
/sbin/mkfs -t ext2 -m 0 /dev/ramdisk 4096
mount -t ext2 /dev/ramdisk /mnt/ramdisk
# ref. http://surfer.nmr.mgh.harvard.edu/partition/ramdisk.html
```

# testing graceful degradation on constrained environment

```bash
mount -t tmpfs -o size=10M,nr_inodes=10,mode=700 tmpfs /mnt/low_nr_inodes_disk
```

# partitioning

```bash
sudo parted /dev/hdz
# print
# mkpart TYPE linux-swap START END

# || On error: unable to satisfy all constraints
sudo fdisk /dev/hdz
# || GPT
sudo gdisk /dev/hdz
# p => print
# n => new
# t => change partition type
# w => write changes
sudo mkfs -t vfat /dev/hdz1
# || NTFS, fast format
sudo mkntfs -f /dev/hdz1 --label foo

mkswap /dev/hdz2
swapon /dev/hdz2

# Validation:
cat /proc/swaps
# Filename  Type      Size    Used Priority
# /dev/hdz2 partition 2047996 0-2
cat /etc/fstab
# /dev/hdz2 swap swap defaults 0 0
```

- https://www.tldp.org/HOWTO/Partition/fdisk_partitioning.html

# Format/Flash USB disk

```bash
cfdisk -z /dev/sdX
```

# BIN/CUE

```bash
# Conversion
bin2iso input.cue
vcdgear -cue2raw input.cue output.iso
# From bin to iso+wav
bchunk -w input.bin input.cue output
```

- `.bin` and `.wav` filenames must match case-sensitive entries in `.cue`
    - http://syndicate.lubiki.pl/swars/html/swars_sounds_adding_cdaudio.php

# CD-ROM

```bash
# Conversion
iat -i input.img --iso -o output.iso
```

- Detection: ./reports/cdrom-detection.md
- Structure: physical sectors
- Take from: block device node (aka. block special file) (e.g. /dev/disk*)
- Yellow Book
    - Mode 1 - Chunks of data area (2352 bytes, defined in Red Book), with fields:
        - Sync: `00 ff ff ff ff ff ff ff ff ff ff 00`
        - Header: Sector Address (3 bytes) + Sector Mode (1 byte)
        - User Data: e.g. ISO9660 (2048 bytes)
        - Error Detection and Correction Codes (aka. Parity) (EDC + ECC) (4 + 284 bytes)
    - http://willcodeforfood.co.uk/Content/Notes/ISO9660.htm
    - http://www.cdfs.com/cdfs-color-books.html
    - https://www.ecma-international.org/publications/files/ECMA-ST/Ecma-130.pdf

# ISO

- Structure: logical sectors
- Take from: character device node (aka. character special file) (e.g. /dev/rdisk*)
    - https://linux-kernel-labs.github.io/refs/heads/master/labs/device_drivers.html
    - https://stackoverflow.com/questions/39613825/how-to-read-plain-data-sectors-mode1-from-a-cd-on-os-x
        - https://superuser.com/questions/631592/why-is-dev-rdisk-about-20-times-faster-than-dev-disk-in-mac-os-x/892768
- Non hybrid
    - Zeroed up to 0x8000 = System Area
        - 16 logical sectors, size = 0x800 (2048 bytes) or 2^n, whichever is larger, where n is the largest integer such that 2^n is less than, or equal to, the number of bytes in the Data Field of any sector recorded on the volume.
    - At 0x8000 = Primary Volume Descriptor
        - Version Number (1 byte)
        - Magic Bytes `43 44 30 30 31`
    - https://www.ecma-international.org/publications/files/ECMA-ST/Ecma-119.pdf
    - https://www.loc.gov/preservation/digital/formats/fdd/fdd000348.shtml
- ISO9660/HFS hybrid
    - Take first 0x600 bytes, zero the rest
        - At 0x200 chunks (512 bytes)
            - Magic Bytes `BD` = HFS Master Directory Block (MDB) (aka. super block)
    - ~/opt/isolyzer/testFiles/iso9660_hfs.iso
    - https://github.com/torvalds/linux/blob/master/fs/hfs/hfs.h
    - https://github.com/libyal/libfshfs/blob/master/documentation/Hierarchical%20File%20System%20(HFS).asciidoc
- Toast / Apple_HFS
    - At 0x0
        - Magic Bytes `45 52 02`
    - At 0x200 chunks (512 bytes)
        - Magic Bytes `PM` = Apple Partition Map (aka. new-type partition map)
    - https://en.wikipedia.org/wiki/Apple_Partition_Map#Layout
    - https://opensource.apple.com/source/IOStorageFamily/IOStorageFamily-116/IOApplePartitionScheme.h
    - https://developer.apple.com/library/archive/documentation/mac/Files/Files-99.html
    - http://fileformats.archiveteam.org/wiki/TOAST
- Sega Mega-CD
    - At 0x0
        - Header + Security Code (0x748 bytes)
    - buildscd.exe
        - FUN_00402180
    - https://www.retrodev.com/segacd.html
    - [How is data addressed in Sega CD programming? \(Archive\) \- Sega\-16 Forums](https://www.sega-16.com/forum/archive/index.php/t-29628.html)
    - [MagicEngine :: View topic \- ISO\-9660 PC Engine CD format](http://forums.magicengine.com/en/viewtopic.php?t=1619)

```bash
# Make
mkisofs -r -N -allow-leading-dots -d -J -T -o target.iso target

# Read
# For wine: Configure "$target-dir" in: winecfg > Drives > d: (Advanced > Type > CD-ROM)
mount -o loop -t iso9660 foo.iso "$target_dir"
# || Setup loop device
udisksctl loop-setup -r -f foo.iso

# Read ISO9660/HFS hybrid
mount -o loop -t hfs foo.iso

# Read files deleted in multi-session CD-ROM
# Identification: ksv ~/opt/isolyzer/testFiles/multisession.iso ~/opt/kaitai_struct/formats/filesystem/iso9660.ksy
mount /dev/cdrom /mnt/cdrom -t iso9660 -o session=0

# Extract files
bsdtar -C DESTINATION -xf foo.iso ISO_DIR
xorriso -osirrox on -indev foo.iso -extract ISO_DIR DESTINATION
isoinfo -J -x /ISO_DIR/FILE -i foo.iso > DESTINATION/FILE
7z x -oDESTINATION -i\!ISO_DIR foo.iso
```

- https://wiki.debian.org/ManipulatingISOs
- https://www.cgsecurity.org/wiki/CDRW

- ~/opt/isolyzer/README.md
- http://fileformats.archiveteam.org/wiki/ISO_9660
- https://wiki.osdev.org/ISO_9660
- http://bazaar.launchpad.net/~libburnia-team/libisofs/scdbackup/view/head:/doc/boot_sectors.txt

# ECM

```bash
ecm d input.img.ecm output.img
```

- [Romhacking\.net \- Utilities \- Command\-Line Pack v1\.03](https://www.romhacking.net/utilities/1440/)
    - [Romhacking\.net \- Community \- Neill Corlett](https://www.romhacking.net/community/99/)

# VHD

- `7z`
- `qemu-nbd`
    - https://stackoverflow.com/a/45280201/8020917
