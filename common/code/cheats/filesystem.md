# +

- [disk](./disk.md)
- [floppy](./floppy.md)

# debug

- Windows: [FileTest](http://www.zezula.net/en/fstools/filetest.html)

# metadata

```bash
# modify creation time
inode_number=
debugfs -w -R "set_inode_field $inode_number crtime 200001010101.11" /dev/sdb1
```

- https://www.anmolsarma.in/post/linux-file-creation-time/

```python
# If the filesystem resolution is 1 second, like Mac OS
# 10.12 Extended, or 2 seconds, like FAT32, and the editor
# closes very fast, require_save can fail. Set the modified
# time to be 2 seconds in the past to work around this.
os.utime(name, (os.path.getatime(name), os.path.getmtime(name) - 2))
# Depending on the resolution, the exact value might not be
# recorded, so get the new recorded value.
timestamp = os.path.getmtime(name)
```

- `click/_termui_impl.py`

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

# Fixing backup GPT
sfdisk -d /dev/sda > ./sda.part
sgdisk -e /dev/sda

# Add to filesystem table
# take $uuid
blkid /dev/sdaX
# if encrypted
echo "foo UUID=$uuid none" >> /etc/crypttab
# add
echo "UUID=$uuid /foo ext4 defaults 0 0 0" >> /etc/fstab
```

- https://www.tldp.org/HOWTO/Partition/fdisk_partitioning.html

### LVM

```sh
# List volume groups, take $vg
vgdisplay
# Activate all logical volumes in volume group
vgchange -ay $vg
# Validation
mount /dev/mapper/foo /mnt

# Recover from "can't read superblock"
vgchange -an $vg
vgchange -ay $vg

# Resize
lvextend -l +100%FREE /dev/vg/foo
e2fsck -f /dev/vg/foo
resize2fs /dev/vg/foo
# Validation
lvscan
```

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

- PS1 has subchannel data on sidecar file .sbi
    - [GitHub \- Kippykip/SBITools: Conversion between Sony PlayStation \.SBI LibCrypt files](https://github.com/Kippykip/SBITools)
    - [PSXSPX Specifications \- CDROM Protection \- LibCrypt](http://problemkaputt.de/psx-spx.htm#cdromprotectionlibcrypt)
    - [Subchannel data reading and CD copy protection Libcrypt\. · Issue \#21 · simias/rustation · GitHub](https://github.com/simias/rustation/issues/21)
        > So the actual contents of the Q subchannel data doesn't matter too much, you just need to single out the invalid sectors (using an sbi file or similar) and return the previous sector's info in GetLocP.
- .bin and .wav filenames must match case-sensitive entries in .cue
    - http://syndicate.lubiki.pl/swars/html/swars_sounds_adding_cdaudio.php

# CD-ROM

```bash
# Conversion
iat -i input.img --iso -o output.iso
```

- Detection: ./reports/cdrom-detection.md
- Structure: physical sectors
- Take from: block device node (aka. block special file) (e.g. `/dev/disk*`)
- Yellow Book
    - Mode 1 - Chunks of data area (2352 bytes, defined in Red Book), with fields:
        - Capacity: 650 MB = 74 minutes (4440 seconds) contained in 333000 blocks / sectors
        - Sync: `00 ff ff ff ff ff ff ff ff ff ff 00`
        - Header: Sector Address (3 bytes) + Sector Mode (1 byte)
        - User Data: 2048 bytes
            - e.g. ISO9660
        - Error Detection and Correction Codes (aka. Parity) (EDC + ECC) (4 + 284 bytes)
            - https://github.com/SonofUgly/PCSX-Reloaded/blob/master/libpcsxcore/ecm.h
            - https://github.com/john32b/cdcrush.net/blob/master/tools/docs/ecmtools/format.txt
    - https://cdrfaq.org/
    - http://willcodeforfood.co.uk/Content/Notes/ISO9660.htm
    - http://www.cdfs.com/cdfs-color-books.html
    - https://www.ecma-international.org/publications/files/ECMA-ST/Ecma-130.pdf
    - [GitHub \- carrotIndustries/redbook: Reading the Red Book – decoding Compact Disc Digital Audio](https://github.com/carrotIndustries/redbook)
- Virtual emulation compatibility with Red Book
    - Running: Virtual drive in position 0 (== `D:`)
    - Detection: Load CD in audio player
    - http://www.oldversion.com/windows/daemon-tools-3-47
    - http://www.magiciso.com/tutorials/miso-magicdisc-history.htm
    - Nero 5.5.10.20 Burning Rom + Image Drive
    - [\_inmm\.dll Tutorial &\#8211; Play Old PC Games](https://www.play-old-pc-games.com/compatibility-tools/_inmm-dll-tutorial/)
        - https://community.pcgamingwiki.com/files/file/107-patched-inmmdll/
        - http://forums.novelnews.net/showthread.php?t=6951
        - http://www.cd-2-dvd.com/modules.php?name=Forums&file=viewtopic&t=1244
    - [Age of Empires CD/A music without Daemon Tools? \\ VOGONS](https://www.vogons.org/viewtopic.php?t=55527)
    - [Emulation for Red Book Audio on Windows 7? \\ VOGONS](https://www.vogons.org/viewtopic.php?t=33095)
    - [Windows 98SE + Virtual CD Software + CD Audio \\ VOGONS](https://www.vogons.org/viewtopic.php?t=37592)
    - [Support for mixed mode CD images \(data \+ audio\) · Issue \#26 · sysprogs/WinCDEmu · GitHub](https://github.com/sysprogs/WinCDEmu/issues/26)
    - [Mixed Mode CD \- Wikipedia](https://en.wikipedia.org/wiki/Mixed_Mode_CD)
- Driver specifications
    - [SCSI Common Codes & Values](https://www.t10.org/lists/1spc-lst.htm)
    - [T10 Working Drafts](https://www.t10.org/drafts.htm#SPC_Family)
        - Sent via `IOCTL_SCSI_PASS_THROUGH`

### Reading all sectors / Skipping TOC

- Given swappable drive: Place CD with fake TOC, read TOC, stop drive motor, replace with target CD, start drive motor, resume rip
    - http://wiki.redump.org/index.php?title=GD-Rom_Dumping_Guide_(Old)#Method_B
    - http://wiki.redump.org/index.php?title=GD-Rom_Dumping_Guide
- TODO: patch cdrdao
    - ? overburn data
    > Copying data track 1 (MODE1_RAW): start 00:00:00, length 03:21:53 to "out.bin"...
- https://community.osr.com/discussion/95919/reading-raw-data-from-cd-dvd

### Empty files

> The reason PSX games have empty audio or data at the end is because the PSX lens assembly is a chunk of shit and has a very hard time reading where the disk ends if the game is under 30MB. This is why people started adding files like CDROM:/ZZZZZZZZ.ZZZ/Z.NULL that contains nothing but 30-300MB of 0x00's in it.
    - https://segaxtreme.net/threads/a-tad-bit-confused.5471

### Swapped bit-order

```bash
# Reference: [Rip my Tekken 2 Disc with Linux? \(CD Audio Noise\) \- Cybdyn Systems](https://www.cybdyn-systems.com.au/forum/viewtopic.php?t=2042)
cdrdao read-cd --read-raw --datafile data.bin --driver generic-mmc:0x20070 data.toc
```

# GD-ROM

1. Convert .bin/.cue to .gdi: [GitHub \- sirconan/gdi\-conversion: Convert Dreamcast Game images \(cue and bin files\) to GDI images in order to run on GDEMU\.](https://github.com/sirconan/gdi-conversion)
2. Mount .gdi: [GitHub \- snickerbockers/gdisofs: FUSE module for mounting Sega Dreamcast GD\-ROM images \(\.gdi format\)](https://github.com/snickerbockers/gdisofs)

# ISO

- Structure: logical sectors
- Take from: character device node (aka. character special file) (e.g. `/dev/rdisk*`)
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
- Bootable ISO
    - https://wiki.osdev.org/El-Torito
- [!] Does not store Red Book audio
    - Alternatives: .bin/.cue, .ccd/.img, .mds/.mdf, .nrg

```bash
# Make
mkisofs -r -J -T \
  -allow-leading-dots \
  -omit-version-number \
  -o foo.iso foo
# || more permissive
mkisofs -r -J -T \
  -allow-lowercase -allow-multidot -allow-leading-dots \
  -omit-version-number -omit-period \
  -o foo.iso foo

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

# Copy and fix permissions from image mounting
rsync -va --no-owner --no-group --include ".*" ./ "/home/$USER"
sudo chmod -R ug+rw "/home/$USER" "/home/$USER"/* "/home/$USER"/.*
sudo chown -R "$USER":"$USER" "/home/$USER" "/home/$USER"/* "/home/$USER"/.*
```

- https://wiki.debian.org/ManipulatingISOs
- https://www.cgsecurity.org/wiki/CDRW

- ~/opt/isolyzer/README.md
- http://fileformats.archiveteam.org/wiki/ISO_9660
- https://wiki.osdev.org/ISO_9660
- http://bazaar.launchpad.net/~libburnia-team/libisofs/scdbackup/view/head:/doc/boot_sectors.txt

# CCD

- .img == .bin without subchannel data

```bash
# Alternative: Take [SBITools](https://github.com/Kippykip/SBITools) `-cue2ccd` code and adapt to produce .cue
ccd2cue input.ccd > input.cue
# || Only data tracks, converted
ccd2iso input.img input.iso
iat -i input.img --iso -o output.iso
# || Only data tracks, mounted
mount -o loop input.img /foo
mkisofs -o output.iso /foo
```

# NRG / Other disk image formats

- [WINUAE \- blkdev_cdimage](https://github.com/tonioni/WinUAE/blob/1e31b33f83e84436a42531969ec411c7b63e5c48/blkdev_cdimage.cpp#L1870)
- [BizHawk \- NRG_format](https://github.com/TASEmulators/BizHawk/blob/ee182499535062473e3abd0854285df7f3cd12e4/src/BizHawk.Emulation.DiscSystem/DiscFormats/NRG_format.cs)
- [GitHub \- aaru\-dps/Aaru: Aaru Data Preservation Suite](https://github.com/aaru-dps/Aaru)
- [Joe Balough / nerorip · GitLab](https://gitlab.com/scallopedllama/nerorip)
- [NRG \(file format\) \- Wikipedia](https://en.wikipedia.org/wiki/NRG_(file_format))

```bash
# Using virtual drive
# - git clone https://git.code.sf.net/p/cdemu/code cdemu-code
# Ubuntu
add-apt-repository ppa:cdemu/ppa
apt-get update
apt-get install cdemu-daemon cdemu-client gcdemu
# Fedora
dnf copr enable rok/cdemu
dnf install cdemu-daemon cdemu-client gcdemu

akmods
systemctl restart systemd-modules-load.service
cdemu status
cdemu load 0 foo.cue

# - svn checkout https://svn.code.sf.net/p/fuseiso/code/trunk fuseiso-code
fuseiso -p foo.bin ./mnt
fusermount -u ./mnt

# Alternative: Using physical drive
# 1. Using Nero Linux, burn NRG image to CD
# 2. Load and mount CD, then create BIN/CUE image
# References:
# - https://www.emaculation.com/forum/viewtopic.php?t=10220&start=25
# - https://github.com/denisleroy/cdrdao/blob/master/README
cdrdao scanbus # take device name
cdrdao read-cd --read-raw --datafile out.bin --device /dev/cdrom out.toc
# If audio data is not big endian samples
cdrdao read-cd --read-raw --datafile out.bin --driver generic-mmc:0x20000 --device /dev/cdrom out.toc
# If subchannel data should be included in .bin
cdrdao read-cd --read-raw --read-subchan rw_raw --datafile out.bin --device /dev/cdrom out.toc

toc2cue out.toc out.cue

# Alternative: nrg2iso, ultraiso
```

# ECM

```bash
ecm d input.img.ecm output.img
```

- [Romhacking\.net \- Utilities \- Command\-Line Pack v1\.03](https://www.romhacking.net/utilities/1440/)
    - [Romhacking\.net \- Community \- Neill Corlett](https://www.romhacking.net/community/99/)

# CD-ROM XA extenstion

- Mode 2 Form 2
    - User Data: 2324 bytes
        - e.g. Video CD (White Book)
    - Capacity: 
        - 738 MB = 74 minutes contained in 333000 blocks / sectors
        - 796 MB = 80 minutes contained in 360000 blocks / sectors
        > VCDs can hold that much more data becasue the .mpg stream has its own built in safeguards against corruption. They use MODE 2 FORM 2 cd sectors that sacrifice data integrity for space.
        > Iso 9660 formatting requires that DATA including .avis be written with MODE 1 / MODE 2 FORM 1 sectors that have full error checking and correction.
            - https://forum.videohelp.com/threads/63493-800-mb-on-a-700-mb-cd
    - https://retrocomputing.stackexchange.com/questions/13733/what-was-the-purpose-of-exotic-modes-and-sectors-for-cd-rom

# qcow

```bash
sudo modprobe nbd
sudo qemu-nbd -c /dev/nbd0 foo.qcow
sudo partx -l /dev/nbd0
sudo mount /dev/nbd0p1 ~/media/disk/

# teardown
sudo qemu-nbd -d /dev/nbd0
```

# vmdk / vhd / vdi

- `7z`
- `qemu-nbd`

```bash
sudo modprobe nbd
sudo qemu-nbd -c /dev/nbd1 ./foo.vdi
sudo qemu-nbd -r -c /dev/nbd1 ./foo.vmdk
```

# ova

```bash
tar -tf foo.ova
tar -xvf foo.ova
```

# raw images

- `7z`
- `loop` block devices

```bash
sudo losetup /dev/loop0 foo.disk
sudo partprobe /dev/loop0
sudo mount -o rw /dev/loop0p1 /mnt/foo

# teardown
sudo losetup -d /dev/loop0
# ||
sudo modprobe -r loop && sudo modprobe loop

# validation
sudo losetup -a  # no entry for /dev/loop0
```

# initial ramdisk (initrd)

```bash
# extract
gzip -dc initrd | cpio -idv --no-absolute-filenames
```

# ntfs

- https://sec-consult.com/blog/detail/pentesters-windows-ntfs-tricks-collection/

# ext4

```sh
# casefold
# - https://www.collabora.com/news-and-blog/blog/2020/08/27/using-the-linux-kernel-case-insensitive-feature-in-ext4/
mkfs -t ext4 -O casefold /dev/vda
# validation
cat /sys/fs/ext4/features/casefold
cat /sys/fs/unicode/version
dumpe2fs -h /dev/vda | grep 'Filesystem features'
mount /dev/vda /mnt; dmesg
# alternative
truncate -s 10G foo.img
mkfs.ext4 foo.img
```

# overlayfs

```sh
sudo mount -t overlay overlay
    -o lowerdir=lower,upperdir=upper,workdir=work
    merged

echo > merged/new_file
ls */new_file
# merged/new_file
# upper/new_file
```

# benchmarking

- [File system performance benchmarking \| GitLab](https://docs.gitlab.com/ee/administration/operations/filesystem_benchmarking.html)

# case studies

- [How does tup use fuse exactly?](https://groups.google.com/g/tup-users/c/LckKoIJFN7k)
- [GitHub \- elfshaker/elfshaker: elfshaker stores binary objects efficiently](https://github.com/elfshaker/elfshaker)
