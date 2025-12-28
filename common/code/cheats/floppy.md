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

```sh
# sanity checks
gw info
gw reset
gw seek --drive 0 0
gw seek --drive 0 79
gw seek --drive 0 80

# 2 sides, 80 tracks
gw read --tracks c=0-80:h=0-1 output.scp

# verify format but dump raw with higher sampling and retries
gw read --revs 5 --seek-retries 2 --format=ibm.1440 output.scp --raw

# validate
hxcfe -finput:input.scp -list

# convert
gw convert --format=ibm.1200 input.scp output.img
hxcfe -finput:input.scp -conv:AMSTRADCPC_DSK -foutput:output.dsk
```

- "Command Failed: GetFluxStatus: No Index"
    - Floppy not inserted;
    - Density Select set low: `gw pin 2 L`;
    - Pull-up resistors on drive outputs;
- https://github.com/keirf/greaseweazle/issues/425#issuecomment-2053168608
    > 5 1/4" section of my floppy combo drive had some initial "unknown mark" related problems and missing sectors due to the fact it hasn't been used in a good while. After setting the --revs option to around 50 to 100, it started to get the hang of it by getting back into sync

- [A Guide to Imaging Obscure Floppy Disk Formats](https://zenodo.org/records/13828372)
- [Publication: advanced disc archiving guide \- stardot\.org\.uk](https://stardot.org.uk/forums/viewtopic.php?t=22514)
- [Looks Good, Reads Bad: Imaging 5–25-inch floppy disks on mismatched drives](https://digitalpreservation-blog.lib.cam.ac.uk/looks-good-reads-bad-imaging-5-25-inch-floppy-disks-on-mismatched-drives-92f7013e0723)
- [GitHub \- archivistsguidetokryoflux/archivists\-guide\-to\-kryoflux: An un\-official user guide for the KryoFlux written by archivists, for archivists](https://github.com/archivistsguidetokryoflux/archivists-guide-to-kryoflux)
- [Archival Floppy Disk Preservation and Use](https://www.youtube.com/watch?v=UxsRpMdmlGo)
- [SuperCard Pro image file format](https://www.cbmstuff.com/downloads/scp/scp_image_specs.txt)

- [GitHub \- latchdevel/HxCFloppyImageConverter: Limited fork from &quot;HxC Floppy Emulator Project&quot; generic/universal floppy disk drive emulator](https://github.com/latchdevel/HxCFloppyImageConverter)
- [GitHub \- keirf/disk\-utilities](https://github.com/keirf/Disk-Utilities)
- [SAMdisk \- Formats](https://simonowen.com/samdisk/formats/)

- [V4\.1 Setup · keirf/greaseweazle Wiki · GitHub](https://github.com/keirf/greaseweazle/wiki/V4.1-Setup)
- [Yann Serra Tutorial · keirf/greaseweazle Wiki · GitHub](https://github.com/keirf/greaseweazle/wiki/Yann-Serra-Tutorial)
- [Pauline, universal Floppy Disk Reader / Simulator \- Share Project \- PCBWay](https://www.pcbway.com/project/shareproject/Pauline__universal_Floppy_Disk_Reader___Simulator.html)
- [A comparison of current disk archival tools — WinWorld](https://forum.winworldpc.com/discussion/7877/a-comparison-of-current-disk-archival-tools)

# formats

```
MF2DD: 1.0MB
 500 * 2 *  8 * 80 = 640000
 500 * 2 *  9 * 80 = 720000

MF2HD: 1.6/2.0MB, can be 256 bytes/record formatted
1000 * 2 *  8 * 77 = 1232000 (3-Mode)
 500 * 2 * 15 * 80 = 1200000 (3-Mode)
 250 * 2 * 36 * 80 = 1440000
 500 * 2 * 18 * 80 = 1440000
 500 * 2 * 21 * 80 = 1680000
```

- 1.44MB 3.5in (IBM)
    - 512 bytes/sector, 1x density, 18 sectors/track, 80 tracks/side, 300RPM
    - 1024 bytes/sector, 2x density, 9 sectors/track, 80 tracks/side, 300RPM
    - `512*2*80*18 = 1474560`
- 1.25MB 3.5in (PC98/X68000)
    - 1024 bytes/sector, 2x density, 8 sectors/track, 77 tracks/side, 360RPM
    - 1024 bytes/sector, 2x density, 18 sectors/track, 80 tracks/side, 135 tpi, 17434 bpi, 360RPM
    - requires 3-Mode floppy-disk drive
        - http://www.amazon.com/Sony-PCGA-UFD5-VAIO-Floppy-Drive/dp/B00006HNH0
        - https://gamesx.com/wiki/doku.php?id=x68000:writing_3.5_floppies
- [Norsk Data](https://www.ndwiki.org/wiki/ND_floppy_disks)
    - 1024 bytes/sector, 2x density, 8 sectors/track, 77 tracks/side => total capacity 616 pages
    - `1024*2*8*77 = 1261568`
- [List of floppy disk formats \- Wikipedia](https://en.wikipedia.org/wiki/List_of_floppy_disk_formats)
- [Floppy disk drive interface \- Wikipedia](https://en.wikipedia.org/wiki/Floppy_disk_drive_interface)

```sh
ufiformat -i /dev/sdb
```

# connections

- 34-pin 5-connector ribbon cable
    - at end: drive letter = a
    - at middle: drive letter = b
- 4-pin white connector from power supply

### 3-Mode

- Samsung SFD-321B
    - Both "OPA" and "OPB" open : 2 Mode (1MB / 2MB);
    - "OPB" is connected and "OPA" is open : 2 Mode (1MB / 1.6MB);
    - "OPA" is connected and "OPB" is open : 3 Mode (1MB / 1.6MB / 2MB);

### Non-IBM PCs

- [MITSUMI D359T5 und D359T6](https://honi.hucki.net/mitsumi.html)
    - Move the 0 ohms resistor position from R14 (DCH) to RDY;
    - Put a jumper wire from PIN 2 to DCH (close to FG2 WG);
    - Move the 0 ohms resistor position DS1 to DS0;
- [Samsung SFD-321B LBL1 rev.T5](https://eab.abime.net/showthread.php?t=30944&highlight=teac+fd-235hf&page=16)
    - Change DS1 to DS0 jumper pad (de-solder the solder blob), to make it the A drive;
    - Short RDY, to put signal on pin 34;
    - Short pin 2 to DC;
    - Clean pads on DS3, INUSE, HD0, TR0, INDEX;
- [Panasonic PC drive &\#8211; MSX Info Pages](https://hansotten.file-hunter.com/do-it-yourself/msx-floppy-drives/panasonic-pc-drive/)
- [Tynemouth Software: Building a 1581 Disk Drive Part 2](http://blog.tynemouthsoftware.co.uk/2025/04/building-1581-disk-drive-part-2.html)
- [Samsung sfd\-321b \| MSX Resource Center](https://www.msx.org/forum/msx-talk/hardware/samsung-sfd-321b)
    - Controller pin 25 = RDY = Drive pin 34 = MSX pin 6;
    - Controller pin 26 = DC = Drive pin 2 = MSX pin 24;
- [Writing disk images to 3.5" floppies with USB floppy drives](https://gamesx.com/wiki/doku.php?id=x68000:writing_3.5_floppies)
- [Writing 5.25" Floppies in Linux](https://www.target-earth.net/wiki/doku.php?id=blog:x68_floppies)
    ```sh
    echo "1232/1232 2464 16 2 77 0 0x35 0x08 0xDF 0x74" > /etc/fdprm
    setfdprm /dev/$FD -p 1232/1232
    fdformat /dev/$FD
    ```
- [The NitrOS-9 Project Old Wiki \-  Transferring_DSK_Images_to_Floppies] (https://sourceforge.net/p/nitros9/wiki/Transferring_DSK_Images_to_Floppies/)
    ```sh
    # COCO40DS
    DS DD sect=18 cyl=40 ssize=256 tpi=48
    # COCO80DS
    DS DD sect=18 cyl=80 ssize=256 tpi=96

    setfdprm /dev/fd1 coco40ds
    fdformat /dev/fd1
    dd if=nos96309l2v030200_ds40_1.dsk of=/dev/fd1
    ```
- [How to read and write disk images for the M20 system](https://www.z80ne.com/m20/index.php?argument=sections/transfer/imagereadwrite/imagereadwrite.inc)
    ```sh
    setfdprm /dev/fd1 OLI320
    # Skip first 4096 bytes. These are the blocks of Track 0/Head 0. Track 0/Head 0 is formatted in FM mode, which isn't readable by many PC floppy controllers.
    sdd iseek=4096 oseek=4096 if=/dev/fd1 of=m20disk.img bs=256 count=1104
    ```
- [RC759 PICCOLINE \- Reading and writing RC75x Floppy Disks with a Linux PC](https://rc700.dk/guides/Reading_and_writing_RC75x_floppy_disks.php)
    > Both the RC750 PARTNER and the RC759 PICCOLINE uses DSHD 96TPI (Double Sided, High Density, 96 tracks per. inch) 1.2MB 5.25" floppy disks formatted with 77 tracks, 8 sectors per track and a sector length of 1024 bytes.
    ```sh
    setfdprm /dev/fd0 sect=8 hd ssize=1024 cyl=77
    ddrescue -v -d -b 1024 -c 8 /dev/fd0 test.img test.log
    ```

# protection

- [Security: Weak bits floppy disc protection: an alternate origins story on 8\-bit](https://scarybeastsecurity.blogspot.com/2020/06/weak-bits-floppy-disc-protection.html)

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

Samsung SFD-321B 3-Mode flux imaging speed diff:

```
Command Failed: GetFluxStatus: No Index => disk not inserted!

# gw info
Host Tools: 1.22
Device:
  Port:     /dev/ttyACM0
  Model:    Greaseweazle V4.1
  MCU:      AT32F403A, 216MHz, 224kB SRAM
  Firmware: 1.6
  Serial:   GWB049C83A5976C01007441705
  USB:      Full Speed (12 Mbit/s), 128kB Buffer

# gw read --tracks c=0-80:h=0-1 output.scp
Reading c=0-80:h=0-1 revs=3
T0.0: Raw Flux (322193 flux in 734.85ms)
T0.1: Raw Flux (312841 flux in 677.54ms)
T1.0: Raw Flux (244600 flux in 648.89ms)
T1.1: Raw Flux (261348 flux in 692.44ms)
T2.0: Raw Flux (252698 flux in 669.49ms)
T2.1: Raw Flux (256685 flux in 680.97ms)

# gw read --format=ibm.1440 output.ibm1440.img
[...]
T78.0: IBM MFM (18/18 sectors) from Raw Flux (151589 flux in 399.14ms)
T78.1: IBM MFM (18/18 sectors) from Raw Flux (151532 flux in 399.14ms)
T79.0: IBM MFM (18/18 sectors) from Raw Flux (151587 flux in 399.14ms)
T79.1: IBM MFM (18/18 sectors) from Raw Flux (151548 flux in 399.14ms)
Cyl-> 0         1         2         3         4         5         6         7
H. S: 01234567890123456789012345678901234567890123456789012345678901234567890123456789
0. 0: ................................................................................
0. 1: ................................................................................
[...]
1.16: ................................................................................
1.17: ................................................................................
Found 2880 sectors of 2880 (100%)

# gw convert --format=ibm.1440 output.scp output.ibm1440.2.img

Shorted OPA + gw pin 2 L => 360rpm
# gw seek 79
# gw seek 0
# gw read --revs 5 --retries=10 --seek-retries=10 --format=ibm.1200 output.ibm1200.scp --raw
T78.0: IBM MFM (15/15 sectors) from Raw Flux (386462 flux in 832.30ms)
T78.1: IBM MFM (15/15 sectors) from Raw Flux (392234 flux in 832.30ms)
T79.0: IBM MFM (15/15 sectors) from Raw Flux (351013 flux in 832.30ms)
T79.1: IBM MFM (15/15 sectors) from Raw Flux (326384 flux in 832.30ms)

vs. 300rpm
T78.0: IBM MFM (15/15 sectors) from Raw Flux (386446 flux in 998.97ms)
T78.1: IBM MFM (15/15 sectors) from Raw Flux (392200 flux in 998.97ms)
T79.0: IBM MFM (15/15 sectors) from Raw Flux (350989 flux in 998.96ms)
T79.1: IBM MFM (15/15 sectors) from Raw Flux (326378 flux in 998.97ms)
```
