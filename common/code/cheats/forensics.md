# +

https://bitvijays.github.io/LFC-Forensics.html

# event log

- 592/4688 - A new process has been created

https://github.com/williballenthin/EVTXtract

# memory analysis

./volatility.md

compare running processes with known file hashes
    [Current RDS Hash Sets | NIST](https://www.nist.gov/itl/ssd/software-quality-group/national-software-reference-library-nsrl/nsrl-download/current-rds)

### memory dump

dumpit, procdump, PMDump
https://github.com/google/rekall/tree/master/tools/windows/winpmem
    winpmem.exe -f test.raw

### live system

```ps1
# load driver
winpmem.exe -l
# run against raw device
vol.py -f \\.\pmem --profile Win7SP1x64 pslist
```

# filesystem mounting

```bash
apt-get install xmount ewf-tools afflib-tools sleuthkit
pip3 install imagemounter
imount --check
# ||
sudo mount -t ext4 -o loop foo mnt_dir
```

# filesystem timestamps

https://countuponsecurity.com/2016/05/30/digital-forensics-ntfs-indx-and-journaling/

# identify by chunks vs. magic bytes

```bash
file -k * | grep ':\s*data$' | cut -d':' -f1 | xargs -i awk '/PNG|IHDR|PLTE|IDAT|IEND/{print FILENAME; exit}' {}
```

http://www.libpng.org/pub/png/spec/1.2/PNG-Chunks.html

# recovering files

```bash
# list deleted files with filesystem start offset
fls -o 129 foo.dd

# recover all files
tsk_recover -o 129 foo.dd .
# || recover files, by inode
icat -o 129 -r foo.dd 54

# list deleted files, with full paths, recursively
fls -d -p -r /dev/sda
# recover files, from unallocated space (carving), by extension
sed -i 's/^#[[:space:]]\+\(\(doc\|pdf\|gif\|jpg\|png\).*\)/\1/g' /etc/scalpel/scalpel.conf
scalpel /dev/sda
```

https://possiblelossofprecision.net/?p=1216
    https://wiki.sleuthkit.org/index.php?title=FS_Analysis
    https://wiki.sleuthkit.org/index.php?title=Case_Studies

### ignore likely carved false positives

```bash
find . -type f -name '*.png' -size +1500k -delete
find . -type d -empty -delete
```

### carving with dd

```bash
dd if=/proc/7/mem bs=$((0x1000)) skip=$((Ox7fb84ee44 + 0x207)) count=1 of=out
```

# repair png

http://libpng.org/pub/png/apps/pngcheck.html

# data sets

https://www.forensicfocus.com/challenges-and-images/
https://www.cfreds.nist.gov/
http://downloads.digitalcorpora.org/corpora/

# case studies

https://forensixchange.com/posts/19_04_22_win10_ntfs_time_rules/
http://journeyintoir.blogspot.com/2013/12/revealing-recentfilecachebcf-file.html

https://trailofbits.github.io/ctf/forensics/

https://www.hecfblog.com/search/label/ctf
https://www.hecfblog.com/2018/08/daily-blog-451-defcon-dfir-ctf-2018.html
    https://infosecuritygeek.com/defcon-dfir-ctf-2018/
    https://medium.com/hackstreetboys/defcon-dfir-ctf-2018-lessons-learned-890ef781b96c
    https://caffeinated4n6.blogspot.com/2018/12/defcon-dfir-ctf-2018.html
https://klanec.github.io/inctf/2020/08/02/inctf-lookout-foxy.html
    firefed (firefox), undbx (mails), mpack (MIME attachments)

### zeroing section headers to thwart dissassemblers 

windows
    GetModuleHandle
    VirtualProtect + RtlZeroMemory
linux
    fopen("/proc/self/maps", "r")
    fscanf addresses
    mprotect + memset

```ps1
winpmem-2.1.post4.exe -o lol.aff4
"C:\Program Files\Rekall\rekal.exe" -f lol.aff4
# procdump proc_regex="thekeys", dump_dir="C:/Users/int0x80/Desktop/"
```

```bash
git clone https://github.com/504ensicsLabs/LiME
sudo insmod ./lime-$(uname -r).ko "path=/tmp/1"

git clone https://github.com/volatilityfoundation/volatility
# Build profile for current machine
cd ~/tools/volatility/tools/linux/
make
# Validation
grep '.debug_info' module.dwarf

python vol.py -f /tmp/1 --profile=Linux...
# linux_pslist
# linux_procdump
```

[DEF CON 24 \- int0x80 \- Anti Forensics AF \- YouTube](https://www.youtube.com/watch?v=_fZfDGWpP4U)

For windows, contents may still be recovered via `vaddump`, if references not broken
    [MNIN Security Blog: Recovering CoreFlood Binaries with Volatility](https://mnin.blogspot.com/2008/11/recovering-coreflood-binaries-with.html)
    [Hidding Module from the Virtual Address Descriptor Tree | Lilxam](http://lilxam.tuxfamily.org/blog/?p=326&lang=en)
    https://reverseengineering.stackexchange.com/questions/16176/volatility-manually-inspect-heap-of-a-process

### zip password attacks

Requirements:
- uncompressed copy of one file
- encryption algorithm = ZipCrypto

https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files
https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf

