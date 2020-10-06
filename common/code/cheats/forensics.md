# +

https://bitvijays.github.io/LFC-Forensics.html

http://freshports.org/sysutils/sleuthkit

# event log

- 592/4688 - A new process has been created

https://github.com/williballenthin/EVTXtract

# process information

```
/proc/self/cmdline
/proc/self/cwd/
```

# memory analysis

- ./volatility.md
    - any format
- AccessData FTK_Imager
    - EnCase format

compare running processes with known file hashes
    [Current RDS Hash Sets | NIST](https://www.nist.gov/itl/ssd/software-quality-group/national-software-reference-library-nsrl/nsrl-download/current-rds)

### memory dump

dumpit, procdump, PMDump
winpmem.exe -f test.raw
    https://github.com/google/rekall/tree/master/tools/windows/winpmem

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

# recovering files

```bash
# list deleted files with filesystem start offset
fls -o 129 foo.dd

# recover all files
tsk_recover -o 129 foo.dd .
# || recover files, by inode
icat -o 129 -r foo.dd 54
# recover all files from journal
extundelete artefact --restore-all

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

# pdf

- [GitHub \- RUB\-NDS/PDF101: Artifacts for the Black Hat talk\.](https://github.com/RUB-NDS/PDF101)
    - https://medium.com/bugbountywriteup/hacker101-ctf-android-challenge-writeups-f830a382c3ce
- [Apprentice Alf’s Blog | Everything you ever wanted to know about DRM and ebooks, but were afraid to ask\.](https://apprenticealf.wordpress.com/)
- ../logbooks/pdf_reformat.md

```bash
# disable security / drm / no copy restriction bits
qpdf --decrypt input.pdf out.pdf
pdftk input.pdf output out.pdf allow AllFeatures
gs -sPDFPassword=$PASS -q -dNOPAUSE -dBATCH -dSAFER -r300 -sDEVICE=pdfwrite -sOutputFile=%stdout% -c .setpdfwrite -f input.pdf > output.pdf
```

# zip

```bash
zip -F foo --out foo.out
zip -FF foo --out foo.out
```

- binwalk expects p7zip
    > The UnZip implementation is the cause of your problem. When binwalk extracts full, the first ZIP actually contains both ZIPs, but UnZip only extracts the last one (which is also stored independently in the second ZIP that binwalk extracted).
    - https://reverseengineering.stackexchange.com/questions/13944/automatically-extract-known-file-types-eg-zip-using-binwalk
- https://reverseengineering.stackexchange.com/questions/13616/simple-carving-of-zip-file-using-binwalk
- https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT
    - ~/code/doc/zip/APPNOTE.TXT
- AE-x (compression method = 99)
    - [AES Encryption Information: Encryption Specification AE-1 and AE-2](https://www.winzip.com/win/en/aes_info.html)
- ~/code/doc/zip/Ten Thousand Traps.pdf

### extraction path

- [GitHub \- snyk/zip\-slip\-vulnerability: Zip Slip Vulnerability \(Arbitrary file write through archive extraction\)](https://github.com/snyk/zip-slip-vulnerability)

### encryption / password attacks

Biham and Kocher's known plaintext attack:

- encryption algorithm = ZipCrypto
- uncompressed copy of one encrypted file
- compressed plaintext file using same algorigthm
    ```bash
    bkcrack -C encrypted.zip -c uncompressed.xml -P plain.zip -p plain.txt
    # Take file entry from encrypted archive, pass to `-c`
    # Take key values, pass to `-k`
    bkcrack -C encrypted.zip -c encrypted.jpg -k c072e51c a36b7996 b6f8d312 -d decrypted.jpg
    ```
- [ZIP Attacks with Reduced Known Plaintext](~/code/doc/zip/zipattacks.pdf)
    - [A known plaintext attack on the PKZIP stream cipher](~/code/doc/zip/CS0842.pdf)
    - https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf

- https://russtone.io/2018/06/24/google-2018-better-zip/

# steg

- https://fotoforensics.com/
    - https://www.hackerfactor.com/blog/index.php?/archives/894-PNG-and-Hidden-Pixels.html
- outguess

# file formats

### polyglots

Detection:

```bash
file -k _
binwalk --dd='.*' _
binwalk -Me _

# images
identify -verbose _
python3 -c 'import cv2, sys; cv2.imread(sys.argv[1])' _
python3 -c 'import sys; from PIL import Image; print(Image.open(sys.argv[1]).verify())' _

# pdfs
pdfinfo _
qpdf --check _
caradoc stats _
```
- [GitHub \- Polydet/polydet: Polyglot detector](https://github.com/Polydet/polydet)

No magic enforced at offset zero:

- PDF, PostScript, BMFF (mp4, mov, heic...), DICOM (medical images), TAR, ZIP, Rar, 7z, Arj, raw dumps (.iso, roms)

Examples:

- ~/opt/mitra/
- ~/opt/truepolyglot/
- jpeg + mp3
- jpeg + php archive
    ```
    \xFF\xD8......................JPEG DATA.....................\xFF\xD9
    __HALT_COMPILER(); ............PHAR DATA............................
    ```
    - execute with: phar://
    - https://medium.com/swlh/polyglot-files-a-hackers-best-friend-850bf812dd8a
- gif + javascript
    - ~/code/snippets/polyglot/thinkfu-js.gif
    - http://web.archive.org/web/20200301052900if_/http://www.thinkfu.com/blog/gifjavascript-polyglots
- gif + jar
    - https://en.wikipedia.org/wiki/Gifar
- msi + jar
    - https://blog.virustotal.com/2019/01/distribution-of-malicious-jar-appended.html

### hash collisions

- https://github.com/corkami/collisions

### mocks

- ./files/mis-identified-files.jpg

### invalid data

```bash
# identify by chunks vs. magic bytes
file -k * | grep '\s*data' | cut -d':' -f1 | xargs -i awk '/PNG|IHDR|PLTE|IDAT|IEND/{print FILENAME; exit}' {}
file -k * | grep '\s*data' | cut -d':' -f1 | xargs -i awk 'match($0, /\xff\xd8|\xff\xe0|JFIF|\xff\xdb|\xff\xc0|\xff\xc4|\xff\xda|\xff\xd9/{print FILENAME ":" RSTART; exit}' {}
```

- CRC correction
    ```bash
    pngcheck -cfv _
    ```
    - https://0x90r00t.com/2016/02/08/sharif-university-ctf-2016-forensic-400-blocks-write-up/
- incorrect chunk length
- incorrect headers
    - https://github.com/apoirrier/CTFs-writeups/blob/master/DarkCTF2020/Misc/QuickFix.md
- extract patterns from specifications
    - http://www.libpng.org/pub/png/spec/1.2/PNG-Chunks.html
