# +

- [compression](./compression.md)
- [filesystem](./filesystem.md)
- [volatility](./volatility.md)

- [CTF Series : Forensics \- tech\.bitvijays\.com](https://bitvijays.github.io/LFC-Forensics.html)
- [FreshPorts \- sysutils/sleuthkit: Tools and library for filesystem forensic analysis](http://freshports.org/sysutils/sleuthkit)
- [RWEverything \- Read Write Everything](http://rweverything.com/)

# documentation, specification

- [ZLIB Compressed Data Format Specification version 3.3](https://ietf.org/rfc/rfc1950.txt)
- [DEFLATE Compressed Data Format Specification version 1.3](https://ietf.org/rfc/rfc1951.txt)
- [GZIP file format specification version 4.3](https://ietf.org/rfc/rfc1952.txt)
- [Portable Network Graphics (PNG) Specification and Extensions](http://libpng.org/pub/png/spec/)

# malware family / classification

- https://whatis.techtarget.com/glossary/Security
- https://docs.microsoft.com/en-us/windows/security/threat-protection/intelligence/malware-naming
- https://encyclopedia.kaspersky.com/knowledge/rules-for-classifying/

# malware analysis / sandbox

- https://hybrid-analysis.com/
- https://app.any.run/
- https://www.virustotal.com/gui/home

- https://zeltser.com/media/docs/malware-analysis-cheat-sheet.pdf
- https://pokhym.com/2017/06/25/part-1-1-basic-static-techniques/
- https://github.com/hxFrost/Malware-Analysis-Tools

# event log

- `592/4688` - A new process has been created

- [GitHub \- williballenthin/EVTXtract: EVTXtract recovers and reconstructs fragments of EVTX log files from raw binary data, including unallocated space and memory images\.](https://github.com/williballenthin/EVTXtract)

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

- compare running processes with known file hashes
    - [Current RDS Hash Sets | NIST](https://www.nist.gov/itl/ssd/software-quality-group/national-software-reference-library-nsrl/nsrl-download/current-rds)

### memory dump

- dumpit, procdump -ma, PMDump
- winpmem.exe -f test.raw
    - https://github.com/google/rekall/tree/master/tools/windows/winpmem

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
# Reference: [How To Search for Strings on a Disk Image Using The Sleuth Kit \- LMG Security](https://www.lmgsecurity.com/sleuth-kit/)
icat -o 129 -r foo.dd 54
# recover all files from journal
extundelete artefact --restore-all

# list deleted files, with full paths, recursively
fls -d -p -r /dev/sda
# recover files, from unallocated space (carving), by extension
sed -i 's/^#[[:space:]]\+\(\(doc\|pdf\|gif\|jpg\|png\).*\)/\1/g' /etc/scalpel/scalpel.conf
scalpel /dev/sda
```

- https://possiblelossofprecision.net/?p=1216
    - https://wiki.sleuthkit.org/index.php?title=FS_Analysis
    - https://wiki.sleuthkit.org/index.php?title=Case_Studies

### ignore likely carved false positives

```bash
find . -type f -name '*.png' -size +1500k -delete
find . -type d -empty -delete
```

### carving with dd

```bash
dd if=/proc/7/mem bs=$((0x1000)) skip=$((Ox7fb84ee44 + 0x207)) count=1 of=out
```

### windows

1. create disk image
    ```powershell
    # List disks
    wmic diskdrive list
    # ||
    Get-WmiObject Win32_DiskDrive
    # Dump disk
    dd.exe if=\\.\PhysicalDrive0 of=d:\images\PhysicalDrive0.img --md5sum --verifymd5 --md5out=d:\images\PhysicalDrive0.img.md5
    ```
    - https://forensicswiki.xyz/wiki/index.php?title=Dd
    - https://hddguru.com/software/HDD-Raw-Copy-Tool/
2. carving
    - https://www.cgsecurity.org/wiki/PhotoRec_Step_By_Step

# data sets

- https://www.forensicfocus.com/challenges-and-images/
- https://www.cfreds.nist.gov/
- http://downloads.digitalcorpora.org/corpora/

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

# decompress streams
qpdf --qdf --object-streams=disable foo.pdf foo.decompressed.pdf

# enumerate references
f=challenge.pdf && { \
  peepdf "$f" | \
  grep 'Objects ([0-9]*):' | \
  sed 's/.*\[\(.*\)\]/\1/; s/\([0-9]\+\)\(, \)\?/references to \1\n/g' | \
  peepdf "$f" -i
} 2>/dev/null
```

- https://blog.didierstevens.com/programs/pdf-tools/
- references to objects, tree
    - https://eternal-todo.com/tools/peepdf-pdf-analysis-tool#usage
- streams
    - https://blog.didierstevens.com/2008/05/19/pdf-stream-objects/
- xrefs
    - https://labs.appligent.com/pdfblog/pdf_cross_reference_table/
    - https://resources.infosecinstitute.com/topic/pdf-file-format-basic-structure/

# zlib

- compression level magic bytes
    - `78 01`: None / Low
    - `78 9C`: Default (Common)
    - `78 DA`: Best

# zip

```bash
# Fix
zip -F foo.zip --out foo.fixed.zip
zip -FF foo.zip --out foo.fixed.zip

# Extract broken zip
bsdtar xf zipfile

# Extract multipart archive
# Given: archives ordered by name
cat foo.*.zip > foo.zip
zip -FF foo.zip --out foo.fixed.zip

# bruteforce password
while read -r i; do 7z x -p"$i" flag.zip >/dev/null; e=$?; if [ ! -s flag.txt ] || [ $e -gt 0 ]; then rm flag.txt; else break; fi; done < ~/code/guides/ctf/SecLists/Passwords/Leaked-Databases/rockyou-75.txt
# preserve attempts where CRC Failed
while read -r i; do 7z x -p"$i" flag.zip >/dev/null; if [ ! -s flag.txt ]; then rm flag.txt; else mv flag.txt flags/"$(date +%s)".flag.txt; fi; done < ~/code/guides/ctf/SecLists/Passwords/Leaked-Databases/rockyou-75.txt
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
- https://ctf-wiki.github.io/ctf-wiki/misc/archive/zip/

### extraction path

- symbolic links
    - [APPNOTE.TXT - .ZIP File Format Specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
        - 4.5.7 UNIX Extra Field (0x000d)
- write outside extraction path using path traversal via relative path, e.g. `../../foo`
    - [APPNOTE.TXT - .ZIP File Format Specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
        - 4.4.17 file name: (Variable)
    - [The Complete Guide to Hacking WWIV \- Volume Three, Issue Thirty-four \- Phrack Magazine](http://phrack.org/issues/34/5.html)
    - [GitHub \- snyk/zip\-slip\-vulnerability: Zip Slip Vulnerability \(Arbitrary file write through archive extraction\)](https://github.com/snyk/zip-slip-vulnerability)

### encryption / password attacks

Bruteforce:

```bash
~/opt/john/run/zip2john flag.zip > flag.zip.john
~/opt/john/run/john --wordlist="$(realpath ~/share/opt/rockyou.txt)" flag.zip.john
```

Biham and Kocher's known plaintext attack:

- encryption algorithm = ZipCrypto
- uncompressed copy of one encrypted file
- compressed plaintext file using same algorigthm
    - https://ctf-wiki.github.io/ctf-wiki/misc/archive/zip/
    - https://www.programmersought.com/article/13436370754/
    ```bash
    # General case
    bkcrack -C encrypted.zip -c uncompressed.xml -P plain.zip -p plain.txt
    # Or: Contains png
    bkcrack -C encrypted.zip -c foo.png -p png_header.bin -o 0
    # Take file entry from encrypted archive, pass to `-c`
    # Take key values, pass to `-k`
    bkcrack -C encrypted.zip -c encrypted.jpg -k c072e51c a36b7996 b6f8d312 -d decrypted.jpg
    ```
- [ZIP Attacks with Reduced Known Plaintext](~/code/doc/zip/zipattacks.pdf)
    - [A known plaintext attack on the PKZIP stream cipher](~/code/doc/zip/CS0842.pdf)
    - https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf

- https://russtone.io/2018/06/24/google-2018-better-zip/

# 7-Zip

- identify trailing data after compressed data: boolean-based error checking with `7z t`, foreach nulled byte
    - [CTFtime\.org / TastelessCTF 2020 / 7/12 / Writeup](https://ctftime.org/writeup/24083)
- CRC fix: null out start header + signature header
    - [7-Zip / Discussion / Help: Headers Error](https://sourceforge.net/p/sevenzip/discussion/45798/thread/84c5df85/)
- [How to recover corrupted 7z archive](https://www.7-zip.org/recover.html)

# rar

```bash
# Extract broken rar
unrar e -kb

# Extract multipart archive
# Given: archives ordered by name
unrar x foo.part1.rar
```

# steganography

- detection
    - https://stegonline.georgeom.net/upload
    - stegoveritas
    - zsteg
    ```bash
    # If differences in most pixels, maybe LSB applied
    compare foo.png original.jpg foo.diff.png
    ```
- application
    - steghide
        - adds huffman table: `()*56789:CDEFGHI`
    - outguess
    - RGB vs RGBA
        - https://medium.com/swlh/lsb-image-steganography-using-python-2bbbee2c69a2
- [GitHub \- RobinDavid/LSB\-Steganography: Python program to steganography files into images using the Least Significant Bit\.](https://github.com/RobinDavid/LSB-Steganography)
- [GitHub \- DominicBreuker/stego\-toolkit: Collection of steganography tools \- helps with CTF challenges](https://github.com/DominicBreuker/stego-toolkit)

- https://fotoforensics.com/
    - https://www.hackerfactor.com/blog/index.php?/archives/894-PNG-and-Hidden-Pixels.html
- [How to defeat naive image steganography | Hacker News](https://news.ycombinator.com/item?id=11579309)
- [ALASKA2: Image Steganalysis \- All you need to know | Kaggle](https://www.kaggle.com/prashant111/alaska2-image-steganalysis-all-you-need-to-know)
- [DDE Download Section](http://dde.binghamton.edu/download/)
- https://cs.cmu.edu/~biglou/PSS.pdf

### printers, yellow dots, machine identification code

- [DEDA - tracking Dots Extraction, Decoding and Anonymisation toolkit](https://github.com/dfd-tud/deda)

# copy protection

- Detection
    - https://protectionid.net/
- Crafting data pattern that interferes with scrambler pattern, causing read errors
    - ~/code/snippets/cdrom/scramble_ecma130.py
    - ~/code/snippets/cdrom/scramble_clonecd.py
    - [Magic of Figures, or Detective Story about Unreadable CDs](http://ixbtlabs.com/articles2/magia-chisel/index.html)
    - [Чтение данных с CD\-ROM \| WASM](https://wasm.in/threads/chtenie-dannyx-s-cd-rom.501/)
    - https://en.wikipedia.org/wiki/Linear-feedback_shift_register
    ```
    0x00: 00 D7 FF E1 7F F7 9F F9 57 FD 01 81
    0x08: A8 FD 01 7E 7F 9F 9F D7 D7 E1 61 88
    0x14: 68 99 51 55 03 80 FE 1F FF B7 FF 36
    ```
- References
    - https://www.cdmediaworld.com/hardware/cdrom/cd_protections.shtml

# file formats

- [QuickBMS generic files extractor and reimporter \- Luigi Auriemma](http://quickbms.aluigi.org/)
- [GitHub \- Sembiance/dexvert: Decompress EXtract and CONVert old file formats into modern ones](https://github.com/Sembiance/dexvert)
- [Index of /fileFormatSamples/](https://telparia.com/fileFormatSamples/)

### polyglots

Detection / Parsing:

```bash
file -k _
binwalk --dd='.*' _
binwalk -Me _

# graphics images
exiftool -v _
identify -verbose _
python3 -c 'import cv2, sys; cv2.imread(sys.argv[1])' _
python3 -c 'import sys; from PIL import Image; print(Image.open(sys.argv[1]).verify())' _
pngcheck -f -vv _

# pdfs
pdfinfo _
qpdf --check _
caradoc stats _

# disk images
### files
fls _
### metadata
iat --debug -i _
ksv ~/opt/isolyzer/testFiles/iso9660.iso ~/opt/kaitai_struct/formats/filesystem/iso9660.ksy
### verify expected file size extracted from headers consistent with actual size
isolyzer _

# archives
7z t _
```
- [GitHub \- Polydet/polydet: Polyglot detector](https://github.com/Polydet/polydet)

No magic enforced at offset zero:

- PDF, PostScript, BMFF (mp4, mov, heic...), DICOM (medical images), TAR, ZIP, Rar, 7z, Arj, raw dumps (.iso, roms)

Examples:

- ~/opt/mitra/
    - https://github.com/corkami/mitra/tree/master/utils/gcm
- ~/opt/truepolyglot.git/
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

Parasites:

- [ICC profile in JPG](https://twitter.com/David3141593/status/1057042085029822464)
    - multipart RAR used to work around JPG block size
- [IDAT chunk in PNG](https://twitter.com/David3141593/status/1371974874856587268)
    - [GitHub \- DavidBuchanan314/tweetable\-polyglot\-png: Pack up to 3MB of data into a tweetable PNG polyglot file\.](https://github.com/DavidBuchanan314/tweetable-polyglot-png)

### hash collisions

- https://github.com/corkami/collisions

### mocks

- ./files/mis-identified-files.jpg
- https://github.com/corkami/pocs/tree/master/mocks

### invalid data

```bash
# identify by chunks vs. magic bytes
### png
hexgrep.py _ "$(printf '%s' 'PNG|IHDR|PLTE|IDAT|IEND' | xxd -p)"
grep -Habo $'PNG\\|IHDR\\|PLTE\\|IDAT\\|IEND' _
file -k * | grep '\s*data' | cut -d':' -f1 | xargs -i env LC_ALL=C awk 'match($0, /PNG|IHDR|PLTE|IDAT|IEND/) {
    offset = count + RSTART - 1;
    group = substr($0, RSTART, RLENGTH);
    printf("%s:%s(0x%x):%s\n", FILENAME, offset, offset, group);
} { count += length + 1; }' {}
### jpeg
hexgrep.py _ '\xff\xd8|\xff\xe0|JFIF|\xff\xdb|\xff\xc0|\xff\xc4|\xff\xda|\xff\xd9'
grep -Habo $'\xff\xd8\\|\xff\xe0\\|JFIF\\|\xff\xdb\\|\xff\xc0\\|\xff\xc4\\|\xff\xda\\|\xff\xd9' _
file -k * | grep '\s*data' | cut -d':' -f1 | xargs -i env LC_ALL=C awk 'match($0, /\xff\xd8|\xff\xe0|JFIF|\xff\xdb|\xff\xc0|\xff\xc4|\xff\xda|\xff\xd9/) {
    offset = count + RSTART - 1;
    group = substr($0, RSTART, RLENGTH);
    printf("%s:%s(0x%x):%s\n", FILENAME, offset, offset, group);
} { count += length + 1; }' {}
```

- CRC correction
    ```bash
    pngcheck -cfv _
    ```
        - http://libpng.org/pub/png/apps/pngcheck.html
    - https://0x90r00t.com/2016/02/08/sharif-university-ctf-2016-forensic-400-blocks-write-up/
- incorrect chunk length
- incorrect headers
    - https://github.com/apoirrier/CTFs-writeups/blob/master/DarkCTF2020/Misc/QuickFix.md
- extract patterns from specifications
    - http://www.libpng.org/pub/png/spec/1.2/PNG-Chunks.html

# case studies

- https://forensixchange.com/posts/19_04_22_win10_ntfs_time_rules/
- http://journeyintoir.blogspot.com/2013/12/revealing-recentfilecachebcf-file.html

- https://trailofbits.github.io/ctf/forensics/

- [GitHub \- stuxnet999/MemLabs: Educational, CTF\-styled labs for individuals interested in Memory Forensics](https://github.com/stuxnet999/MemLabs)
    - https://bananamafia.dev/post/mem/
- https://www.hecfblog.com/search/label/ctf
- https://www.hecfblog.com/2018/08/daily-blog-451-defcon-dfir-ctf-2018.html
    - https://infosecuritygeek.com/defcon-dfir-ctf-2018/
    - https://medium.com/hackstreetboys/defcon-dfir-ctf-2018-lessons-learned-890ef781b96c
    - https://caffeinated4n6.blogspot.com/2018/12/defcon-dfir-ctf-2018.html
- https://klanec.github.io/inctf/2020/08/02/inctf-lookout-foxy.html
    - firefed (firefox), undbx (mails), mpack (MIME attachments)
- https://cyberdefenders.org/labs/37
- https://www.ashemery.com/dfir.html

### zeroing section headers to thwart dissassemblers

- windows
    - GetModuleHandle
    - VirtualProtect + RtlZeroMemory
- linux
    - fopen("/proc/self/maps", "r")
    - fscanf addresses
    - mprotect + memset

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

- [DEF CON 24 \- int0x80 \- Anti Forensics AF \- YouTube](https://www.youtube.com/watch?v=_fZfDGWpP4U)

- For windows, contents may still be recovered via `vaddump`, if references not broken
    - [MNIN Security Blog: Recovering CoreFlood Binaries with Volatility](https://mnin.blogspot.com/2008/11/recovering-coreflood-binaries-with.html)
    - [Hidding Module from the Virtual Address Descriptor Tree | Lilxam](http://lilxam.tuxfamily.org/blog/?p=326&lang=en)
    - https://reverseengineering.stackexchange.com/questions/16176/volatility-manually-inspect-heap-of-a-process
