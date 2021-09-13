# Detection

- [GitHub \- temisu/ancient: Decompression routines for ancient formats](https://github.com/temisu/ancient_format_decompressor)
- [Help:Contents/Finding Content/Compression Algorithms \- The Cutting Room Floor](https://tcrf.net/Help:Contents/Finding_Content/Compression_Algorithms)

# Types

- run-length encoding
- entropy
- dictionary

# DEFLATE

- `zlib.decompress(decoded_data , -15)`
    - https://github.com/ResultsMayVary/ctf/tree/master/PlaidCTF-2017/misc50_zipper
- [Improving compression with a preset DEFLATE dictionary \| Hacker News](https://news.ycombinator.com/item?id=9288710)
- [java \- How to find a good/optimal dictionary for zlib &\#39;setDictionary&\#39; when processing a given set of data? \- Stack Overflow](https://stackoverflow.com/questions/2011653/how-to-find-a-good-optimal-dictionary-for-zlib-setdictionary-when-processing-a)
- [RFC 1950 ZLIB Compressed Data Format Specification version 3\.3](http://www.zlib.org/rfc-zlib.html)
    - [zlib 1.2.11 Manual \- Advanced Functions](https://zlib.net/manual.html#Advanced)

```bash
# brute deflate
python3 -c '
import sys, zlib
b = open(sys.argv[1], "rb").read()
for j in range(0, len(b)):
    for i in range(-15,47):
        try:
            sys.stdout.buffer.write(zlib.decompress(b[j:], i))
            print(i,j)#exit(123)
        except SystemExit as e:
            raise e
        except:
            pass
' foo

python3 -c '
import sys, zlib
CHUNKSIZE=2
d = zlib.decompressobj(-15)
with open(sys.argv[1], "rb") as f:
    buffer=f.read(CHUNKSIZE)
    try:
        while buffer:
            sys.stdout.buffer.write(d.decompress(buffer))
            print("--- {}".format(buffer))
            buffer=f.read(CHUNKSIZE)
    except Exception as e:
        print(e)
' foo
```

# zip

```bash
# extract
jar xvf foo.bin
java -XX:MaxPermSize=256m -Xmx1024M -jar foo.bin -unpack

# repair (recreates central dir)
zip -FF
```

### file format

foo.img

```
2 [PkSection]
    magic = [80, 75]
    sectionType = 0x403 = 1027
    body [LocalFile]
        header [LocalFileHeader]
            version = 0x14 = 20
            flags = 0x0 = 0
            compressionMethod = DEFLATED (0x8 = 8)
            fileModTime = 0x81FB = 33275
            fileModDate = 0x4B8E = 19342
            crc32 = 0x375A1ED = 58040813
            compressedSize = 0x33C = 828
            uncompressedSize = 0x969 = 2409
            fileNameLen = 0xC = 12
            extraLen = 0x0 = 0
            fileName = Pages/1.xaml
            extra [Extras]
        body = [213, 86, 75, 147, 211, 56, 16, 190, ...]
```

bar.img

```
61 [PkSection]
    magic = [80, 75]
    sectionType = 0x403 = 1027
    body [LocalFile]
        header [LocalFileHeader]
            version = 0x14 = 20
            flags = 0x0 = 0
            compressionMethod = DEFLATED (0x8 = 8)
            fileModTime = 0x90A3 = 37027
            fileModDate = 0x4E5C = 20060
            crc32 = 0x0 = 0
            compressedSize = 0x1640 = 5696
            uncompressedSize = 0x73A1 = 29601
            fileNameLen = 0xD = 13
            extraLen = 0x0 = 0
            fileName = Pages/14.xaml
            extra [Extras]
        body = [179, 182, 206, 51, 75, 223, 3, 24, ...]
```

- crc32 = 0x0
- compressedSize = 0x1640 = 5696
    - => matches body length
    ```bash
    python -c 'print(abs(int("0x202fc", 16) - int("0x2193b", 16)) + 1)'
    ```

### password

- flag = 0x1
- https://sevenzip.osdn.jp/chm/cmdline/switches/password.htm

```bash
patch.py 1_2.zip 4 0x14 # version
patch.py 1_2.zip 5 0
patch.py 1_2.zip 6 1 # flags
patch.py 1_2.zip 0x362 0x14 # versionMadeBy
patch.py 1_2.zip 0x363 0
patch.py 1_2.zip 0x364 0x14 # versionNeededToExtract
patch.py 1_2.zip 0x365 0
patch.py 1_2.zip 0x366 1 # flags

patch.py 1_2.zip 4 0x14
patch.py 1_2.zip 5 0x03
patch.py 1_2.zip 6 1
patch.py 1_2.zip 0x362 0x3f
patch.py 1_2.zip 0x363 0x03
patch.py 1_2.zip 0x364 0x14
patch.py 1_2.zip 0x365 0x03
patch.py 1_2.zip 0x366 1
```

### case studies

- https://codisec.com/backdoorctf16-crc/
    - bruteforce crc
- [Does Microsoft OneDrive export large ZIP files that are corrupt?](https://www.bitsgalore.org/2020/03/11/does-microsoft-onedrive-export-large-ZIP-files-that-are-corrupt)
    - ZIP64 end of central dir locator, total number of disks: expected 1, got 0
- [Shrink, Reduce, and Implode: The Legacy Zip Compression Methods](https://www.hanshq.net/zip2.html)

# Rob Northern Compression (RNC)

- [RNC · CorsixTH/CorsixTH Wiki · GitHub](https://github.com/CorsixTH/CorsixTH/wiki/RNC)
- [RNC ProPack \- MultimediaWiki](https://wiki.multimedia.cx/index.php/RNC_ProPack)

# Apple Disk Image / Apple Driver Map (dmg)

```bash
# Decompress
dmg2img foo.dmg
# ||
7z x foo.dmg

# Validation
file -ib ~/Downloads/SF-Font-Pro.dmg
# application/zlib; charset=binary
file -ib foo.img
# application/x-apple-diskimage; charset=binary

# Extract files from filesystem
sudo mount -t hfsplus -o force,rw foo.dmg ~/media/dmg
# ||
7z x foo.img
7z x bar.pkg
7z x Payload~

# Validation
grep HFS /boot/config-"$(uname --kernel-release)"
find /lib/modules/"$(uname --kernel-release)" -name "hfs*.ko*"
modinfo hfs hfsplus
```

- [p7zip / Bugs / \#113 zip extraction loss execute bit in applications](https://sourceforge.net/p/p7zip/bugs/113/)
- [How to work with DMG files on Linux](https://eastmanreference.com/how-to-work-with-dmg-files-on-linux)
