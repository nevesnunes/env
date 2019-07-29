jar xvf ./foo
java -XX:MaxPermSize=256m -Xmx1024M -jar ./foo -unpack

zip -FF
    recreates central dir
    :( does not recompute bad crc

extract ignoring crc
    => already done by `jar`
    ```
    java.util.zip.ZipException: invalid entry CRC (expected 0x0 but got 0xd0d30aae)
    vs
    java.io.IOException: Push back buffer is full
    ```

deflate vs deflate64
    => use `binwalk` instead of `jar`
    ```
    java.util.zip.ZipException: invalid compression method
    ```

```
python -c 'print(abs(int("0x202fc", 16) - int("0x2193b", 16)) + 1)'
5696
```

# password

https://sevenzip.osdn.jp/chm/cmdline/switches/password.htm

flag = 0x1

patch.py 1_2.zip 4 0x14 # version
patch.py 1_2.zip 5 0
patch.py 1_2.zip 6 1 # flags
patch.py 1_2.zip 0x362 0x14 # versionMadeBy
patch.py 1_2.zip 0x363 0
patch.py 1_2.zip 0x364 0x14 # versionNeededToExtract
patch.py 1_2.zip 0x365 0
patch.py 1_2.zip 0x366 1 # flags

# +

https://zlib.net/manual.html#Advanced

bruteforce crc
    https://codisec.com/backdoorctf16-crc/

direct deflate
    https://github.com/ResultsMayVary/ctf/tree/master/PlaidCTF-2017/misc50_zipper

dictionary - improves run-length encoding
    https://news.ycombinator.com/item?id=9288710
    https://stackoverflow.com/questions/2011653/how-to-find-a-good-optimal-dictionary-for-zlib-setdictionary-when-processing-a

https://en.wikipedia.org/wiki/DEFLATE
http://www.zlib.org/rfc-zlib.html

---

zip -F ./foo --out ./bar
zip -FF ./foo --out ./bar

binwalk --dd='.*' ./foo
binwalk -e ./foo

binwalk expects p7zip, so install p7zip to fix this problem.
    The UnZip implementation is the cause of your problem. When binwalk extracts full, the first ZIP actually contains both ZIPs, but UnZip only extracts the last one (which is also stored independently in the second ZIP that binwalk extracted).
    -- https://reverseengineering.stackexchange.com/questions/13944/automatically-extract-known-file-types-eg-zip-using-binwalk

https://reverseengineering.stackexchange.com/questions/13616/simple-carving-of-zip-file-using-binwalk


