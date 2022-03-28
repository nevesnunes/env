# +

- [Volatility \- CheatSheet \- HackTricks](https://book.hacktricks.xyz/forensics/volatility-examples)
- [GitHub \- HellishPn/Volatility\-MM\-CS: Volatility MindMap &amp; Cheat Sheet](https://github.com/HellishPn/Volatility-MM-CS)

- https://volatility-labs.blogspot.com/2012/10/solving-grrcon-network-forensics.html
- https://www.andreafortuna.org/category/volatility/
    - https://www.andreafortuna.org/2017/06/25/volatility-my-own-cheatsheet-part-1-image-identification/
    - https://www.andreafortuna.org/2017/07/03/volatility-my-own-cheatsheet-part-2-processes-and-dlls/
    - https://www.andreafortuna.org/2017/07/10/volatility-my-own-cheatsheet-part-3-process-memory/
- https://github.com/5h3r10ck/CTF_Writeups/tree/master/InCTF
    - pstree > cmdline > filescan > dumpfiles -Q

# Command Sequences

### Profile

```bash
volatility -f foo.vmem kdbgscan
# ||
volatility -f foo.vmem imageinfo
```

```
Instantiating KDBG using: foo.vmem WinXPSP2x86 (5.1.0 32bit)
Offset (P)                    : 0x2c560a0
KDBG owner tag check          : True
Profile suggestion (KDBGHeader): Win7SP1x64
PsActiveProcessHead           : 0x2c8cb90
PsLoadedModuleList            : 0x2caae90
KernelBase                    : 0xfffff80002a65000
```

- Windows 8+:
    - `--kdbg=$KdCopyDataBlock`

```bash
volatility -f foo.vmem --profile=Win7SP1x64 pstree | tee pstree.out
```

```
0xfffffa800d029b30:explorer.exe                     2188    596     36    818 2020-07-22 09:05:19 UTC+0000
. 0xfffffa800cfec710:vmtoolsd.exe                    2428   2188      9    196 2020-07-22 09:05:20 UTC+0000
. 0xfffffa800cffdb30:chrome.exe                      1344   2188      0 ------ 2020-07-22 09:06:37 UTC+0000
```

### file system

1. MFTParser - Find interesting files
2. Filescan - Find the physical address of the file
3. Dumpfiles - Extract file

mftparser

```
Access Date                    Name/Path
------------------------------ ---------
2020-07-21 02:45:01 UTC+0000   calc.exe
```

- MFTECmd
    - detect timestomping - history of created timestamps

filescan
```
0x000000003fb5cb30 chrome.exe         2520   1344 0x0000000029dfe000 2020-07-22 09:06:57 UTC+0000   2020-07-22 09:07:03 UTC+0000  
0x000000003fdfdb30 chrome.exe         1344   2188 0x000000000f760000 2020-07-22 09:06:37 UTC+0000   2020-07-22 09:07:03 UTC+0000  
```

amcache

shimcache

- https://github.com/mandiant/ShimCacheParser
    - HKLM\SYSTEM\CurrentControlSet\Control\SessionManager\AppCompatCache\AppCompatCache

```
2009-07-14 01:38:57 UTC+0000   \??\C:\Windows\system32\calc.exe
2020-07-10 22:34:46 UTC+0000   \??\C:\Program Files (x86)\Google\Chrome\Application
```

userassist

```
REG_BINARY    %windir%\system32\calc.exe :
Count:          16
Focus Count:    29
Time Focused:   0:06:40.529000
Last updated:   2020-07-21 18:21:35 UTC+0000
```

prefetch

```
CALC.EXE-AC08706A.pf                       2020-07-22 09:06:32 UTC+0000    12    23850
CHROME.EXE-5FE9909D.pf                     2020-07-22 09:06:37 UTC+0000    53    20370
```

```ps1
fsutil volume filelayout 'C:\Program Files (x86)\Google\Chrome\Application\chrome.exe'
gci C:\Windows\Prefetch\chrome.exe* | % { C:\Users\f\opt\PECmd.exe -f $_.FullName | sls 'count|(last run)' }
```

```
Run count: 7
Last run: 2020-07-31 22:43:03
Run count: 13
Last run: 2020-07-31 22:41:47
Run count: 7
Last run: 2020-07-31 22:43:04
Run count: 7
Last run: 2020-07-31 22:43:03
Run count: 21
Last run: 2020-07-31 22:41:45
```

### registry

hivelist

```
0xfffff8a001993010 0x00000000143d2010 \??\C:\Windows\ServiceProfiles\NetworkService\NTUSER.DAT
0xfffff8a001a23010 0x0000000015d26010 \??\C:\Windows\ServiceProfiles\LocalService\NTUSER.DAT
0xfffff8a00256d010 0x00000000005dd010 \??\C:\Users\Adam\ntuser.dat
```

- https://www.andreafortuna.org/2017/07/31/volatility-my-own-cheatsheet-part-6-windows-registry/
    - https://forensicswiki.xyz/wiki/index.php?title=List_of_Windows_MRU_Locations
- https://github.com/EricZimmerman/RECmd
    - https://github.com/EricZimmerman/RegistryPlugins/blob/master/RegistryPlugin.OpenSavePidlMRU/OpenSavePidlMRU.cs
- https://www.nirsoft.net/utils/open_save_files_view.html

# search, grep

```bash
~/opt/volatility \
    yarascan -Y "FwordCTF{" -p 3700,3752,2560,3304,3304,3528,616,540,3816,2516,3992 \
    --profile=Win7SP1x64 \
    --kdbg=0xf80002c48120 \
    -f ~/share/ctf/FWordCTF2020/foren.raw
# ||
~/opt/volatility \
    memmap -p 2560 \
    --profile=Win7SP1x64 \
    --kdbg=0xf80002c48120 \
    -f ~/share/ctf/FWordCTF2020/foren.raw \
    | awk '/0x/ {print $2 " " $3}' \
    | while read -r i j; do dd skip=$i count=$j iflag=skip_bytes,count_bytes \
        | rg -a "FwordCTF\{" 2560.dmp; done
# ||
~/opt/volatility \
    memdump -p 2560 --dump-dir . \
    --profile=Win7SP1x64 \
    --kdbg=0xf80002c48120 \
    -f ~/share/ctf/FWordCTF2020/foren.raw
rg -a "FwordCTF\{" 2560.dmp

# utf-16
rg -a "foo" ./bar; rg -a -e utf-16 "foo" ./bar
# ||
grep -a "foo" ./bar; grep -Pa "$(echo "foo" | sed 's/\(.\)/\1\x00/g')" ./bar
```

https://www.andreafortuna.org/2017/07/10/volatility-my-own-cheatsheet-part-3-process-memory/
