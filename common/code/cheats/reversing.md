# +

- [asm](./asm.md)
- [wasm](./wasm.md)
- [evasion](./evasion.md)

- [ghidra](ghidra.md)
- [ida](ida.md)
- [r2](r2.md)

- [angr](./angr.md)
- [frida](./frida.md)
- [strace](./strace.md)
- [z3](./z3.md)

- text
    - any format: `strings` (`-el` for 16-bit le)
    - ELF format: [match x86 that appears to be stack string creation · GitHub](https://gist.github.com/williballenthin/ed7b3de224d5b986bc04dc882c5ee7c5)
    - PE format:
        - `floss` (extracts stack strings)
        - [Script to generate stackstrings YARA signatures for common implementation patterns · GitHub](https://gist.github.com/notareverser/4f6b9c644d4fe517889b3fbb0b4271ca)
        - [GitHub \- CybercentreCanada/assemblyline\-service\-frankenstrings: Assemblyline 4 IOC and String extraction service](https://github.com/CybercentreCanada/assemblyline-service-frankenstrings)
- syscalls, dynamic library calls
    - any format: [GitHub \- maroueneboubakri/lscan: lscan is a library identification tool on statically linked/stripped binaries](https://github.com/maroueneboubakri/lscan)
        - [GitHub \- push0ebp/ALLirt: Tool that converts  All of libc to signatures for IDA Pro FLIRT Plugin\. and utility make sig with FLAIR easily](https://github.com/push0ebp/ALLirt)
        - [GitHub \- CheckPointSW/Karta: Karta \- source code assisted fast binary matching plugin for IDA](https://github.com/CheckPointSW/Karta)
    - ELF format:
        - static
            - `ldd -iv` (validates shared libraries initialization)
            - `./pax-utils/lddtree.py` (tree formatting)
            - [GitHub \- marin\-m/vmlinux\-to\-elf: A tool to recover a fully analyzable \.ELF from a raw kernel, through extracting the kernel symbol table \(kallsyms\)](https://github.com/marin-m/vmlinux-to-elf)
        - dynamic
            - `LD_DEBUG=files /bin/ls >/dev/null 2>&1 | grep needed`
            - `ltrace -if`
            - `strace -X verbose -if -s 9999`
    - PE format:
        - `procmon`
        - [GitHub \- fireeye/capa: The FLARE team&\#39;s open\-source tool to identify capabilities in executable files\.](https://github.com/fireeye/capa)
        - [GitHub \- microsoft/ApplicationInspector: A source code analyzer built for surfacing features of interest and other characteristics to answer the question &\#39;What&\#39;s in the code?&\#39; quickly using static analysis with a json based rules engine\. Ideal for scanning components before use or detecting feature level changes\.](https://github.com/microsoft/ApplicationInspector)
        - [GitHub \- CobaltFusion/DebugViewPP: DebugView\+\+, collects, views, filters your application logs, and highlights information that is important to you!](https://github.com/CobaltFusion/DebugViewPP)
    - signatures detection with parameter names on pushed registers
        - [ghidra](./ghidra.md#FID)
        - [IDA](./ida.md#FLIRT)
- branches
    - [An introduction to last branch records \(LWN\.net\)](https://lwn.net/Articles/680985/)
    - [Advanced usage of last branch records \(LWN\.net\)](https://lwn.net/Articles/680996/)
    - [Last branch records and branch tracing \- CodeProject](https://www.codeproject.com/Articles/517466/Last-branch-records-and-branch-tracing)
- resources
    - PE format: `wrestool`
    - NE format:
        - [GitHub \- david47k/neresex: Resource extractor for Windows 3\.xx 16\-bit New Executable \(NE\) files](https://github.com/david47k/neresex)
        - Borland Resource Workshop
        - eXeScope
- types
    - [GitHub \- ampotos/dynStruct: Reverse engineering tool for automatic structure recovering and memory use analysis based on DynamoRIO and Capstone](https://github.com/ampotos/dynStruct)
- linkers
    - https://github.com/RolfRolles/Miscellaneous/blob/master/MSVC-CRT.md
    - [GitHub \- horsicq/Nauz\-File\-Detector: Linker/Compiler/Tool detector  for Windows, Linux and MacOS\.](https://github.com/horsicq/Nauz-File-Detector)
        - [GitHub \- horsicq/SpecAbstract](https://github.com/horsicq/SpecAbstract)
- object manager namespace
    - [WinObj \- Windows Sysinternals \| Microsoft Docs](https://docs.microsoft.com/en-us/sysinternals/downloads/winobj)
- installers
    - [GitHub \- Bioruebe/UniExtract2: Universal Extractor 2 is a tool to extract files from any type of archive or installer\.](https://github.com/Bioruebe/UniExtract2)
- packers
    - [GitHub \- horsicq/Detect\-It\-Easy: Program for determining types of files for Windows, Linux and MacOS\.](https://github.com/horsicq/Detect-It-Easy)
    - [GitHub \- ExeinfoASL/ASL: ExeinfoPE](https://github.com/ExeinfoASL/ASL)
    - [methodologies](./evasion.md#generic)
- roms
    - [Symgrate \- A Web API for Thumb2 Firmware Reverse Engineering](https://symgrate.com/)
    - [uCON64 \- ReadMe](https://ucon64.sourceforge.io/ucon64/readme.html)
    - [GitHub \- al3xtjames/ghidra\-firmware\-utils: Ghidra utilities for analyzing PC firmware](https://github.com/al3xtjames/ghidra-firmware-utils)
    - [GitHub \- jrspruitt/ubi\_reader: Collection of Python scripts for reading information about and extracting data from UBI and UBIFS images\.](https://github.com/jrspruitt/ubi_reader)
    - [FlashcatUSB \- Flashcat Memory Programmers \- NAND NOR Serial and Parallel](https://flashcatusb.com/)
    - [Hex2bin](http://hex2bin.sourceforge.net/)
    - [SRecord \- Tools for manipulating EPROM load files](http://srecord.sourceforge.net/)
- drivers
    - windows in VM, plug USB adapter, run vendor software in the vm, run usbmon + wireshark on the host
- debuginfo
    - [GitHub \- wbenny/pdbex: pdbex is a utility for reconstructing structures and unions from the PDB into compilable C headers](https://github.com/wbenny/pdbex)
    - [GitHub \- camden\-smallwood/pdb\-decompiler: A tool to decompile MSVC PDB files to C\+\+ source code\.](https://github.com/camden-smallwood/pdb-decompiler)
    - [GitHub \- seilweiss/dwarf2cpp: Converts DWARF v1 debug data into C/C\+\+ definitions\.](https://github.com/seilweiss/dwarf2cpp)
- constants
    - e.g.
        ```python
        # localhost ip address prefix
        >>> ''.join([struct.pack('<B', x).hex() for x in [192,168]])
        'c0a8'
        # unix timestamp
        >>> struct.pack('<L', int(time.time())).hex()
        '88da6b62'
        ```
    - [The Magic Number Database \| MagnumDB](https://www.magnumdb.com/)
    - [The On\-Line Encyclopedia of Integer Sequences&reg; \(OEIS&reg;\)](https://oeis.org/)
    - [FindCrypt \- Hex Rays](https://hex-rays.com/blog/findcrypt/)
    - https://hiddencodes.wordpress.com/2011/12/23/string-manipulation-functions-in-glibc-ms-visual-studio-and-0x7efefeff-0x81010100-0x81010101/
- data structures
    - find addresses pointing to lists of names + other fields
        - modify nearby addresses and observe effects
    - object references
        - Text search for unique method / member offset
            - e.g. byte at +174h: `movb al, [rcx+174h]`
        - [Immediate search](https://hex-rays.com/blog/igors-tip-of-the-week-48-searching-in-ida/)
    - asm
        - global
            ```fasm
            mov     ds:dword_405020, 1
            mov     ds:dword_405024, 2
            mov     ds:dword_405028, 3
            ```
        - local
            ```fasm
            mov     [esp+30h+var_18], 1
            mov     [esp+30h+var_14], 2
            mov     [esp+30h+var_10], 3
            ```
        - heap
            ```fasm
            mov     eax, [esp+20h+var_4]
            mov     dword ptr [eax], 1
            mov     dword ptr [eax+4], 2
            mov     dword ptr [eax+8], 3
            ```
- visual structure
    - https://binvis.io/
        - https://github.com/binvis/binvis.io
        - https://github.com/cortesi/scurve
    - https://justine.storage.googleapis.com/memzoom/index.html
    - [GitHub \- katjahahn/PortEx: Java library to analyse Portable Executable files with a special focus on malware analysis and PE malformation robustness](https://github.com/katjahahn/PortEx)
    - [Hex viewers and editors](https://twitter.com/i/events/841916822014332930)
- memory scanner
    - [GitHub \- scanmem/scanmem: memory scanner for Linux](https://github.com/scanmem/scanmem)
    - [GitHub \- gamozolabs/mempeek: A command line tool that resembles a debugger as well as Cheat Engine, to search for values in memory](https://github.com/gamozolabs/mempeek)
- hex diff
    - [GitHub \- 8051Enthusiast/biodiff: Hex diff viewer using alignment algorithms from biology](https://github.com/8051Enthusiast/biodiff)
        - e.g. [Test Point Break: Analysis of Huawei’s OTA Fix For BootROM Vulnerabilities \- taszk\.io labs](https://labs.taszk.io/articles/post/huawei_kirin990_bootrom_patch/)
    - [GitHub \- juhakivekas/multidiff: Binary data diffing for multiple objects or streams of data](https://github.com/juhakivekas/multidiff)
- binary diff
    - [GitHub \- joxeankoret/pigaios: A tool for matching and diffing source codes directly against binaries\.](https://github.com/joxeankoret/pigaios)
    - [GitHub \- joxeankoret/diaphora: Diaphora, the most advanced Free and Open Source program diffing tool\.](https://github.com/joxeankoret/diaphora)
        - [GitHub \- FernandoDoming/r2diaphora](https://github.com/FernandoDoming/r2diaphora)
    - [DarunGrim: A Patch Analysis and Binary Diffing Tool](http://www.darungrim.org/)
    - [radiff2](https://radareorg.github.io/blog/posts/binary-diffing/)
    - [GitHub \- ubfx/BinDiffHelper: Ghidra Extension to integrate BinDiff for function matching](https://github.com/ubfx/BinDiffHelper)
    - [Limits of Ghidra Patch Diffing](https://blog.threatrack.de/2019/10/17/ghidra-patchdiff-cve-2019-3568/)
    - [Patch Diffing a Cisco RV110W Firmware Update \(Part II\) \| QTNKSR](https://quentinkaiser.be/exploitdev/2020/10/01/patch-diffing-cisco-rv110/)
- entropy
    - binwalk
        ```bash
        # Given $PYTHONPATH with matplotlib:
        env PYTHONPATH="$HOME/.local/lib/python3.8/site-packages" binwalk --entropy
        ```
    - audacity
    - e.g. high valued with some drops
        > clear-text bootloader is the one in charge of decrypting the other partitions during the boot process
        - https://www.shielder.com/blog/2022/03/reversing-embedded-device-bootloader-u-boot-p.1/
- frequency analysis
    ```bash
    xxd -p < foo | paste -sd '' | sed 's/\(..\)/\1\n/g' | sort | uniq -c | sort -n

    # ||
    sed 's/\(.\)/\1\n/g' < foo | LC_ALL=C awk -F "" '
    BEGIN {
        for (i = 0; i <= 255; i++) {
            t = sprintf("%c", i)
            ord[t] = sprintf("%x", i)
        }
    }
    { freq[$0]++; }
    END {
        for (i in freq) {
            printf("%8d %2s\n", freq[i], ord[i]);
        }
    }
    ' | sort -n
    ```

- [Program Analysis Reading List &mdash; Möbius Strip Reverse Engineering](https://www.msreverseengineering.com/program-analysis-reading-list)
- [GitHub \- alphaSeclab/obfuscation\-stuff: Source Code Obfuscation And Binary Obfuscation, Multiple Languages And Multiple Platforms\. Including 250\+ Tools and 600\+ Posts](https://github.com/alphaSeclab/obfuscation-stuff)

# methodologies

- overview
    - make state explicit: tracing, instrumentation, diffing, input PoCs (e.g. change 1 byte/field on each iteration)...
        - [Ali Rizvi-Santiago @ OffensiveCon22 \- Mark Dowd\- Keynote \-How Do You Actually Find Bugs? \- YouTube](https://www.youtube.com/watch?v=7Ysy6iA2sqA&lc=Ugy8whDYBW9MnPSJhWF4AaABAg)
            > - Simple reversing tip: If you're doing static-reversing, first thing you should _always_ do to help slice out things of relevance is to run a hit-trace (coverage) so you know what code is actually relevant, and what code does _not_ get exercised. It's worth considering analyzing the code that doesn't get exercised.
            > - Also, don't be allergic to writing code... Simple things like storing your results in a set and augmenting your function notations or coloring your addresses is such a low-effort power. Think of it like this, how can you quickly find the code that's responsible for parsing input from a socket without having to do any reversing? Collect a set of all of the functions that are executed. That's set #1. Now connect to socket and send some data a couple of times, set2 (or set3 or set4). After union'ing your second set of sets, diff the results from set1. Now you know where the parser starts. There's embedded languages in all debuggers and disassemblers, make sure you use them because you get them for free.
    - follow interfaces: apis, tests, modes, algorithmic functions (e.g. decompression)...
    - know the shape of data: addresses, structs, protocols...
        - https://margin.re/media/an-opinionated-guide-on-how-to-reverse-engineer-software-part-1.aspx
    - bottom-up analysis: constants (e.g. error message string, unique numbers), conditional control-flow (e.g. when is error handler called)...
- taxonomies
    - str array: strs are accessed w/ an offset from the 1st str (array base), which _will_ have an xref
    - algorithm: google constants
    - hashing: branchless xors/rols
        - https://blog.whtaguy.com/2020/04/guys-30-reverse-engineering-tips-tricks.html
- enumerate exports, imports, syscalls, xrefs to winapi, registry keys, services, dll dependencies, handles, mutex, strings
    - lifecycle
        - before OEP
            - ELF format: init_array
            - PE format: TLS callback (IMAGE_DIRECTORY_ENTRY_TLS), `_initterm()`
        - debugger: break on thread exit, dll unload, process exit, then check stack
        - [Intercepting Program Startup on Windows and Trying to Not Mess Things Up / Habr](https://habr.com/en/post/544456/)
    - finding `main()` function
        - any format:
            - follow xrefs to exit(), find which function's return value (saved in rax) is passed to exit()
            > Basically rax contains the return code of "main". When main ends, the return code of the program is sent to exit() (and later on to ExitProcess(), on windows)
        - ELF format: on `entry()`, take 1st argument to `__libc_start_main()`
        - PE format: `mainCRTStartup(), __scrt_common_main_seh() > invoke_main()`
    - calling functions
        - any format:
            ```python
            import ctypes

            user32_dll = ctypes.cdll.LoadLibrary('User32.dll')
            print(user32_dll.GetDoubleClickTime())

            # libc = ctypes.cdll.msvcrt # Windows
            # libc = ctypes.CDLL('libc.dylib') # Mac
            libc = ctypes.CDLL('libc.so') # Linux and most other *nix
            libc.printf(b'hi there, %s\n', b'world')
            ```
        - ELF format: https://github.com/taviso/ctypes.sh
        - PE format: https://blog.whtaguy.com/2020/04/calling-arbitrary-functions-in-exes.html?m=1
    - filesystem
        - FileRead/FileWrite calls
        - FileDelete monitoring and recovery
            - https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon#event-id-23-filedelete-file-delete-archived
            - [Sysinternals Update April 2020 \- YouTube](https://www.youtube.com/watch?v=_MUP4tgdM7s)
    - events
        - Windows: debugview / tracelog -kd + tracefmt, [windbg](./windbg.md#trace-sessions), eventvwr, evtutil
        - Linux: dmesg, journalctl
    - networking
        - https://www.aldeid.com/wiki/FakeNet
        - hw read break on packet buffer, frida hook on winsock calls
        - [ws2\_32 recv/send](https://docs.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-recv)
        - [WSARecvFrom/WSASendTo](https://docs.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsasendto)
    - registry
        - [Regshot \- take a snapshot of your registry and then compare it with a second one](https://sourceforge.net/projects/regshot/)
        - [REGDIFF \- command line tool to compare two registry files, export the registry, merge .REG files](http://p-nand-q.com/download/regdiff.html)
        - [GitHub \- bitranox/fingerprint: Monitoring Registry and File Changes in Windows](https://github.com/bitranox/fingerprint)
    - APIs
        - [API Monitor: Spy on API Calls and COM Interfaces \(Freeware 32\-bit and 64\-bit Versions!\) \| rohitab\.com](http://www.rohitab.com/apimonitor)
        - [WinAPIOverride : Free Advanced API Monitor, spy or override API or exe internal functions](http://jacquelin.potier.free.fr/winapioverride32/)
        - [GitHub \- poona/APIMiner: API Logger for Windows Executables](https://github.com/poona/APIMiner/)
        - [GitHub \- hasherezade/tiny\_tracer: A Pin Tool for tracing API calls etc](https://github.com/hasherezade/tiny_tracer)
        - [GitHub \- microsoft/Detours: Detours is a software package for monitoring and instrumenting API calls on Windows\.  It is distributed in source code form\.](https://github.com/microsoft/Detours)
            - e.g. http://web.archive.org/web/20070222031635/http://www.matasano.com/log/620/hand-detouring-windows-function-calls-with-ht/
            - e.g. https://wheybags.com/blog/emperor.html
        - [GitHub \- CodeCracker\-Tools/MegaDumper: Dump native and \.NET assemblies](https://github.com/CodeCracker-Tools/MegaDumper)
        - [GitHub \- tyranid/oleviewdotnet: A \.net OLE/COM viewer and inspector to merge functionality of OleView and Test Container](https://github.com/tyranid/oleviewdotnet)
        - [oledump\.py \| Didier Stevens](https://blog.didierstevens.com/programs/oledump-py/)
        - [RpcView](http://rpcview.org)
        - [GitHub \- mrexodia/phnt\-single\-header: Single header version of System Informer&\#39;s phnt library\.](https://github.com/mrexodia/phnt-single-header)
    - debug symbols
        - take old versions, patches, API examples, API clients
            - e.g. https://lock.cmpxchg8b.com/lotus123.html
        - Windows:
            - Run-time type information (RTTI)
                - applies to classes with virtual functions, compiled with Visual Studio
                - describes vtable function addresses, type, and level of inheritance (hierarchy)
                - https://sourceforge.net/projects/classinformer/
                - https://docs.microsoft.com/en-us/cpp/cpp/run-time-type-information?view=msvc-160
            - .pdb
                - [GitHub \- MolecularMatters/raw\_pdb: A C\+\+11 library for reading Microsoft Program DataBase PDB files](https://github.com/MolecularMatters/raw_pdb)
                - [GitHub \- KirillOsenkov/Dia2Dump: Taken from C:\\Program Files \(x86\)\\Microsoft Visual Studio\\2017\\Enterprise\\DIA SDK\\Samples\\DIA2Dump](https://github.com/KirillOsenkov/Dia2Dump)
                - [PDB Downloader](https://github.com/rajkumar-rangaraj/PDB-Downloader)
                - https://docs.microsoft.com/en-us/visualstudio/debugger/debug-interface-access/querying-the-dot-pdb-file?view=vs-2019
        - [GitHub \- binsync/binsync: A collaborative reversing plugin for cross\-decompiler collaboration, built on git\.](https://github.com/binsync/binsync)
    - id functions without debug symbols
        - take old version introducing specific logic in changelog, then bindiff with current version
    - headers
        - [pestudio](https://www.winitor.com/features)
        - [pe-bear](https://hshrzd.wordpress.com/pe-bear/)
    - protocols
        - versioning: magic bytes
        - packet fragmentation: length of remaining bytes; sequence numbers
        - https://en.wikipedia.org/wiki/Type%E2%80%93length%E2%80%93value
            - invalid size may lead to unchecked memory read/write
- binary patching, code injection, [fault inducing](./fuzzing.md#fault-injection)
    - converting calls to jmps to disassemble as subroutine (e.g. un-nest calls, recover params/returned values on atypical calling conventions)
        - https://ctf.harrisongreen.me/2020/googlectf/exceptional/
            - use `jz 5 + jmp foo + jmp bar` for multiple targets
    - static instrumentation by taking instructions from another compiled source
        - https://mrt4ntr4.github.io/Noverify-Java-Crackme-3/
            - adding prints via Recaf
        - https://ctf.harrisongreen.me/2020/redpwnctf/java_is_ez_2/
            - adding prints via JByteMod
        - https://ctf.harrisongreen.me/2021/midnightsunfinals/elbrus/
            > Most of my experience with patching at this point relied on either disassemblers like Binary Ninja or programatically modifying certain instructions at the assembly level. However, since there is no existing interactive disassembler for Elbrus and I don’t understand it well enough to program assembly for it, I used the e2k-gcc tool to compile C code and then simply copied the instructions directly into the binary.
            ```c
            // Patch into check
            void foo() {
                // check is too small to hold all three of the calls so we need
                // to use a short trampoline to jump into a separate area.
                void (*_target)() = (void (*)())(0x53b10);
                _target();
            }

            // Patch into 0x53b10 (unused libc function)
            int main() {
                void (*__libc_write)(int fd, const void *buffer, unsigned long size) = (void (*)())(0x6b188);
                void (*_exit)(int r) = (void (*)())(0x68cf8);
                void *buf1 = (void *)0x1af250;
                void *buf2 = (void *)0x1b25d8;

                __libc_write(1, buf1, 12 * 4);
                __libc_write(1, buf2, 12 * 4);
                _exit(0);
            }
            ```
    - removing field in request to trigger error message
        - https://ferib.dev/blog.php?l=post/How_I_automated_McDonalds_mobile_game_to_win_free_iphones
    - image parsing coverage changes on error
        > produce a blank image, add one pixel (say purple - that is 50% Red, 50% Blue, 0% Green), change the color of the pixel, then change the location of the pixel, to see how the BMP binary code changes.
    - identifying variables
        - if small address space, then watch memory value changes on input action; override memory address with static value; turn function into no-op by setting first instruction to a return
            - [Reprogramming Mega Man 4&\#39;s Charged Shot \- Behind the Code \- YouTube](https://www.youtube.com/watch?v=n1yloWiWVxY)
    - disable function (e.g. patch `ret`)
    - find threads by patching a jump with a short jump (x86: `EBFE`) to create an endless loop you can then search for
    - chaining trampolines to follow dynamic/obfuscated blocks
        - http://www.giovanni-rocca.com/reverse-engineering-supercell-part-6/
    - [GitHub \- jxy\-s/vfdynf: Application Verifier Dynamic Fault Injection](https://github.com/jxy-s/vfdynf)
- monitoring
    - file system, accounts, services, ports, certificate stores, registry
        - snapshot before and after installation, then before and after execution
        - https://github.com/Microsoft/AttackSurfaceAnalyzer
        - https://www.microsoft.com/security/blog/2019/05/15/announcing-new-attack-surface-analyzer-2-0/
    - memory maps
        - snapshot at `entry()`, then check if executable section became writable and modified at later snapshot
        - diff/search for data changes before and after blocks: loops, func calls...
        - hook `memcpy()` + `strcpy()`
- efficiency
    - https://blog.perfect.blue/perfect-blue-finishes-top-1-on-CTFtime-2020
        > So one of the key strategies for us is to stockpile solution templates. For us at least, there’s no excuse for not having a canned solution when encountering a stereotyped problem. From our experience, we would say around 50% of challenges are stereotyped.
        > Necessity is the mother of invention—we’ve learned a lot of tools in-depth as a result. [...] The importance of tooling is universal: it could mean the difference between 1 month of manual effort or just 1 hour.

- [Tampering and Reverse Engineering - Mobile Security Testing Guide](https://mobile-security.gitbook.io/mobile-security-testing-guide/general-mobile-app-testing-guide/0x04c-tampering-and-reverse-engineering)
- https://breaking-bits.gitbook.io/breaking-bits/vulnerability-discovery/reverse-engineering/modern-approaches-toward-embedded-research

# lifting

- asm to c
    - [UIUCTF 2021 Ropfuscated Writeup \- HackMD](https://hackmd.io/@M30W/UIUCTF2021-Ropfuscated-Writeup)
    - [ia32rtools/saveasm\.cpp at master · notaz/ia32rtools · GitHub](https://github.com/notaz/ia32rtools/blob/master/ida/saveasm/saveasm.cpp)
    - [ia32rtools/translate\.c at master · notaz/ia32rtools · GitHub](https://github.com/notaz/ia32rtools/blob/master/tools/translate.c)
    - [alpha\_waves\_loader/original\_port\.cpp at main · LowLevelMahn/alpha\_waves\_loader · GitHub](https://github.com/LowLevelMahn/alpha_waves_loader/blob/main/read_some_file_sub_4/original_port.cpp)
- [GitHub \- vtil\-project/VTIL\-Utils: VTIL command line utility](https://github.com/vtil-project/VTIL-Utils)
    - e.g. lift single function with NoVmp, then: `vtil dump 1234.optimized.vtil`
- [GitHub \- lifting\-bits/mcsema: Framework for lifting x86, amd64, aarch64, sparc32, and sparc64 program binaries to LLVM bitcode](https://github.com/lifting-bits/mcsema)
    - [GitHub \- lifting\-bits/remill: Library for lifting of x86, amd64, and aarch64 machine code to LLVM bitcode](https://github.com/lifting-bits/remill)
    - [Rewriting Functions in Compiled Binaries \| Trail of Bits Blog](https://blog.trailofbits.com/2019/09/02/rewriting-functions-in-compiled-binaries/)
        - alternative: append a section and redirect the function to your rewritten function

# llvm

- https://llvm.org/docs/LangRef.html
- Optimization Pipeline Viewer
    - e.g. https://godbolt.org/z/xa7q4GToz

```sh
# disasm
clang -emit-llvm -S foo.c -o foo.ll
llvm-as foo.ll -o foo.bc
llvm-dis foo.bc -o foo.ll

# lower from mlir
mlir-opt --convert-std-to-llvm foo.mlir -o foo.llvm.mlir
mlir-translate --mlir-to-llvmir foo.llvm.mlir -o foo.bc

# run
lli foo.bc

# compile
llc -march=x86-64 foo.bc -o foo.s
clang -S foo.bc -o foo.s -fomit-frame-pointer
# ||
llc -march=x86-64 foo.bc -o foo.s
gcc foo.s externc.c -o foo
# ||
llc -march=x86-64 foo.bc -o foo.o -filetype=obj
```

# seccomp

- [GitHub \- david942j/seccomp\-tools: Provide powerful tools for seccomp analysis](https://github.com/david942j/seccomp-tools)

- register
    - https://man7.org/linux/man-pages/man2/prctl.2.html
    ```strace
    prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, {len=205, filter=0x7fffffffca50})
    ```
- format
    ```
    0x00000020  0x00000000  0xc8000015  0x00000309
    0x00000020  0x00000010  0x00000054  0x000000ff
    0x00c70035  0x00000080  0x00000020  0x00000010
    0x00000074  0x00000008  0x00000054  0x000000ff
    ```

# mba

- [Mixed Boolean\-Arithmetic Obfuscation - WASM Sandbox](https://plzin.github.io/mba-wasm/)
- [Mixed Boolean\-Arithmetic \(Part 1\): Introduction](https://plzin.github.io/posts/mba)

# vm

```asm
; foo
push vm_bytecode
call vm_entry

; vmentry: context switch w/ function prologue + epilogue
push 12345678h ; vmkey
call sub_14001234 ; vminit: decrypts bytecode using vmkey

; vm handlers: tbl that maps bytecode to semantics, looked up by vm dispatcher (fetch-decode-execute loop)
00 ; vadd
01 ; vmul
; ...

; vm dispatcher
mov bl, [rsi]
inc rsi ; if many handlers add instruction size to this var, then likely is virtual pc
movzx rax, bl
jmp __handler_tbl[rax*8]

; vpush
mov eax, dword [rdx + 1]
mov dword [rcx + 8], eax
add rcx, 8 ; virtual sp
add rdx, 5 ; virtual pc (1 + 4 bytes for operand)
jmp 0x1234

; register-based vm
; x = x + y + 1
mov rax, x
mov rbx, y
add rax, rbx
inc rax

; stack-based vm
; x = x + y + 1
vpush x
vpush y

add rdx, 1

mov eax, dword [rcx] ; load y
add dword [rcx - 8], eax ; store x + y
sub rcx, 8

vpush 1

mov eax, dword [rcx] ; load 1
add dword [rcx - 8], eax ; store x + y + 1
sub rcx, 8

jmp 0x1234
```

- finding all vmentry subroutines: trace jumps across sections (e.g. tiny_tracer)
    - [SpeakEasy writeup\. 1\. Overview \| by kishou yusa \| Medium](https://medium.com/@acheron2302/speakeasy-writeup-3af3375ab63)
- remove dead code: identify using static single assignment form, patch with nops
    - [Cracking BattlEye packet encryption \| secret club](https://secret.club/2020/06/19/battleye-packet-encryption.html)
    - [Quick blog: Remove unnecessary call with static single assignment form \| by kishou yusa \| Medium](https://medium.com/@acheron2302/quick-blog-remove-unnecessary-call-with-static-single-assignment-form-88d50a78a80)
    - https://github.com/acheron2302/Binary-ninja-plugin-collection/blob/main/snippet/Deobfuscate_OutputDebug.py
- un-flatten control flow by setting user indirect branches
    - [TetCTF 2022 \- crackme pls \(964 pt / 7 solves\)](https://ctf.harrisongreen.me/2022/tetctf/crackme_pls/)
    - [Automated Detection of Control-flow Flattening \- synthesis.io](https://synthesis.to/2021/03/03/flattening_detection.html)
- automating deofbuscation
    - use dfs over basic-blocks, follow control-flow from vmentry to vmexit, adding concrete values when stopping at conditional branches (e.g. constraint memory with bytecode value that will take a jump; set known parameter value passed in register);
        - if vmexit is reached, then output can be concrete;
        - take instruction trace to figure out how handlers are composed and extract higher-level instructions;
    - [Writing Disassemblers for VM-based Obfuscators](https://synthesis.to/2021/10/21/vm_based_obfuscation.html)
        ```
        bb_stack = [vmentry]
        while bb_stack is not empty:
            bb = bb_stack.pop()
            next_bb = symex_bb(bb)
            if next_bb is address:
                bb_stack.push(next_bb)
            else:
                print(next_bb)
        ```
    - [Analysis of Virtualization\-based Obfuscation \(r2con2021workshop\) \- YouTube](https://www.youtube.com/watch?v=b6udPT79itk)
        - [follow\_execution\_flow\.py at main · mrphrazer/r2con2021\_deobfuscation · GitHub](https://github.com/mrphrazer/r2con2021_deobfuscation/blob/main/follow_execution_flow.py)
- [ZeusVM analysis &mdash; Miasm&\#39;s blog](https://miasm.re/blog/2016/09/03/zeusvm_analysis.html)
- [An Abstract Interpretation\-Based Deobfuscation Plugin for Ghidra \- Möbius Strip Reverse Engineering](https://www.msreverseengineering.com/blog/2019/4/17/an-abstract-interpretation-based-deobfuscation-plugin-for-ghidra)
- [FinFisher exposed: A researcher’s tale of defeating traps, tricks, and complex virtual machines \- Microsoft Security Blog](https://www.microsoft.com/security/blog/2018/03/01/finfisher-exposed-a-researchers-tale-of-defeating-traps-tricks-and-complex-virtual-machines/)
- Bruce Dang, Alexandre Gazet, Elias Bachaalany - Practical Reverse Engineering
    - Chapter 5 - Obfuscation

### VMProtect

- section headers:
    - runtime section (e.g. .vmp0)
    - loader section (e.g. .vmp1): raw address = 0x400
    - .text, .data, .rdata sections' raw size / address zeroed
- [GitHub \- can1357/NoVmp: A static devirtualizer for VMProtect x64 3\.x\. powered by VTIL\.](https://github.com/can1357/NoVmp)
- [Extracting VMProtect handlers with Binary Ninja](https://www.lodsb.com/extracting-vmprotect-handlers-with-binary-ninja)

# functional programming

- [GitHub \- sjsyrek/malc: Make a lambda calculus\.](https://github.com/sjsyrek/malc)
- [Beta reduction \- HaskellWiki](https://wiki.haskell.org/Beta_reduction)
- [David Beazley \- Lambda Calculus from the Ground Up \- PyCon 2019 \- YouTube](https://www.youtube.com/watch?v=pkCLMl0e_0k)

# AST parsing

- tree-sitter
- semgrep
    - [semgrep/bridge\_design\.txt at 650422c2002007b98517bdc6c688b7f760a057bc · returntocorp/semgrep · GitHub](https://github.com/returntocorp/semgrep/blob/650422c2002007b98517bdc6c688b7f760a057bc/semgrep-core/src/cli-bridge/bridge_design.txt)
    - [semgrep/core\_runner\.py at 3e6d1dc320c79c52b258d908d57956d68d26730a · returntocorp/semgrep · GitHub](https://github.com/returntocorp/semgrep/blob/3e6d1dc320c79c52b258d908d57956d68d26730a/cli/src/semgrep/core_runner.py#L324)

# taint analysis

- [DNN\-decompiler/trace\_filter\.py at master · monkbai/DNN\-decompiler · GitHub](https://github.com/monkbai/DNN-decompiler/blob/master/trace_filter.py)

# bios

- [Reverse Engineering MenuetOS 64 \- Primary Boot Loader \| StarkeBlog](https://nstarke.github.io/bios/menuetos/2022/09/22/reverse-engineering-menuetos.html)

# scripting dissassembly

- [Programming with Python language – Capstone – The Ultimate Disassembler](https://www.capstone-engine.org/lang_python.html)
- [find\_ioctls\.py · GitHub](https://gist.github.com/uf0o/011cedcae3f52102c69c7d8c28ae678c)

# side channels

- timing attacks - On password validation routine, when a char is correct, more instructions are executed
    - ~/code/snippets/pin/count_me_if_you_can.py
    - [write\-up for dont\_panic \- Eternal Stories](http://eternal.red/2017/dont_panic-writeup/)
- syscall counting - `strace | sort | uniq -c`
- ! instruction counting disturbed by OS scheduler
    - [performance \- Perf overcounting simple CPU\-bound loop: mysterious kernel work? \- Stack Overflow](https://stackoverflow.com/questions/39864416/perf-overcounting-simple-cpu-bound-loop-mysterious-kernel-work)

```bash
# instruction counting
qemu-x86_64 -d in_asm ./a.out 2>&1 \
    | awk '/IN:/{i+=1} END{print i}'
# || :( variable inscount
~/opt/dynamorio/build/bin64/drrun -c ~/opt/dynamorio/build/api/bin/libinscount.so -- ./a.out \
    | awk '/Instrumentation results:/{print $3}'
# || :( variable inscount
gcc -O0 a.c && echo 'a' \
    | perf stat -e instructions:u ./a.out 2>&1 \
    | awk '/instructions.u/{print $1}'

# bruteforcing chars
for n in {32..127}; do
    c=$(echo $n | awk '{ printf("%c", $0); }')
    printf '%s ' $c
    ~/opt/dynamorio/build/bin64/drrun -c ~/opt/dynamorio/build/api/bin/libinscount.so -- ./a.out <(printf '%s' $c) | awk '/Instrumentation results:/{print $3}'
done 2>/dev/null | vim -
# - [Counting instructions using Stalker · Issue \#94 · frida/frida\-python · GitHub](https://github.com/frida/frida-python/issues/94)
# - https://stackoverflow.com/questions/22507169/how-to-run-record-instruction-history-and-function-call-history-in-gdb
# - https://stackoverflow.com/questions/8841373/displaying-each-assembly-instruction-executed-in-gdb/46661931#46661931
# - https://en.wikibooks.org/wiki/QEMU/Invocation

# coverage
# - differential analysis: do unrelated actions, compare traced functions against relevant action
#     - e.g. [On why my tbreak tracing trick did not work \- gynvael\.coldwind//vx\.log](https://gynvael.coldwind.pl/?id=638)
~/code/snippets/gdb/cov.py
~/opt/dynamorio/build/bin64/drrun -t drcov -dump_text -- ./a.out
diff -Nauw drcov.a.out.2575073.0000.proc.log drcov.a.out.2575098.0000.proc.log | vim -
# - source code highlighting
drcov2lcov -dir . -output cov.info -src_filter foo
genhtml cov.info --output-directory out

# - diff alternative: `lighthouse` plugin
# - https://stackoverflow.com/questions/53218160/how-can-i-do-code-path-analysis-in-a-debugger
# - https://stackoverflow.com/questions/22507169/how-to-run-record-instruction-history-and-function-call-history-in-gdb
# - https://dynamorio.org/dynamorio_docs/page_drcov.html
# - http://mysqlentomologist.blogspot.com/2021/10/bpftrace-as-codefunction-coverage-tool.html

# ||
# 1. grep xrefs from asm dump, take addresses
# 2. make gdb script with temporary breakpoint (`tbreak`) foreach address
# - [On why my tbreak tracing trick did not work \- gynvael\.coldwind//vx\.log](https://gynvael.coldwind.pl/?id=638)

# execution trace / instruction trace
# qemu
# - :) stable inscount
# - :( partial trace
# - alternative: https://github.com/MarginResearch/cannoli
qemu-x86_64 -d in_asm a.out
# pintool
# - Handbook for CTFers - Pintool Basic Framework
# - https://github.com/s3team/VMHunt/blob/master/tracer/instracelog.cpp
# - https://github.com/wuyongzheng/pin-instat
pin.sh -t obj-intel64/instat.so ./a.out
~/code/snippets/pin/instrace.cpp
# dynamorio
# - :( variable inscount
~/opt/dynamorio/build/bin64/drrun -c ~/opt/dynamorio/build/api/bin/libinstrace_x86_text.so -- ./a.out
# frida stalker
# - https://github.com/bmax121/sktrace
python3 sktrace/sktrace.py -m attach -l libnative-lib.so -i Java_com_kanxue_ollvm_1ndk_MainActivity_UUIDCheckSum com.kanxue.ollvm_ndk_9
# perf
# - https://man7.org/linux/man-pages/man1/perf-intel-pt.1.html
# - https://perf.wiki.kernel.org/index.php/Tutorial#Source_level_analysis_with_perf_annotate
# - https://lore.kernel.org/lkml/20180914031038.4160-4-andi@firstfloor.org/
perf trace record -- ./foo
perf script --call-trace
perf script --insn-trace --xed -F+srcline,+srccode
# debugger
# - ~/code/snippets/instrace.gdb
# - x64dbg - https://help.x64dbg.com/en/latest/gui/views/Trace.html#start-run-trace
#     - Trace view > Start Run Trace
# - IDA Pro - https://reverseengineering.stackexchange.com/questions/2486/is-there-an-equivalent-of-run-trace-as-in-ollydbg-for-ida-pro
#     - Debugger > Tracing > Function Tracing
#     - Debugger > Tracing > Instruction Tracing
#     - Debugger > Switch Debugger... > Trace replayer
# - https://github.com/teemu-l/execution-trace-viewer
```

# recompilation

- [Hunting for the Right Compiler, Part 1 \| neuviemeporte’s journal](https://neuviemeporte.github.io/f15-se2/2023/05/17/compiler.html)
- [Education/2021/CicoParser at master · gabonator/Education · GitHub](https://github.com/gabonator/Education/tree/master/2021/CicoParser)
- [GitHub \- notaz/ia32rtools](https://github.com/notaz/ia32rtools)
    - [Starcraft on Open Pandora: How the Port Came to Be &\#8211; Giant Pockets](https://www.giantpockets.com/starcraft-pandora-port-came/)
- [GitHub \- simonlindholm/decomp\-permuter: Randomly permute C files to better match a target binary](https://github.com/simonlindholm/decomp-permuter)

# binary rewriting

- [GitHub \- GJDuck/e9patch: A powerful static binary rewriting tool](https://github.com/GJDuck/e9patch)
    - [Binary Rewriting without Control Flow Recovery](https://www.comp.nus.edu.sg/~gregory/papers/e9patch.pdf)
- [GitHub \- HexHive/retrowrite: RetroWrite \-\-  Retrofitting compiler passes though binary rewriting](https://github.com/HexHive/retrowrite)
- [GitHub \- utds3lab/multiverse: A static binary rewriter that does not use heuristics](https://github.com/utds3lab/multiverse)
- [GitHub \- dyninst/dyninst: DyninstAPI: Tools for binary instrumentation, analysis, and modification\.](https://github.com/dyninst/dyninst)
- [GitHub \- iu\-parfunc/liteinst: Runtime application probing with lightweight binary instrumentation\.  Related to PLDI17\.](https://github.com/iu-parfunc/liteinst)
    - [Instruction Punning: Lightweight Instrumentation for x86-64](https://doi.org/10.1145/3062341.3062344)
- [GitHub \- boricj/ghidra\-delinker\-extension: Ghidra extension for exporting relocatable object files](https://github.com/boricj/ghidra-delinker-extension)
- [GitHub \- jnider/delinker: Unlinks a binary executable to get back a set of \.o object files for further transformation and re\-linking\.](https://github.com/jnider/delinker)
- [GitHub \- advanced\-microcode\-patching/shiva: A custom ELF linker/loader for installing ET\_REL binary patches at runtime](https://github.com/advanced-microcode-patching/shiva)

Alternative: 

# clean room design

- [Myths About Samba](https://www.samba.org/samba/docs/myths_about_samba.html)
    - [French Cafe technique - How Samba was written](https://www.samba.org/ftp/tridge/misc/french_cafe.txt)

# case studies

- transformation
    - [Changing EXE file into DLL library](https://lubiki.keeperklan.com/other_docs/change_exe_to_dll.htm)
    - [How to turn a DLL into a standalone EXE](https://hshrzd.wordpress.com/2016/07/21/how-to-turn-a-dll-into-a-standalone-exe/)
    - [Calling Arbitrary Functions In EXEs: Performing Calls to EXE Functions Like DLL Exports](https://blog.whtaguy.com/2020/04/calling-arbitrary-functions-in-exes.html)
    - [windows \- how to use class member function defined in a exe within a dll \- Reverse Engineering Stack Exchange](https://reverseengineering.stackexchange.com/questions/26006/how-to-use-class-member-function-defined-in-a-exe-within-a-dll)
    - [Transforming an ELF executable into a library — LIEF Documentation](https://lief-project.github.io/doc/latest/tutorials/08_elf_bin2lib.html)
    - [Modifying and running a binary by recompiling a reverse engineered disassembly](https://www.devever.net/~hl/recompile)
- easter egg in wrong password handler
    - https://twitter.com/suddendesu/status/1386994549302562818
        > [...] these all lead to gameplay stages by looking at the code. If it finds a match in the password table, it stores that offset in one of the "current stage" variables. directly.
        > The code then jumps to the init gameplay after a match. This means that each entry in the list above corresponds to a gameplay stage. First one (1111) is map 1, the next (0142) is map 2, and so on. There are no special cases that lead to anything besides a game map.
    - https://twitter.com/new_cheats_news/status/1387832686484525057
        > You looked in the different place ;) special password is checked in a special place when wrong passwords goes to, then you need a button code to be held additionally, and voila. ;)
- finding correlations/patterns
    - [\(DSCTF 2019\) CPU Adventure &\#8211; Unknown CPU Reversing &\#8211; Robert Xiao](https://www.robertxiao.ca/hacking/dsctf-2019-cpu-adventure-unknown-cpu-reversing/)
    - https://docs.mongodb.com/v3.2/reference/method/ObjectId/
        ```
        4-byte value representing the seconds since the Unix epoch,
            incrementing, mod base 16 => 2. linear search, inc length of substring when all lines passed
        3-byte machine identifier
            fixed => 1. lcs
        2-byte process id, and
            fixed...
        3-byte counter, starting with a random value.
            incrementing...
        ```
    - https://www.timdbg.com/posts/recognizing-patterns/
- [FwordCTF 2020 - XO](https://github.com/quintuplecs/writeups/blob/master/FwordCTF/xo.md)
    - strlen side-channel on flag xor - use dummy values as previous chars while guessing next char, since a right char generates a null byte, making strlen ignore next chars after the right char
- [America Online Exploits Bug In Own Software](https://www.geoffchappell.com/notes/security/aim/index.htm)
    > - The reason is that the packet data, as received from the AIM server, is contrived so that the corruption of memory by the AIM client is carefully controlled. The buggy routine in the AIM client is made to “return” to an address at which it is known there will be the bytes for a call esp instruction (actually provided in the bitmap for an icon in the AIM.EXE resources). The effect of this instruction is to start executing some of the packet data.
    > - The next part of the contrivance is that this part of the packet data actually has been prepared as executable code. It does two things. One is to recover from the bug, so that the AIM client resumes apparently normal execution. The other, done as a little side-trip before recovery, is to form some of the downloaded packet data into a new packet that the AIM client is induced to send to the AIM server.

### binary patching

- [GitHub \- ret2jazzy/ELFPatch: A library for patching ELFs](https://github.com/ret2jazzy/ELFpatch)
    > Instead of inline patching, it adds new segments, jmps there and jmp back. And since you're not adding new instructions inline, you can skip all the complicated re-assembly
    > lol I had to single step kernel ELF loader inside qemu for days before I got it working properly
- [GitHub \- liyansong2018/elfspirit: ELF static analysis and injection framework that parse, manipulate, patch and camouflage ELF files\.](https://github.com/liyansong2018/elfspirit)
- coreutils
    ```bash
    # Generate
    diff -u0 <(xxd -c1 -p 1) <(xxd -c1 -p 2) > 1_2.diff

    # Apply (`patch` requires regular file)
    xxd -c1 -p 1 > x1
    patch -u x1 1_2.diff
    paste -sd '' < x1 | xxd -r -p > 2
    ```
- Multi-threading safe call patching
    - [NativeCall::set_destination_mt_safe()](https://github.com/AdoptOpenJDK/openjdk-jdk11u/blob/fa3ecefdd6eb14a910ae75b7c0aefb1cf8eedcce/src/hotspot/cpu/x86/nativeInst_x86.cpp#L258): patch a single jump at the beginning, then the last 3 bytes, then the first 2 bytes
        - ensure cache invalidation with memory barrier calls
        - ensure cache line alignment with at least 2 byte boundary
            ```c
            ((uintptr_t)instruction_address() / cache_line_size == ((uintptr_t)instruction_address()+1) / cache_line_size)
            ```
        - ./reports/replace-mt-safe.md
- Skype version check
    > The issue is that skype stopped supporting old version, and I am forced to use web skype, or new skype for linux which doesn't meet my expectations.
    > When I launch old skype login screen pops, I enter my credentials and after clicking 'login' skype just exits.
    > Fortunately, Microsoft has implemented the program version verification in a particularly simple way.
    - https://stackoverflow.com/questions/47261038/old-skype-issues
    ```bash
    sed -i 's/4\.3\.0\.37/8.3.0.37/g' skype
    ```
- Mattermost phone-home
    > [...] versions of Mattermost have phone-home to segment.io embedded in the server, which can be disabled with the undocumented and exceedingly misleadingly-named 'MM_LOGSETTINGS_ENABLEDIAGNOSTICS=false' var in the env.
    > I made a Dockerfile that actually patches out the spying in the binary using sed, rather than figure out how to rebuild it without it or trust that the env vars work.
    - https://news.ycombinator.com/item?id=25147844
    - https://github.com/caprover/one-click-apps/blob/master/public/v4/apps/mattermost.yml#L34
    ```yaml
    dockerfileLines:
        - FROM mattermost/mattermost-team-edition@$$cap_mattermost_version
        - RUN sed -i 's#api.segment.io#xx.example.com#gI' /mattermost/bin/mattermost
        - RUN sed -i 's#securityupdatecheck.mattermost.com#xxxxxxxxxxxxxxxxxxxxxx.example.com#gI' /mattermost/bin/mattermost
    ```
- Singleton initialization causes infinite loop
    - [Win32 Disk Imager / Bugs / \#85 If Google File Stream is loaded,  win32DiskImager Crashes on Startup](https://sourceforge.net/p/win32diskimager/tickets/85/)
    - dissassembly
        - offset 0x3bfd = virtual 0x47fd
        - byte 0x74 to 0xeb = je to jmp
    - decompilation
        ```cpp
        BVar3 = DeviceIoControl(param_1,0x2d0800,(LPVOID)0x0,0,(LPVOID)0x0,0,&local_44,(LPOVERLAPPED)0x0);
        // Before patching
        if (BVar3 == 0) {
          return 0;
        }
        // After patching
        return 0;
        ```
    - DeviceIoControl
        - https://docs.microsoft.com/en-us/windows/win32/api/ioapiset/nf-ioapiset-deviceiocontrol
        > If the operation completes successfully, the return value is nonzero.
        > If the operation fails or is pending, the return value is zero. To get extended error information, call GetLastError.
        https://docs.microsoft.com/en-us/windows/win32/devio/calling-deviceiocontrol
    - translating control code `0x2d0800`
        - https://github.com/tpn/winsdk-7/blob/master/v7.1A/Include/WinIoCtl.h#L252
            ```c
            #define CTL_CODE( DeviceType, Function, Method, Access ) (                 \
                ((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method) \
            )
            #define IOCTL_STORAGE_CHECK_VERIFY2 CTL_CODE(IOCTL_STORAGE_BASE, 0x0200, METHOD_BUFFERED, FILE_ANY_ACCESS)
            // hex(0x200 << 2) = 0x800
            ```
        - https://docs.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-ioctl_storage_check_verify
            > Determines whether media are accessible for a device.
    - actual issue: `DeviceIoControl()` error handling logic gets a singleton via `MainWindow::getInstance()` while it's constructor is still executing, causing another constructor call, and another `DeviceIoControl()` call, which will enter the same conditional branch again in a loop, until a stack overflow occurs.
        - stack trace (read from bottom to top)
            ```
            ntdll!NtDeviceIoControlFile+c
            KERNELBASE!DeviceIoControl+40
            kernel32!DeviceIoControlImplementation+4b
            Win32DiskImager+4f38
            Win32DiskImager+672a
            Win32DiskImager+cd65
            --- [Loop end]
            Win32DiskImager+4d2d
            Win32DiskImager+5083
            Win32DiskImager+672a
            Win32DiskImager+cd65
            [...]
            Win32DiskImager+4d2d = GetDisksProperty() -> QMessageBox::critical(
                    MainWindow::getInstance(),
                    QObject::tr("File Error"),
                    QObject::tr("An error occurred while getting the device number.\n"
                            "This usually means something is currently accessing the device;"
                            "please close all applications and try again.\n\nError %1: %2").arg(GetLastError()).arg(errText));
            Win32DiskImager+5083 = checkDriveType() -> GetDisksProperty(hDevice, pDevDesc, &deviceInfo)
            Win32DiskImager+672a = MainWindow::getLogicalDrives() -> checkDriveType(drivename, &pID)
            Win32DiskImager+cd65 = MainWindow::MainWindow() -> getLogicalDrives();
            --- [Loop begin]
            Win32DiskImager+58dc = main() -> MainWindow* mainwindow = MainWindow::getInstance();
            Win32DiskImager+10212
            Win32DiskImager+1825d
            Win32DiskImager+13e2
            kernel32!BaseThreadInitThunk+19
            ntdll!__RtlUserThreadStart+2f
            ntdll!_RtlUserThreadStart+1b
            ```
        - tools used: `procexp` to take a memory dump, `Debug Diagnostic Tool` to inspect stack trace and memory allocations, `x32dbg` to break on previously identified loop addresses
