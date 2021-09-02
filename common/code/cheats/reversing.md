# +

- [asm](./asm.md)
- [wasm](./wasm.md)
- [evasion](./evasion.md)

- [ghidra](ghidra.md)
- [ida](ida.md)
- [r2](r2.md)
- [strace](./strace.md)

- [angr](./angr.md)
- [frida](./frida.md)
- [z3](./z3.md)

- text
    - any format: `strings` (`-el` for 16-bit le)
    - ELF format: [match x86 that appears to be stack string creation · GitHub](https://gist.github.com/williballenthin/ed7b3de224d5b986bc04dc882c5ee7c5)
    - PE format: `floss`
        - :) extracts stack strings
- libraries
    - any format: [GitHub \- maroueneboubakri/lscan: lscan is a library identification tool on statically linked/stripped binaries](https://github.com/maroueneboubakri/lscan)
        - [GitHub \- push0ebp/ALLirt: Tool that converts  All of libc to signatures for IDA Pro FLIRT Plugin\. and utility make sig with FLAIR easily](https://github.com/push0ebp/ALLirt)
    - ELF format: `ldd -iv` (validates shared libraries initialization)
        - [GitHub \- marin\-m/vmlinux\-to\-elf: A tool to recover a fully analyzable \.ELF from a raw kernel, through extracting the kernel symbol table \(kallsyms\)](https://github.com/marin-m/vmlinux-to-elf)
    - PE format: [GitHub \- fireeye/capa: The FLARE team&\#39;s open\-source tool to identify capabilities in executable files\.](https://github.com/fireeye/capa)
- resources
    - NE format: [GitHub \- david47k/neresex: Resource extractor for Windows 3\.xx 16\-bit New Executable \(NE\) files](https://github.com/david47k/neresex)
- packers
    - [GitHub \- horsicq/Detect\-It\-Easy: Program for determining types of files for Windows, Linux and MacOS\.](https://github.com/horsicq/Detect-It-Easy)
    - [GitHub \- ExeinfoASL/ASL: ExeinfoPE](https://github.com/ExeinfoASL/ASL)
- roms
    - [uCON64 \- ReadMe](https://ucon64.sourceforge.io/ucon64/readme.html)
    - [GitHub \- al3xtjames/ghidra\-firmware\-utils: Ghidra utilities for analyzing PC firmware](https://github.com/al3xtjames/ghidra-firmware-utils)
- syscalls, dynamic library calls
    - ELF format: `strace -X verbose -if -s 9999`, `ltrace -if`
    - PE format: `procmon`
- constants
    - [The Magic Number Database \| MagnumDB](https://www.magnumdb.com/)
    - https://hiddencodes.wordpress.com/2011/12/23/string-manipulation-functions-in-glibc-ms-visual-studio-and-0x7efefeff-0x81010100-0x81010101/
- visual structure
    - https://binvis.io/
        - https://github.com/binvis/binvis.io
        - https://github.com/cortesi/scurve
    - https://justine.storage.googleapis.com/memzoom/index.html
    - [GitHub \- katjahahn/PortEx: Java library to analyse Portable Executable files with a special focus on malware analysis and PE malformation robustness](https://github.com/katjahahn/PortEx)
    - [Hex viewers and editors](https://twitter.com/i/events/841916822014332930)
- entropy
    - binwalk
        ```bash
        # Given $PYTHONPATH with matplotlib:
        env PYTHONPATH="$HOME/.local/lib/python3.8/site-packages" binwalk --entropy
        ```
    - audacity
- diff
    - [GitHub \- joxeankoret/pigaios: A tool for matching and diffing source codes directly against binaries\.](https://github.com/joxeankoret/pigaios)
    - [GitHub \- joxeankoret/diaphora: Diaphora, the most advanced Free and Open Source program diffing tool\.](https://github.com/joxeankoret/diaphora)
    - [GitHub \- ubfx/BinDiffHelper: Ghidra Extension to integrate BinDiff for function matching](https://github.com/ubfx/BinDiffHelper)

# methodologies

- taxonomies
    - str array: strs are accessed w/ an offset from the 1st str (array base), which _will_ have an xref
    - algorithm: google constants
    - hashing: branchless xors/rols
    - debug symbols: from old versions
- enumerate exports, imports, function use, syscalls, winapi, mutex, dll dependencies, strings
    - lifecycle
        - before OEP
            - pe format: TLS
            - elf format: init_array
        - debugger: break on thread exit, dll unload, process exit, then check stack
    - finding `main()` function
        - on libc `entry`, take 1st argument to `__libc_start_main()`
        - || find which function's return value (saved in eax) is passed to exit(), then follow xrefs in reverse
    - calling functions
        - debugger
        - https://blog.whtaguy.com/2020/04/calling-arbitrary-functions-in-exes.html?m=1
    - filesystem
        - FileRead/FileWrite calls
        - [GitHub \- poona/APIMiner: API Logger for Windows Executables](https://github.com/poona/APIMiner/)
    - networking
        - hw read break on packet buffer, frida hook on winsock calls
        - [ws2_32 recv/send](https://docs.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-recv)
        - [WSARecvFrom/WSASendTo](https://docs.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsasendto)
    - finding specific functions
        - take old version introducing specific logic in changelog, then bindiff with current version
- diff/search for data changes before and after blocks: loops, func calls...
- binary patching, code injection, fault inducing
- monitor memory maps - snapshot at `entry()`, then check if executable section became writable and modified at later snapshot
- alternative to reverse debugging: vm snapshots
- images
    - produce a blank image, add one pixel (say purple - that is 50% Red, 50% Blue, 0% Green), change the color of the pixel, then change the location of the pixel, to see how the BMP binary code changes.

- [Tampering and Reverse Engineering - Mobile Security Testing Guide](https://mobile-security.gitbook.io/mobile-security-testing-guide/general-mobile-app-testing-guide/0x04c-tampering-and-reverse-engineering)
- https://breaking-bits.gitbook.io/breaking-bits/vulnerability-discovery/reverse-engineering/modern-approaches-toward-embedded-research
- https://blog.whtaguy.com/2020/04/guys-30-reverse-engineering-tips-tricks.html

# lifting

- [GitHub \- lifting\-bits/mcsema: Framework for lifting x86, amd64, aarch64, sparc32, and sparc64 program binaries to LLVM bitcode](https://github.com/lifting-bits/mcsema)
    - [GitHub \- lifting\-bits/remill: Library for lifting of x86, amd64, and aarch64 machine code to LLVM bitcode](https://github.com/lifting-bits/remill)

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

# vm

- https://www.microsoft.com/security/blog/2018/03/01/finfisher-exposed-a-researchers-tale-of-defeating-traps-tricks-and-complex-virtual-machines/

# functional programming

- [GitHub \- sjsyrek/malc: Make a lambda calculus\.](https://github.com/sjsyrek/malc)
- [Beta reduction \- HaskellWiki](https://wiki.haskell.org/Beta_reduction)
- [David Beazley \- Lambda Calculus from the Ground Up \- PyCon 2019 \- YouTube](https://www.youtube.com/watch?v=pkCLMl0e_0k)

# scripting dissassembly

- [Programming with Python language – Capstone – The Ultimate Disassembler](https://www.capstone-engine.org/lang_python.html)
- [find\_ioctls\.py · GitHub](https://gist.github.com/uf0o/011cedcae3f52102c69c7d8c28ae678c)

# side channels

- timing attacks - On password validation routine, when a char is correct, more instructions are executed
    - ~/code/snippets/pin/count_me_if_you_can.py
    - [write\-up for dont\_panic \- Eternal Stories](http://eternal.red/2017/dont_panic-writeup/)
- syscall counting - `strace | sort | uniq -c`

```bash
# instruction counting
~/opt/dynamorio/build/bin64/drrun -c ~/opt/dynamorio/build/api/bin/libinscount.so -- ./a.out \
    | awk '/Instrumentation results:/{print $3}'
qemu-x86_64 -d in_asm ./a.out 2>&1 \
    | awk '/IN:/{i+=1} END{print i}'
gcc -O0 a.c && echo 'a' \
    | perf stat -e instructions:u ./a.out 2>&1 \
    | awk '/instructions.u/{print $1}'

# bruteforcing chars
for n in {32..127}; do
    c=$(awk '{ printf("%c", $0); }' <<< $n)
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
# - diff alternative: `lighthouse` plugin
# - https://stackoverflow.com/questions/53218160/how-can-i-do-code-path-analysis-in-a-debugger
# - https://stackoverflow.com/questions/22507169/how-to-run-record-instruction-history-and-function-call-history-in-gdb
# - https://dynamorio.org/dynamorio_docs/page_drcov.html

# ||
# 1. grep xrefs from asm dump, take addresses
# 2. make gdb script with temporary breakpoint (`tbreak`) foreach address
# - [On why my tbreak tracing trick did not work \- gynvael\.coldwind//vx\.log](https://gynvael.coldwind.pl/?id=638)

# execution trace
# :) stable inscount
qemu-x86_64 -d in_asm a.out
# ||
pin.sh -t obj-intel64/instat.so ./a.out
# || :( variable inscount
~/opt/dynamorio/build/bin64/drrun -c ~/opt/dynamorio/build/api/bin/libinstrace_x86_text.so -- ./a.out
# ||
# - https://man7.org/linux/man-pages/man1/perf-intel-pt.1.html
# - https://perf.wiki.kernel.org/index.php/Tutorial#Source_level_analysis_with_perf_annotate
perf script --call-trace
perf script --insn-trace --xed -F+srcline,+srccode
perf trace record
# ||
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

- [Education/2021/CicoParser at master · gabonator/Education · GitHub](https://github.com/gabonator/Education/tree/master/2021/CicoParser)
- [GitHub \- notaz/ia32rtools](https://github.com/notaz/ia32rtools)
    - [Starcraft on Open Pandora: How the Port Came to Be &\#8211; Giant Pockets](https://www.giantpockets.com/starcraft-pandora-port-came/)

# clean room design

- [Myths About Samba](https://www.samba.org/samba/docs/myths_about_samba.html)
    - [French Cafe technique - How Samba was written](https://www.samba.org/ftp/tridge/misc/french_cafe.txt)

# case studies

- [Changing EXE file into DLL library](https://lubiki.keeperklan.com/other_docs/change_exe_to_dll.htm)
- [Calling Arbitrary Functions In EXEs: Performing Calls to EXE Functions Like DLL Exports](https://blog.whtaguy.com/2020/04/calling-arbitrary-functions-in-exes.html)
- [Modifying and running a binary by recompiling a reverse engineered disassembly](https://www.devever.net/~hl/recompile)
- [America Online Exploits Bug In Own Software](https://www.geoffchappell.com/notes/security/aim/index.htm)
- [FwordCTF 2020 - XO](https://github.com/quintuplecs/writeups/blob/master/FwordCTF/xo.md)
    - strlen side-channel on flag xor - use dummy values as previous chars while guessing next char, since a right char generates a null byte, making strlen ignore next chars after the right char
- easter egg in wrong password handler
    - https://twitter.com/suddendesu/status/1386994549302562818
        > [...] these all lead to gameplay stages by looking at the code. If it finds a match in the password table, it stores that offset in one of the "current stage" variables. directly.
        > The code then jumps to the init gameplay after a match. This means that each entry in the list above corresponds to a gameplay stage. First one (1111) is map 1, the next (0142) is map 2, and so on. There are no special cases that lead to anything besides a game map.
    - https://twitter.com/new_cheats_news/status/1387832686484525057
        > You looked in the different place ;) special password is checked in a special place when wrong passwords goes to, then you need a button code to be held additionally, and voila. ;)

### binary patching

- coreutils
    ```bash
    # Generate
    diff -Nauw \
        <(xxd -p 1 | sed 's/\(..\)/\1\n/g') \
        <(xxd -p 2 | sed 's/\(..\)/\1\n/g') \
        > 1_2.diff

    # Apply (`patch` requires regular file)
    xxd -p 1 | sed 's/\(..\)/\1\n/g' > x1
    patch -u x1 1_2.diff
    paste -sd '' < x1 | xxd -r -p > 2
    ```
- x64dbg
- [GitHub \- GJDuck/e9patch: A powerful static binary rewriting tool](https://github.com/GJDuck/e9patch)
    - [Binary Rewriting without Control Flow Recovery](https://www.comp.nus.edu.sg/~gregory/papers/e9patch.pdf)
- [GitHub \- iu\-parfunc/liteinst: Runtime application probing with lightweight binary instrumentation\.  Related to PLDI17\.](https://github.com/iu-parfunc/liteinst)
    - [Instruction Punning: Lightweight Instrumentation for x86-64](https://doi.org/10.1145/3062341.3062344)

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
