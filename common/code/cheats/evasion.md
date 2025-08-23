# +

- [GitHub \- zardus/preeny: Some helpful preload libraries for pwning stuff\.](https://github.com/zardus/preeny)
- [GitHub \- jonatan1024/CpuidSpoofer: x64dbg plugin for simple spoofing of CPUID instruction behavior](https://github.com/jonatan1024/CpuidSpoofer)
- [GitHub \- mgeeky/ShellcodeFluctuation: An advanced in\-memory evasion technique fluctuating shellcode&\#39;s memory protection between RW/NoAccess &amp; RX and then encrypting/decrypting its contents](https://github.com/mgeeky/ShellcodeFluctuation)
- [GitHub \- myzxcg/RealBlindingEDR: Remove AV/EDR Kernel ObRegisterCallbacks、CmRegisterCallback、MiniFilter Callback、PsSetCreateProcessNotifyRoutine Callback、PsSetCreateThreadNotifyRoutine Callback、PsSetLoadImageNotifyRoutine Callback\.\.\.](https://github.com/myzxcg/RealBlindingEDR)
- [GitHub \- wavestone\-cdt/EDRSandblast](https://github.com/wavestone-cdt/EDRSandblast)
- [GitHub \- JustasMasiulis/lazy\_importer: library for importing functions from dlls in a hidden, reverse engineer unfriendly way](https://github.com/JustasMasiulis/lazy_importer)
- [GitHub \- NtDallas/MemLoader: Run native PE or \.NET executables entirely in\-memory\. Build the loader as an \.exe or \.dll—DllMain is Cobalt Strike UDRL\-compatible](https://github.com/NtDallas/MemLoader)

- [Map \- Unprotect Project](https://search.unprotect.it/map)
- [Anti\-Debug Tricks](https://anti-debug.checkpoint.com/)
- [GitHub \- CheckPointSW/Evasions: Evasions encyclopedia gathers methods used by malware to evade detection when run in virtualized environment\. Methods are grouped into categories for ease of searching and understanding\. Also provided are code samples, signature recommendations and countermeasures within each category for the described techniques\.](https://github.com/CheckPointSW/Evasions)
    - [Evasion techniques](https://evasions.checkpoint.com/)
- [GitHub \- seifreed/awesome\-sandbox\-evasion: A summary about different projects/presentations/tools to test how to evade malware sandbox systems](https://github.com/seifreed/awesome-sandbox-evasion)
- [GitHub \- persistence\-info/persistence\-info\.github\.io](https://github.com/persistence-info/persistence-info.github.io)
    - [persistence\-info\.github\.io](https://persistence-info.github.io/)
- [Defense Evasion, Tactic TA0005 \- Enterprise \| MITRE ATT&CK&reg;](https://attack.mitre.org/tactics/TA0005/)
- [MalSearch](https://malsearch.com/)

# methodology

1. Start Process Monitor / Process Explorer / Wireshark / Inetsim
2. Take 1st Regshot
3. Take VM snapshot
4. Run malware
5. Take 2nd Regshot
6. End Process Monitor / Process Explorer / Wireshark / Inetsim
7. Revert VM snapshot

- [Set up your own malware analysis lab with VirtualBox, INetSim and Burp \- Christophe Tafani\-Dereeper](https://blog.christophetd.fr/malware-analysis-lab-with-virtualbox-inetsim-and-burp/)

### detection

- dynamic analysis
    - [Cuckoo Sandbox \- Automated Malware Analysis \- Installation](https://cuckoo.readthedocs.io/en/latest/installation/)
        - [Hardening Cuckoo Sandbox against VM aware malware \| AT&T Alien Labs](https://cybersecurity.att.com/blogs/labs-research/hardening-cuckoo-sandbox-against-vm-aware-malware)
        - [Creating Hooks \- Cuckoo Monitor 1\.3 documentation](https://cuckoo-monitor.readthedocs.io/en/latest/hooks.html)
    - [INetSim: Internet Services Simulation Suite \- Features](https://www.inetsim.org/features.html)
    - APIs
        - Memory allocation/map: VirtualAllocEx, NtCreateSection
        - Write code/data: WriteProcessMemory, NtMapViewOfSection
        - Execution: CreateRemoteThread, SetThreadContext, QueueUserAPC
    - stack alignment
- static analysis
    - high-entropy data
- process injection
    - [Implement Image Coherency by jxy\-s · Pull Request \#751 · processhacker/processhacker · GitHub](https://github.com/processhacker/processhacker/pull/751)
    - [AddressOfEntryPoint Code Injection without VirtualAllocEx RWX \- Red Teaming Techniques & Experiments](https://www.ired.team/offensive-security/code-injection-process-injection/addressofentrypoint-code-injection-without-virtualallocex-rwx)
    - [GitHub \- wbenny/injdrv: proof\-of\-concept Windows Driver for injecting DLL into user\-mode processes using APC](https://github.com/wbenny/injdrv)
    - ELF format: `ptrace()` + `_dl_open()` || `pthread_create()`
        - [Ars\-Informatica &middot; by Daniele Gasperini\.](https://web.archive.org/web/20150717110958/http://www.ars-informatica.com/Root/Code/2010_04_18/LinuxPTrace.aspx)
        - [System Programming: Linux Threads Through a Magnifier: Remote Threads](http://syprog.blogspot.com/2012/03/linux-threads-through-magnifier-remote.html)
        - [shared libraries \- \.so injection under linux: how to locate address of dlopen\(\)? \- Stack Overflow](https://stackoverflow.com/questions/21651761/so-injection-under-linux-how-to-locate-address-of-dlopen)
        - [GitHub \- kubo/injector: Library for injecting a shared library into a Linux or Windows process](https://github.com/kubo/injector)
        - [GitHub \- namazso/linux\_injector: A simple ptrace\-less shared library injector for x64 Linux](https://github.com/namazso/linux_injector)
        - [GitHub \- gaffe23/linux\-inject: Tool for injecting a shared object into a Linux process](https://github.com/gaffe23/linux-inject)
        - [GitHub \- ilammy/linux\-crt: CreateRemoteThread for Linux](https://github.com/ilammy/linux-crt)
        - [GitHub \- DavidBuchanan314/dlinject: Inject a shared library \(i\.e\. arbitrary code\) into a live linux process, without ptrace](https://github.com/DavidBuchanan314/dlinject)
        - [GitHub \- vfsfitvnm/intruducer: A Rust crate to load a shared library into a Linux process without using ptrace\.](https://github.com/vfsfitvnm/intruducer)
        - [GitHub \- zznop/drow: Injects code into ELF executables post\-build](https://github.com/zznop/drow)
- registry keys
    ```
    {HKCU,HKLM}\Software\Microsoft\Windows\CurrentVersion\{Run,RunOnce,RunOnceEx,RunServices,RunServicesOnce}
    {HKCU,HKLM}\Software\Microsoft\Windows\CurrentVersion\Explorer\{User Shell Folders,Shell Folders}
    {HKCU,HKLM}\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
    {HKCU,HKLM}\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\{Userinit,Shell}
    {HKCU,HKLM}\Software\Microsoft\Windows NT\CurrentVersion\Windows /v load
    {HKCU,HKLM}\System\CurrentControlSet\Control\Session Manager /v BootExecute
    ```
    - [registry-keys-startup-folder](https://dmcxblue.gitbook.io/red-team-notes/persistence/registry-keys-startup-folder)
    - [Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder, Sub\-technique T1547\.001 \- Enterprise \| MITRE ATT&CK&reg;](https://attack.mitre.org/techniques/T1547/001/)

- [GitHub \- last\-byte/PersistenceSniper: Powershell script that can be used by Blue Teams, Incident Responders and System Administrators to hunt persistences implanted in Windows machines\.](https://github.com/last-byte/PersistenceSniper)
- [GitHub \- LordNoteworthy/al\-khaser: Public malware techniques used in the wild: Virtual Machine, Emulation, Debuggers, Sandbox detection\.](https://github.com/LordNoteworthy/al-khaser)
    - https://www.hybrid-analysis.com/sample/4ca52a1ff170690804811145806c4b6ae6b2c81e129e3cc6b967fd88f47b067e/5bb544127ca3e129f82cc2b9
- [GitHub \- a0rtega/pafish: Pafish is a testing tool that uses different techniques to detect virtual machines and malware analysis environments in the same way that malware families do](https://github.com/a0rtega/pafish)
- [GitHub \- secrary/makin: makin \- reveal anti\-debugging and anti\-VM tricks \(This project is not maintained anymore\)](https://github.com/secrary/makin)

# anti-vm

- vbox
    - [GitHub \- d4rksystem/VBoxCloak: A PowerShell script that attempts to help malware analysts hide their Windows VirtualBox Windows VM&\#39;s from malware that may be trying to evade analysis\. Guaranteed to bring down your pafish ratings by at least a few points ;\)](https://github.com/d4rksystem/VBoxCloak)
    - [GitHub \- nsmfoo/antivmdetection: Script to create templates to use with VirtualBox to make vm detection harder](https://github.com/nsmfoo/antivmdetection)
    - [VirtualBox: How to Setup your Malware Analysis \- Embedded Lab Vienna for IoT &amp; Security](https://wiki.elvis.science/index.php?title=VirtualBox:_How_to_Setup_your_Malware_Analysis)
- vmware
    - [GitHub \- d4rksystem/VMwareCloak: A PowerShell script that attempts to help malware analysts hide their VMware Windows VM&\#39;s from malware that may be trying to evade analysis\.](https://github.com/d4rksystem/VMwareCloak)
- qemu
    - [GitHub \- hatching/vmcloak: Automated Virtual Machine Generation and Cloaking for Cuckoo Sandbox\.](https://github.com/hatching/vmcloak)
    - [GitHub \- zhaodice/qemu\-anti\-detection: A patch to hide qemu itself, bypass mhyprot,EAC,nProtect / VMProtect,VProtect, Themida, Enigma Protector,Safegine Shielden](https://github.com/zhaodice/qemu-anti-detection)

- ~/code/snippets/evasion/SMBiosData.ps1

# self-modifying code, packers

Detecting changes in process maps:

```gdb
# https://stackoverflow.com/questions/1780765/setting-a-gdb-exit-breakpoint-not-working
catch syscall exit exit_group
# || catch syscall 60 231
starti
vmmap
c
vmmap
dump memory foo.mem 0x401000 0x402000

# Take pid (e.g. 123)
info proc
```

```bash
sha1sum foo
# ||
sha1sum /proc/123/map_files/401000-402000

sha1sum foo.mem
# || https://unix.stackexchange.com/questions/6301/how-do-i-read-from-proc-pid-mem-under-linux
sha1sum <(python -c 'import sys;f=open(sys.argv[1],"rb");s=int(sys.argv[2]);e=int(sys.argv[3]);f.seek(s);sys.stdout.buffer.write(f.read(e-s))' /proc/123/mem $((0x401000)) $((0x402000)))
```

- https://shanetully.com/2013/12/writing-a-self-mutating-x86_64-c-program/
- http://web.archive.org/web/20170501105431im_/http://www.pinkstyle.org/elfcrypt.html
- https://redcanary.com/blog/process-memory-integrity-linux/

### .NET

- dynamically loaded assemblies: `Assembly.Load`
- dynamically call methods: reflection APIs, VB.NET `LateBinding.LateCall/LateGet`
- duplicated CLR stream names, unusal CLR tables like EncLog/EncMap, unicode .NET method names in MethodDef table
- encrypted data: resources, `FieldRva` table for static arrays pointers, `#US` for user strings

- https://malcat.fr/blog/statically-unpacking-a-simple-net-dropper/

### upx

- Identification: sequence of null bytes after jmp to oep
- Dumping executable from memory
    ```gdb
    # break after unpacking, but before executing unpacked code
    catch syscall munmap
    # ~/code/snippets/lief/dump_elf.py
    ```
    - Windows
        - http://secmem.blogspot.com/2013/07/dealing-with-upx-packed-executables.html
- Fixing upx tags
    - https://r3v3rs3r.wordpress.com/2015/09/18/solving-fusion-level-9/
- TODO: understand trailing instructions added to unpacked executable map
    - ~/code/wip/upx/
    ```
    0f 05           SYSCALL
    5a              POP        RDX
    c5              RET
    ```

### generic

- find uncompressed data in memory
- trace contains many loops (high jumps/all_instructions ratio)
- dumping
    1. At entrypoint, set hardware watch on `$rsp`
        - On break, take `jmp` address, subtract image base (`0x400000`) to get original entrypoint (oep)
    2. Dump
        - https://github.com/NtQuery/Scylla/
        - https://github.com/hasherezade/pe-sieve
            - `pe-sieve32.exe /imp 3 /shellc /pid 1234`
        - https://github.com/EquiFox/KsDumper
- emulation
    - [GitHub \- mandiant/speakeasy: Windows kernel and user mode emulation\.](https://github.com/mandiant/speakeasy)
    - [GitHub \- mrexodia/driver\_unpacking: Ghetto user mode emulation of Windows kernel drivers\.](https://github.com/mrexodia/driver_unpacking)
        - [kernel-driver-unpacking](https://x64dbg.com/blog/2017/06/08/kernel-driver-unpacking.html)
    - [GitHub \- OALabs/BlobRunner: Quickly debug shellcode extracted during malware analysis](https://github.com/OALabs/BlobRunner)
    - [GitHub \- mrexodia/dumpulator: An easy\-to\-use library for emulating code in minidump files\.](https://github.com/mrexodia/dumpulator)
    - [GitHub \- hzqst/unicorn\_pe: Unicorn PE is an unicorn based instrumentation project designed to emulate code execution for windows PE files\.](https://github.com/hzqst/unicorn_pe)
    - [GitHub \- Phat3/PINdemonium: A pintool in order to unpack malware](https://github.com/Phat3/PINdemonium)
    - [GitHub \- zcutlip/nvram\-faker: A simple library to intercept calls to libnvram when running embedded linux applications in emulated environments\.](https://github.com/zcutlip/nvram-faker)
    > rip the depacker code in the emulator debugger, note what it requires (which registers must be set to point to src/dest, etc.) and 'borrow' an R5900-cpu core from some emulator github :)
    > Packers tend not to touch any custom chips or be affected by any kind of timing/irqs, so just functional CPU emulation will do the job to make a depacking tool.
- https://twitter.com/re_and_more/status/1505091717971775491
    > memory or hardware breakpoints on write operation set on the allocated block may help intercept the moment when the unpacked code and data of interest will be written there

# anti-debugging

### Windows

- user mode (ring 3)
    - [GitHub \- x64dbg/ScyllaHide: Advanced usermode anti\-anti\-debugger\. Forked from https://bitbucket\.org/NtQuery/scyllahide](https://github.com/x64dbg/ScyllaHide)
- kernel mode (ring 0)
    - [GitHub \- mrexodia/TitanHide: Hiding kernel\-driver for x86/x64\.](https://github.com/mrexodia/TitanHide)
    - [GitHub \- Air14/HyperHide: Hypervisor based anti anti debug plugin for x64dbg](https://github.com/Air14/HyperHide)
- use kernel debugger to bypass user mode evasion

- readonly pages
    - `NtProtectVirtualMemory` with `Protect = PAGE_READONLY`
    - `NtMapViewOfSection` with `AllocationType = SEC_NO_CHANGE`
        - bypass: Direct Kernel Object Manipulation (DKOM): https://www.unknowncheats.me/forum/anti-cheat-bypass/354089-unprotect-sec_no_change.html
            ```
            # Validating on windbg: dt _MMVAD_FLAGS
            # https://doxygen.reactos.org/d7/d14/struct__MMVAD__FLAGS.html
            vadshort->u.VadFlags.NoChange = 0;
            vadshort->u.VadFlags.Protection = 7;
            ```
        - bypass: kernel driver that tampers `AllocationType`
        - bypass: remap (alloc new memory, copy, suspend, resume exec)
    - `NtQueryVirtualMemory` tarpit with `MEM_RESERVE`: [Preventing memory inspection on Windows \| secret club](https://secret.club/2021/05/23/big-memory.html)

- [NtQueryInformationProcess function \(winternl\.h\) \- Win32 apps \| Microsoft Docs](https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess?redirectedfrom=MSDN)
    - ProcessDebugPort != 0
- heap tail checking enabled => 0xABABABAB signature appended at end of allocated blocks
    ```fasm
    call [ebp+RtlAllocateHeap]
    cmp [eax+10h], ecx  ; 0xABABABAB
    jz short debugger_detected
    ```
- detecting hardware breakpoints
    - GetThreadContext() can be hooked: https://momo5502.com/posts/2022-11-17-reverse-engineering-integrity-checks-in-black-ops-3/
    - raise exception => hardware breakpoint addresses present in ContextRecord structure passed to exception handler
        ```fasm
        mov eax, [esp+0xc]  ; ContextRecord
        mov ecx, [eax+0x4]  ; DR0
        or ecx, [eax+0x8]  ; DR1
        or ecx, [eax+0xc]  ; DR2
        or ecx, [eax+0x10]  ; DR3
        jne debugger_detected
        ```

### LD_PRELOAD

- /etc/ld.so.preload => applied to setuid binaries loaded by glibc /lib/ld-linux.so
- https://haxelion.eu/article/LD_NOT_PRELOADED_FOR_REAL/

### ptrace(PTRACE_TRACEME, 0, 0)

debugger bypass:

```gdb
catch syscall ptrace
commands 1
set $rax = 0
continue
end
```

library hook:

```c
long ptrace(int request, int pid, void *addr, void *data) {
    return 0;
}
```

```bash
env LD_PRELOAD=ptrace.so ./foo
```

# anti-dbi, anti-frida

- [r2\-pay: anti\-debug, anti\-root & anti\-frida \(part 1\) \| Romain Thomas](https://www.romainthomas.fr/post/20-09-r2con-obfuscated-whitebox-part1/)

# syscalls

- [Hiding Your Syscalls \| PassTheHashBrowns](https://passthehashbrowns.github.io/hiding-your-syscalls)

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
- decrypting instruction opcodes with exception handler
    - https://en.wikipedia.org/wiki/Trace_vector_decoder
- [CD Media World \- CD/DVD Protections \- CD/DVD/Game Copy Protections & Tools](https://www.cdmediaworld.com/hardware/cdrom/cd_protections.shtml)
- [Pinball Construction Set \- A 4am and san inc crack](https://ia804700.us.archive.org/13/items/PinballConstructionSet4amCrack/Pinball%20Construction%20Set%20%284am%20and%20san%20inc%20crack%29.txt)
- [GitHub \- RibShark/SafeDiscShim: SafeDiscShim is a compatibility tool that allows for SafeDisc protected games which utilize the insecure Macrovision Security Driver \(&quot;secdrv\.sys&quot;\) to run on modern versions of Windows \.](https://github.com/RibShark/SafeDiscShim)

# case studies

- https://www.fortinet.com/blog/threat-research/deep-analysis-of-driver-based-mitm-malware-itranslator
- https://tccontre.blogspot.com/2020/11/interesting-formbook-crypter.html
- https://www.rezilion.com/blog/the-race-to-limit-ptrace/
- https://katyscode.wordpress.com/2021/01/24/reverse-engineering-adventures-brute-force-function-search-or-how-to-crack-genshin-impact-with-powershell/
