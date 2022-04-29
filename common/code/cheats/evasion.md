# +

- [GitHub \- zardus/preeny: Some helpful preload libraries for pwning stuff\.](https://github.com/zardus/preeny)
- [GitHub \- jonatan1024/CpuidSpoofer: x64dbg plugin for simple spoofing of CPUID instruction behavior](https://github.com/jonatan1024/CpuidSpoofer)
- [GitHub \- mgeeky/ShellcodeFluctuation: An advanced in\-memory evasion technique fluctuating shellcode&\#39;s memory protection between RW/NoAccess &amp; RX and then encrypting/decrypting its contents](https://github.com/mgeeky/ShellcodeFluctuation)

- [Map \- Unprotect Project](https://search.unprotect.it/map)
- [Anti\-Debug Tricks](https://anti-debug.checkpoint.com/)
- https://github.com/CheckPointSW/Evasions
    - https://evasions.checkpoint.com/
- https://github.com/seifreed/awesome-sandbox-evasion

# detection

- dynamic analysis
    - [Cuckoo Sandbox \- Automated Malware Analysis \- Installation](https://cuckoo.readthedocs.io/en/latest/installation/)
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

# anti-vm

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
    2. Dump using Scylla
- emulation
    > rip the depacker code in the emulator debugger, note what it requires (which registers must be set to point to src/dest, etc.) and 'borrow' an R5900-cpu core from some emulator github :)
    > Packers tend not to touch any custom chips or be affected by any kind of timing/irqs, so just functional CPU emulation will do the job to make a depacking tool.

# anti-debugging

### Windows

- user mode (ring 3)
    - [GitHub \- x64dbg/ScyllaHide: Advanced usermode anti\-anti\-debugger\. Forked from https://bitbucket\.org/NtQuery/scyllahide](https://github.com/x64dbg/ScyllaHide)
- kernel mode (ring 0)
    - [GitHub \- mrexodia/TitanHide: Hiding kernel\-driver for x86/x64\.](https://github.com/mrexodia/TitanHide)
- use kernel debugger to bypass user mode evasion

- [NtQueryInformationProcess function \(winternl\.h\) \- Win32 apps \| Microsoft Docs](https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess?redirectedfrom=MSDN)
    - ProcessDebugPort != 0
- heap tail checking enabled => 0xABABABAB signature appended at end of allocated blocks
    ```fasm
    call [ebp+RtlAllocateHeap]
    cmp [eax+10h], ecx  ; 0xABABABAB
    jz short debugger_detected
    ```
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
- https://www.cdmediaworld.com/hardware/cdrom/cd_protections.shtml

# case studies

- https://tccontre.blogspot.com/2020/11/interesting-formbook-crypter.html
- https://www.rezilion.com/blog/the-race-to-limit-ptrace/
- https://katyscode.wordpress.com/2021/01/24/reverse-engineering-adventures-brute-force-function-search-or-how-to-crack-genshin-impact-with-powershell/
