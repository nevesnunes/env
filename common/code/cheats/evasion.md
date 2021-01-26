# +

- [Map \- Unprotect Project](https://search.unprotect.it/map)
- [Anti\-Debug Tricks](https://anti-debug.checkpoint.com/)
- https://github.com/CheckPointSW/Evasions
- https://github.com/seifreed/awesome-sandbox-evasion

# detection

- dynamic analysis
    - [Cuckoo Sandbox \- Automated Malware Analysis \- Installation](https://cuckoo.readthedocs.io/en/latest/installation/)
- process injection
    - [Implement Image Coherency by jxy\-s · Pull Request \#751 · processhacker/processhacker · GitHub](https://github.com/processhacker/processhacker/pull/751)
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

# self-modifying code, packers

Detecting changes in process maps:

```gdb
# https://stackoverflow.com/questions/1780765/setting-a-gdb-exit-breakpoint-not-working
catch syscall exit exit_group
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

### upx

- Dumping executable from memory
    ```gdb
    # break after unpacking, but before executing unpacked code
    catch syscall munmap
    # ~/code/snippets/lief/dump_elf.py
    ```
- Fixing upx tags
    - https://r3v3rs3r.wordpress.com/2015/09/18/solving-fusion-level-9/
- TODO: understand trailing instructions added to unpacked executable map
    - ~/code/wip/upx/
    ```
    0f 05           SYSCALL
    5a              POP        RDX
    c5              RET
    ```

# anti-debugging

### Windows

- user mode (ring 3)
    - https://github.com/x64dbg/ScyllaHide
- kernel mode (ring 0)
    - https://github.com/mrexodia/TitanHide

- [NtQueryInformationProcess function \(winternl\.h\) \- Win32 apps \| Microsoft Docs](https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess?redirectedfrom=MSDN)
    - ProcessDebugPort != 0

### LD_PRELOAD

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

# case studies

- https://tccontre.blogspot.com/2020/11/interesting-formbook-crypter.html


