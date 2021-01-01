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


