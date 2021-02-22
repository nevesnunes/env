# Keybinds

- Find pattern - `Ctrl-b`

# Modules

- Debug > Run to user code

# Scripting

1. On `Command` input field: 

```
scriptload "C:\foo"
```

2. Select tab `Script` > [Context Menu] Run

- [GitHub \- x64dbg/Scripts: A collection of x64dbg scripts\. Feel free to submit a pull request to add your script\.](https://github.com/x64dbg/Scripts/)

# Breakpoints

```
SetBPX kernel32.WriteFile
SetBPX kernelbase.WriteFile

SetBPX ntdll.ZwQueryDirectoryFileW
SetBPX kernelbase.FindNextFileExW
SetBPX kernelbase.FindFirstFileExW

SetBPX NtCreateSection

SetBPX ucrtbase.dll._stricmp

>= w7
SetBPX ntdll.ZwDeviceIoControlFile
~=
SetBPX ntdll.NtDeviceIoControlFile

# after unpacking
# - https://criticaldefence.com/malware-analysis-part-2/
SetBPX VirtualFree
```
