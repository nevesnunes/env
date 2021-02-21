# Keybinds

- Find pattern - `Ctrl-b`

# Modules

- Debug > Run to user code

# Scripting

```
scriptload "C:\foo"
```

# Breakpoints

```
SetBPX NtCreateSection
SetBPX kernel32.WriteFile
SetBPX ucrtbase.dll._stricmp

>= w7
SetBPX ntdll.ZwDeviceIoControlFile
~=
SetBPX ntdll.NtDeviceIoControlFile

# after unpacking
# - https://criticaldefence.com/malware-analysis-part-2/
SetBPX VirtualFree
```
