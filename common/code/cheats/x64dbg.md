# Breakpoints

```
SetBPX kernel32.WriteFile
SetBPX ucrtbase.dll._stricmp

>= w7
SetBPX ntdll.ZwDeviceIoControlFile
~=
SetBPX ntdll.NtDeviceIoControlFile
```
