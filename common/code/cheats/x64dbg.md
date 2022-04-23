# +

- http://reverseengineeringtips.blogspot.com/2015/01/an-introduction-to-x64dbg.html

- https://github.com/mrexodia/StackContains
- https://github.com/Air14/HyperHide

# Keybinds

- Options > Shortcuts
    - Find pattern - `Ctrl-b`

# Modules

- Debug > Run to user code

# DLL

1. load rundll32.exe
2. File > Change Command Line > `"C:\Windows\System32\rundll32.exe" "C:\foo.dll", #1`
3. Option > Preferences > Check: "DLL Entry Point"

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

// >= w7
SetBPX ntdll.ZwDeviceIoControlFile
// ~=
SetBPX ntdll.NtDeviceIoControlFile

// after unpacking
// - https://criticaldefence.com/malware-analysis-part-2/
SetBPX VirtualFree

// clear previous breakpoints
bc
bphwc
bpmc

// ~= gdb tbreak
SetBPX 004015f4
SetBreakpointCondition 004015f4,0
SetBreakpointLog 004015f4,hit:{eip}
SetBreakpointLogCondition 004015f4,$breakpointcounter==1

// write-only
bphws 006fd712,w,1
SetHardwareBreakpointCondition 006fd712,0
SetHardwareBreakpointLog 006fd712,hit_0:{eip}_v:{byte(006fd712)}
SetHardwareBreakpointLogCondition 006fd712,$breakpointcounter==1

// bpgoto
SetBreakpointCondition arg1, 0
SetBreakpointCommand arg1, "CIP=arg2"
SetBreakpointCommandCondition arg1, 1
SetBreakpointFastResume arg1, 0

// Skip EXCEPTION_PRIV_INSTRUCTION
SetExceptionBPX c0000096,3
SetExceptionBreakpointCondition c0000096,0
SetExceptionBreakpointCommand c0000096,skip
SetExceptionBreakpointCommandCondition c0000096,1
```
