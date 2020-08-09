# +

https://hshrzd.wordpress.com/2017/05/28/starting-with-windows-kernel-exploitation-part-1-setting-up-the-lab/
https://hshrzd.wordpress.com/2016/07/21/how-to-turn-a-dll-into-a-standalone-exe/

https://kiewic.com/2014-07-26/win32-mutex-handles-and-windbg-handle-extension

# cheatsheet

http://sandsprite.com/blogs/index.php?uid=7&pid=51
https://dblohm7.ca/pmo/windbgcheatsheet.html

# methodology

find the call stack in procmon and set a breakpoint on one of the function
-- https://reverseengineering.stackexchange.com/questions/15823/how-can-windbg-be-used-to-troubleshoot-program-loading

# preview

https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/debugging-using-windbg-preview

# heap dump on crash

```
!analyze -v
```

# symbols

https://techcommunity.microsoft.com/t5/IIS-Support-Blog/Getting-better-stack-traces-in-Process-Monitor-Process-Explorer/ba-p/376407
    path - `srv*c:\symcache*http://msdl.microsoft.com/download/symbols`
    [xref] procmon, procexp

# case studies

```
Want to see all undocumented parameters of certutil.exe?
1. run "certutil -?" under #WinDbg
2. bp certutil!Usage
3. Find test byte ptr [rbx], 4
4. Replace 4 with 0 (eb 00007ff6`8f417218 00)
5. Let it run
```
https://twitter.com/0gtweet/status/1236960061873967104

# kernel debugging

https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/setting-up-local-kernel-debugging-of-a-single-computer-manually
https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/getting-started-with-windbg--kernel-mode-
https://voidsec.com/windows-kernel-debugging-exploitation/
https://www.endgame.com/blog/technical-blog/introduction-windows-kernel-debugging

# log syscalls

```
.load logexts

!loge \\foo
!logb f
g
```

# disable breaks on ProcessCreate, ProcessExit

windbg.exe -g -G MyProgram.exe

```
sxn cpr [:Process] 
sxn epr [:Process]
```

# disable breaks on exceptions

```
sxn c00000005
```

https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/controlling-exceptions-and-events?redirectedfrom=MSDN

# describe exceptions

```
.exr
!analyze
```

# stackframes - go up without hitting breakpoints

```
bd *; gu; be *;
```

# printf open files

```
bp kernelbase!CreateFileW ".printf \"Opening file: <%mu> \", dwo(@esp+4); .echo ---; k 3; gc"
bp kernelbase!CreateFileW du /c100(@rcx); k 3; gc
```

https://techblog.dorogin.com/windbg-how-to-set-a-breakpoint-at-win32-createfile-for-a-win64-process-a5ac952ad8be

# docs

https://doxygen.reactos.org/dc/de2/ARM3_2section_8c_source.html#l03369


