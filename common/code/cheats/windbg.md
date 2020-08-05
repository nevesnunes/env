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

# +

https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/setting-up-local-kernel-debugging-of-a-single-computer-manually
https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/getting-started-with-windbg--kernel-mode-
https://voidsec.com/windows-kernel-debugging-exploitation/
https://www.endgame.com/blog/technical-blog/introduction-windows-kernel-debugging


