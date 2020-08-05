# Windows alternative

```basic
Option explicit
Dim oShell
set oShell= Wscript.CreateObject("WScript.Shell")
oShell.Run "telnet"
WScript.Sleep 1000
oShell.Sendkeys "open 172.25.15.9~"
WScript.Sleep 1000
oShell.Sendkeys "password~"
WScript.Sleep 1000
oShell.Sendkeys "en~"
WScript.Sleep 1000
oShell.Sendkeys "password~"
WScript.Sleep 1000
oShell.Sendkeys "reload~"
WScript.Sleep 1000
oShell.Sendkeys "~"
Wscript.Quit
```

-- https://stackoverflow.com/a/9484147

https://stackoverflow.com/questions/12730293/how-does-telnet-differ-from-a-raw-tcp-connection
    Telnet is a way of passing control information about the communication channel. It defines line-buffering, character echo...
