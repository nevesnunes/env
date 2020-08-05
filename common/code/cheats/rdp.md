# rdp

# Use multiple monitors

```
mstsc /w:5000 /h:1600
```

# Workaround client path validations

```
net use X: \\tsclient\x
net use
```

# Mapping client devices

```
net use com1: \\tsclient\com2:
net use
```

https://docs.citrix.com/en-us/receiver/windows/current-release/optimize/map-client-devices.html#map-client-drives-to-host-side-drive-letters

# Automation

```ps1
Add-Type -AssemblyName System.Windows.Forms
$f = New-Object System.Collections.Specialized.StringCollection
$f.Add("D:\tmp\mypic1.bmp")
[System.Windows.Forms.Clipboard]::SetFileDropList($f)
```

https://superuser.com/questions/966428/is-there-a-way-to-programatically-copy-and-paste-to-an-rdp


