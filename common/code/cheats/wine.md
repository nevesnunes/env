# debug

```bash
env WINEDEBUG=+all wine
# relay ~= syscalls
env WINEDEBUG=+loaddll,+relay,+seh wine
```

- https://wiki.winehq.org/Wine_Developer%27s_Guide/Debug_Logging
- https://wiki.winehq.org/Debug_Channels

### kill process

```
winedbg

Wine-dbg>info proc
 pid      threads  executable (all id:s are in hex)
 0000000d 4        'taskmgr.exe'
 0000000e 4        'services.exe'
 0000001a 3        \_ 'plugplay.exe'

echo $(( 0x0000000d ))
# 13

Wine-dbg>attach 13
Wine-dbg>kill
Wine-dbg>quit
```

# prefix

```bash
env WINEARCH=win32 WINEPREFIX="$HOME/share/wine32" winecfg
```

# run batch

```bash
wineconsole
# ||
wine cmd.exe
```

# dotnet

```bash
wine msiexec /i ./wine-mono-4.7.5.msi
winetricks dotnet20
```

- https://wiki.winehq.org/Mono#Versions

# performance

- https://github.com/lutris/docs/blob/master/Performance-Tweaks.md
