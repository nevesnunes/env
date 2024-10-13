# debug

```bash
# ~/code/snippets/wine/channels.txt
env WINEDEBUG=+all wine
# relay ~= syscalls
env WINEDEBUG=+loaddll,+relay,+seh wine
```

- [Wine Developer's Guide/Debug Logging \- WineHQ Wiki](https://wiki.winehq.org/Wine_Developerwine.md27s_Guide/Debug_Logging)
- [Debug Channels \- WineHQ Wiki](https://wiki.winehq.org/Debug_Channels)

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

### gdb remote

```
winedbg --gdb --no-start

# On gdb client:
target remote localhost:12345
```

- [Wine Developer's Guide/Debugging Wine \- WineHQ Wiki](https://wiki.winehq.org/Wine_Developerwine.md27s_Guide/Debugging_Wine#Other_debuggers)
- [GitHub \- JuliaComputing/gdb\-solib\-wine: GDB enhanced to debug wine processes](https://github.com/JuliaComputing/gdb-solib-wine)

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

- [Mono \- WineHQ Wiki](https://wiki.winehq.org/Mono#Versions)

# performance

- [docs/Performance\-Tweaks\.md at master · lutris/docs · GitHub](https://github.com/lutris/docs/blob/master/Performance-Tweaks.md)
