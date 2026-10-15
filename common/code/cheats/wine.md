# compile (debian)

```bash
mkdir -p $HOME/code/chroot/wine32
cd $HOME/code/chroot
sudo debootstrap --arch i386 stable $HOME/code/chroot/wine32 http://deb.debian.org/debian/
sudo mkdir -p $HOME/code/chroot/wine32/mnt/opt
sudo mount -o bind $HOME/opt wine32/mnt/opt
sudo mount -o bind /proc wine32/proc
sudo cp /etc/resolv.conf wine32/etc/resolv.conf
# sudo cp /etc/hosts wine32/etc/hosts
# sudo cp /proc/mounts wine32/etc/mtab
sudo chroot wine32

sudo apt install libx11-dev:i386 libfreetype-dev:i386 libxcursor-dev:i386 libxi-dev:i386 libxxf86vm-dev:i386 libxrandr-dev:i386 libxinerama-dev:i386 libxcomposite-dev:i386 libxrender-dev:i386 libglu-dev:i386 libosmesa-dev:i386 libglu-dev:i386 libosmesa-dev:i386 libdbus-1-dev:i386 libncurses-dev:i386 libv4l-dev:i386 libgphoto\*-dev:i386 liblcms-dev:i386 libgstreamer-plugins\*-dev:i386 libcapi20-dev:i386 libcups2-dev:i386 libfontconfig-dev:i386 libgsm1-dev:i386 libtiff-dev:i386 libpng-dev:i386 libjpeg-dev:i386 libmpg123-dev:i386 libopenal-dev:i386 libldap-dev:i386 libxml2-dev:i386 libxslt-dev:i386 gettext:i386 bzip2:i386 bison:i386 flex:i386 checkinstall:i386 ocl-icd-libopencl1:i386 opencl-headers:i386 libasound2-dev:i386 build-essential
# ||
sudo apt install devscripts
mk-build-deps wine
sudo apt install wine-build-deps_*.deb

exit
sudo apt install pipewire-alsa:i386
```

- https://verahill.blogspot.com/2013/04/387-compiling-wine-1528-in-i386-chroot.html

# debug

```bash
# ~/code/snippets/wine/channels.txt
env WINEDEBUG=+all wine
# relay ~= syscalls
env WINEDEBUG=+loaddll,+relay,+seh wine
```

- [Wine Developer's Guide/Debug Logging \- WineHQ Wiki](https://wiki.winehq.org/Wine_Developerwine.md27s_Guide/Debug_Logging)
- [Debug Channels \- WineHQ Wiki](https://wiki.winehq.org/Debug_Channels)
- [GitHub \- JuliaComputing/gdb\-solib\-wine: GDB enhanced to debug wine processes](https://github.com/JuliaComputing/gdb-solib-wine)
- [Debugging Wine with LLDB and VSCode \| Andy Hippo](https://werat.dev/blog/debugging-wine-with-lldb-and-vscode/)

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
