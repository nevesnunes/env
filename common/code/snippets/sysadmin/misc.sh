# Run local PHP server
php -S localhost:port

# Pacifism
chmod 000 <file>

# Run app in seperate X display
xinit <app> -- :1

# Running output
strace -ewrite -s9999 -p<pid> 2>&1 | grep "write(1"

touch <file>
gdb -p <pid>
call close(1)
call open ("<file>", 0400)

# [Wine] Remove apps
wine uninstaller

~/.wine/drive_c/Program Files
~/.local/share/applications/wine/Programs/
wine configuration > applications > remove .exe

# Run multiple apps in bash
prog1 &
prog2 &

# 32 vs 64
schroot
      
# Clean kill
Alt+SysRQ+e (sends TERM-signal, processes can shutdown properly (e.g. save data))
Alt+SysRQ+u (a sync will be done when unmounting anyway)
Alt+SysRQ+i (for the processes that didnt listen for the TERM signal, this is a kill -9 process)
Alt+SysRQ+b (reboot)

# MISC
cat /proc/version
lsb_release -a
uname -a

> /dev/null 2>&1
