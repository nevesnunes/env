# +

https://wiki.winehq.org/Wine_Developer%27s_Guide/Debug_Logging
https://wiki.winehq.org/Debug_Channels
relay = syscalls

env WINEDEBUG=+all wine
env WINEDEBUG=+loaddll,+relay,+seh wine

# run batch

wineconsole
wine cmd.exe

# kill process

$ winedbg
Wine-dbg>info proc
 pid      threads  executable (all id:s are in hex)
 0000000d 4        'taskmgr.exe'
 0000000e 4        'services.exe'
 0000001a 3        \_ 'plugplay.exe'
$ echo $(( 0x0000000d ))
Wine-dbg>attach 13
Wine-dbg>kill
Wine-dbg>quit
