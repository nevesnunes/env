# follow fds

open("/bin/fooConfig.sh", O_RDONLY) = 3
ioctl(3, TCGETS, 0x7fffa44700f0)        = -1 ENOTTY (Inappropriate ioctl for device)
lseek(3, 0, SEEK_CUR)
read(3, "#!/bin/sh\n#\n# foo .............................................................", 80) = 80
lseek(3, 0, SEEK_SET)                   = 0
getrlimit(RLIMIT_NOFILE, {rlim_cur=1024, rlim_max=4*1024}) = 0
fcntl(255, F_GETFD)                     = -1 EBADF (Bad file descriptor)
dup2(3, 255)                            = 255
close(3)                                = 0
fcntl(255, F_SETFD, FD_CLOEXEC)         = 0
fcntl(255, F_GETFL)                     = 0x8000 (flags O_RDONLY|O_LARGEFILE)
fstat(255, {st_mode=S_IFREG|0755, st_size=257, ...}) = 0
lseek(255, 0, SEEK_CUR)                 = 0
rt_sigprocmask(SIG_BLOCK, NULL, [], 8)  = 0
read(255, "#!/bin/sh\n#\n# foo .............................................................", 257) = 257

# read in alternative resource

open("/tmp/foo.zip", O_RDONLY) = 12
stat("/tmp/F.class", 0x7fbda85a48c0) = -1 ENOENT (No such file or directory)
lseek(12, 34295740, SEEK_SET <unfinished ...>
<... lseek resumed> )       = 34295740
read(12,  <unfinished ...>

# javaagent was loaded

stat("/tmp/com/sun/btrace/org/objectweb/asm/ClassVisitor.class", <unfinished ...>

# silent logging

```
stat("/root/.visualvm/8u40/var/log/messages.log", {st_mode=S_IFREG|0644, st_size=0, ...}) = 0
...
write(38, "-------------------------------------------------------------------------------
>Log Session: Monday, September 9, 2019 11:26:51 AM WEST
...
java.lang.UnsatisfiedLinkError: /opt/jdk1.8.0_77/jre/lib/amd64/libawt_xawt.so: libXtst.so.6: cannot open shared obje
       ct file: No such file or directory
        ...
        at sun.awt.X11GraphicsEnvironment$1.run(X11GraphicsEnvironment.java:77)
```
