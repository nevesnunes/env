# +

- clock_gettime => busy wait
- clone => creating threads
- brk => calling mallocs
- fcntl => manipulating file descriptor
- FUTEX_WAIT loop => mapping has bad permissions
- poll(POLLIN|POLLOUT), all returning POLLOUT => if no writes, loops as fast as possible until data finally available => replace POLLOUT | POLLIN by POLLOUT if writing else POLLIN
    - https://bitbucket.org/pypy/pypy/issues/2900/high-cpu-100-usage-on-reading-from-socket

- https://github.com/pgbovine/strace-plus/blob/master/README-linux-ptrace

# methodologies

- run with `time` to get diff between syscalls time and library calls time

# statistics

```bash
# group by pid
gawk '
    match($0, /^(\[pid\s*)?([0-9]+)(\s*\])?\s*([0-9\.]+)?\s*([A-Za-z_-]+)/, a) {
        out[a[2]]++
        total++
    }
    END {
        for (key in out) {
            printf "%16s | %.2f | %s\n", out[key], (out[key] / total), key
        }
    }
' < strace_redirect.log | sort -V

# group by func
gawk '
    match($0, /^(\[pid\s*)?([0-9]+)(\s*\])?\s*([0-9\.]+)?\s*([A-Za-z_-]+)/, a) {
        out[a[5]]++
        total++
    }
    END {
        for (key in out) {
            printf "%16s | %.2f | %s\n", out[key], (out[key] / total), key
        }
    }
' < strace_redirect.log | sort -V

# group by pid + func
gawk '
    match($0, /^(\[pid\s*)?([0-9]+)(\s*\])?\s*([0-9\.]+)?\s*([A-Za-z_-]+)/, a) {
        v = a[2] "-" a[5]
        out[v]++
        total++
    }
    END {
        for (key in out) {
            printf "%16s | %.2f | %s\n", out[key], (out[key] / total), key
        }
    }
' < strace_redirect.log | sort -V

# foreach pid, group by func
f=./foo
gawk '
    match($0, /^(\[pid\s*)?([0-9]+)(\s*\])?\s*([0-9\.]+)?\s*([A-Za-z_-]+)/, a) {
        out[a[2]]++
    }
    END {
        for (key in out) {
            print key
        }
    }
' < "$f" | xargs -P0 -i sh -c 'x=$1; gawk -v x="$x" '"'"'
    BEGIN {
        printf "PID: %s\n", x
    }
    match($0, /^(\[pid\s*)?([0-9]+)(\s*\])?\s*([0-9\.]+)?\s*([A-Za-z_-]+)/, a) {
        if (a[2] != x) {
            next
        }
        out[a[5]]++
        total++
    }
    END {
        for (key in out) {
            h = ""
            max_h = 8 * out[key] / total
            for (i=0; i<max_h; i++) {
                h = h "="
            }
            printf "%16s | %8s %.2f | %s\n", out[key], h, (out[key] / total), key
        }
    }
'"'"' < '"$f"' | sort -V' _ {}
```

# examples

### connection closed by client

```strace
select(5, [0 4], [], NULL, NULL)        = 1 (in [4])
recvfrom(4, "GET / HTTP/1.1\r\nUser-Agent: curl"..., 8192, 0, NULL, NULL) = 73
...
select(5, [0 4], [], NULL, NULL)        = 1 (in [4])
recvfrom(4, "", 8192, 0, NULL, NULL)    = 0
close(4)                                = 0
```

### read until EOF

```
read(3, "628   1575370401.788909 restart_"..., 65536) = 2201
read(3, "", 65536)                      = 0
close(3)                                = 0
```

SysV compatibility
https://unix.stackexchange.com/questions/517064/why-does-hexdump-try-to-read-through-eof
    https://sourceware.org/ml/libc-alpha/2012-09/msg00343.html

### follow fds

```
open("/foo.sh", O_RDONLY) = 3
ioctl(3, TCGETS, 0x7fffa44700f0)        = -1 ENOTTY (Inappropriate ioctl for device)
lseek(3, 0, SEEK_CUR)
read(3, "#!/bin/sh\n[...]", 80) = 80
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
read(255, "#!/bin/sh\n[...]", 257) = 257
```

### read in alternative resource

```
open("/foo.zip", O_RDONLY) = 12
stat("/bar.class", 0x7fbda85a48c0) = -1 ENOENT (No such file or directory)
lseek(12, 34295740, SEEK_SET <unfinished ...>
<... lseek resumed> )       = 34295740
read(12,  <unfinished ...>
```

### javaagent was loaded

```
stat("/example/com/sun/btrace/org/objectweb/asm/ClassVisitor.class", <unfinished ...>
```

### silent logging

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

### gnome-shell notifications

```bash
strace -f -s 9999 -p 2140 2>1
vim 1
```

- check how requests are handled: execv / sendmsg...
    - `:g!/send.*(/d`
- filter cross-cutting concerns: logging...
    - `:g/GLIB_OLD_LOG_API/d`

```strace
[pid  4346] sendmsg(9, {msg_name=NULL, msg_namelen=0, msg_iov=[{iov_base="l\1\0\1:\0\0\0\207\23\0\0w\0\0\0\1\1o\0\33\0\0\0/ca/desrt/dconf/Writer/user\0\0\0\0\0\2\1s\0\25\0\0\0ca.desrt.dconf.Writer\0\0\0\6\1s\0\16\0\0\0ca.desrt.dconf\0\0\10\1g\0\2ay\0\3\1s\0\6\0\0\0Change\0\0006\0\0\0/org/gnome/desktop/notifications/show-banners\0\0\0\0\0b\0.5", iov_len=194}], msg_iovlen=1, msg_controllen=0, msg_flags=0}, MSG_NOSIGNAL <unfinished ...>
[pid  4346] sendmsg(9, {msg_name=NULL, msg_namelen=0, msg_iov=[{iov_base="l\1\0\1:\0\0\0\210\23\0\0w\0\0\0\1\1o\0\33\0\0\0/ca/desrt/dconf/Writer/user\0\0\0\0\0\2\1s\0\25\0\0\0ca.desrt.dconf.Writer\0\0\0\6\1s\0\16\0\0\0ca.desrt.dconf\0\0\10\1g\0\2ay\0\3\1s\0\6\0\0\0Change\0\0006\0\0\0/org/gnome/desktop/notifications/show-banners\0\0\0\1\0b\0.5", iov_len=194}], msg_iovlen=1, msg_controllen=0, msg_flags=0}, MSG_NOSIGNAL) = 194
```

- [ ] how to cluster these lines? by most common (e.g. GLIB_OLD_LOG_API), by least common (e.g. show-banners)...
    - ~/code/data/strace-patterns/gnome-shell-notifications

### Xorg

repeated pattern:

```strace
[pid  2236] epoll_wait(4, [{EPOLLIN, {u32=2334095552, u64=93971923564736}}], 256, -1) = 1
[pid  2236] setitimer(ITIMER_REAL, {it_interval={tv_sec=0, tv_usec=5000}, it_value={tv_sec=0, tv_usec=5000}}, NULL) = 0
[pid  2236] recvmsg(32, {msg_name=NULL, msg_namelen=0, msg_iov=[{iov_base="\216\3\4\0uxb\0\0\0\0\0\0\0\0\0", iov_len=16384}], msg_iovlen=1, msg_controllen=0, msg_flags=0}, 0) = 16
[pid  2236] recvmsg(32, {msg_namelen=0}, 0) = -1 EAGAIN (Resource temporarily unavailable)
[pid  2236] setitimer(ITIMER_REAL, {it_interval={tv_sec=0, tv_usec=0}, it_value={tv_sec=0, tv_usec=0}}, NULL) = 0
[pid  2236] getpid()                    = 2236
[pid  2236] getpid()                    = 2236
[pid  2236] getpid()                    = 2236
[pid  2236] getpid()                    = 2236
```

- [ ] how to filter out these sequences, which can be mixed with other calls?

```strace
[pid  2236] epoll_wait(4, [{EPOLLIN, {u32=2334095552, u64=93971923564736}}], 256, -1) = 1
[pid  2236] setitimer(ITIMER_REAL, {it_interval={tv_sec=0, tv_usec=5000}, it_value={tv_sec=0, tv_usec=5000}}, NULL) = 0
[pid  2236] recvmsg(32, {msg_name=NULL, msg_namelen=0, msg_iov=[{iov_base="\31\0\v\0\345\341\345\1\0\0\0\0! \0\0\345\341\345\1\357\1\0\0\346\215\3\0\0\0\0\0\233c\253\225P\0\0\0\0\0\0\0", iov_len=16384}], msg_iovlen=1, msg_controllen=0, msg_flags=0}, 0) = 44
[pid  2236] writev(56, [{iov_base="\241 >o\345\341\345\1\357\1\0\0\346\215\3\0\0\0\0\0\233c\253\225P\0\0\0\0\0\0\0", iov_len=32}], 1) = 32
[pid  2236] recvmsg(32, {msg_namelen=0}, 0) = -1 EAGAIN (Resource temporarily unavailable)
[pid  2236] setitimer(ITIMER_REAL, {it_interval={tv_sec=0, tv_usec=0}, it_value={tv_sec=0, tv_usec=0}}, NULL) = 0
[pid  2236] getpid()                    = 2236
[pid  2236] getpid()                    = 2236
[pid  2236] getpid()                    = 2236
[pid  2236] getpid()                    = 2236
[pid  2236] epoll_wait(4, [{EPOLLIN, {u32=2323670640, u64=93971913139824}}], 256, -1) = 1
[pid  2236] read(15, "\2\0\0\0 \0\0\0J\215/\0\0\0\0\0\374G\5\0\362\224\6\0\342\330<\1<\0\0\0", 1024) = 32
[pid  2236] writev(11, [{iov_base="#\223\340\325\0\0\0\0\2\0\0\0\"\0@\0\21\0@\0@\374\37\0O\373@\0P\373@\0", iov_len=32}], 1) = 32
[pid  2236] writev(11, [{iov_base="#\223\340\325\2\0\0\0\1\0\0\1\"\0@\0\21\0@\0A\374\37\0\362\213\253\225P\0\0\0\332\327<\1\0\0\0\0", iov_len=40}], 1) = 40
[pid  2236] writev(11, [{iov_base="_\0\340\325\202\201\0\0\22\0@\0P\0\0\0\362\213\253\225\0\0\0\0\332\327<\1A\374\37\0", iov_len=32}], 1) = 32
[pid  2236] ioctl(15, DRM_IOCTL_MODE_RMFB, 0x7ffd066797dc) = 0
[pid  2236] getpid()                    = 2236
[pid  2236] getpid()                    = 2236
[pid  2236] getpid()                    = 2236
[pid  2236] getpid()                    = 2236
```

# case studies

- [How does \`ls\` work? · GitHub](https://gist.github.com/amitsaha/8169242)
    - ~/Downloads/ls.rst
