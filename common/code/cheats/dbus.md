# debug

```bash
dbus-monitor --system
strace -p 1 -s 9999 -ff
```

```strace
accept4(12, 0, NULL, SOCK_CLOEXEC|SOCK_NONBLOCK) = 13
...
getsockname(13, {sa_family=AF_LOCAL, sun_path="/run/systemd/private"}, [23]) = 0
...
sendmsg(13, {msg_name(0)=NULL, msg_iov(2)=[{"l\4\1\1H\0\0\0\2\0\0\0\206\0\0\0\1\1o\0!\0\0\0/org/freedesktop/systemd1/job/242\0\0\0\0\0\0\0\2\1s\0\37\0\0\0org.freedesktop.DBus.Properties\0\3\1s\0\21\0\0\0PropertiesChange"..., 152}, {"\34\0\0\0org.freedesktop.systemd1.Job\0\0\0\0\34\0\0\0\5\0\0\0State\0\1s\0\0\0\0\7\0\0\0running\0\0\0\0\0", 72}], msg_controllen=0, msg_flags=0}, MSG_DONTWAIT|MSG_NOSIGNAL) = 224
```

- [GitHub \- mvidner/dbus\-dump: tool to capture D\-Bus messages in a libpcap capture file](https://github.com/mvidner/dbus-dump)
- http://billauer.co.il/blog/2019/05/dbus-dump-systemd-debugging/
- https://wiki.ubuntu.com/DebuggingDBus
