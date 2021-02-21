# upgrade distro version

On /etc/apt/sources.list:

```
deb http://deb.debian.org/debian buster main contrib
```

```bash
apt update -y
apt upgrade -y
apt full-upgrade

# Validation
dpkg -C
apt-mark showhold
dpkg --audit
# foo is not configured yet
dpkg --configure foo
# ||
dpkg --configure -a
```

https://www.debian.org/releases/buster/amd64/release-notes/ch-upgrading.en.html

# use non-free repositories

On /etc/apt/sources.list:

```
deb http://http.us.debian.org/debian stable main contrib non-free
```

# updates over http

```bash
wget --recursive --no-parent --no-host-directories 192.168.1.4:8123
```

# repair mode

> To access rescue mode, select rescue from the boot menu, type rescue at the boot: prompt, or boot with the rescue/enable=true boot parameter

https://www.debian.org/releases/jessie/amd64/ch08s07.html.en
