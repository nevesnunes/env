# +

```bash
# updates over http
wget --recursive --no-parent --no-host-directories 192.168.1.4:8123
```

# package manager

```bash
# latest installed packages
grep " install " /var/log/dpkg.log{,.1}

# downgrade
apt-cache showpkg foo
apt-get install foo=123
apt-mark hold foo
```

### upgrade distro version

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

### non-free repositories

On /etc/apt/sources.list:

```
deb http://http.us.debian.org/debian stable main contrib non-free
```

### testing

On /etc/apt/sources.list:

```
deb http://http.us.debian.org/debian testing main contrib
```

On /etc/apt/apt.conf.d/00default-release:

```
APT::Default-Release "stable";
```

Installing packages:

```bash
apt -t testing install foo
```

# repair mode

> To access rescue mode, select rescue from the boot menu, type rescue at the boot: prompt, or boot with the rescue/enable=true boot parameter

https://www.debian.org/releases/jessie/amd64/ch08s07.html.en
