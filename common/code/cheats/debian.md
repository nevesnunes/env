# +

```bash
# Updates over http
# - ! Switch ports must be in same VLAN
# - ! Wireless protocols must match
#     - Used by host: iw dev wlan0 station dump
#     - Supported by AP: iw dev wlan0 scan dump
wget --recursive --no-parent --no-host-directories 192.168.1.5:8123
```

# distribution version

```bash
lsb_release -a
hostnamectl
cat /proc/version
cat /etc/*-release
```

# package manager

```bash
# find packages that provides file
apt-file find /foo

# latest installed packages
grep " install " /var/log/dpkg.log{,.1}

# all installed packages
apt list --installed

# downgrade
apt-cache showpkg foo
apt-get install foo=123
apt-mark hold foo

# dependencies
apt-get source foo
grep Build-Depends foo-1.dsc \
    | sed 's/Build-Depends: //g; s/\( ([^\)]*)\)\?, / /g; s/ \[[^]]*\] */ /g;' \
    | xargs apt install
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

- [Chapter 4\. Upgrades from Debian 9 \(stretch\)](https://www.debian.org/releases/buster/amd64/release-notes/ch-upgrading.en.html)

### 11

On /etc/apt/sources.list:

```
deb http://security.debian.org/debian-security/ bullseye-security main
deb-src http://security.debian.org/debian-security/ bullseye-security main
```

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

### extract deb

```bash
ar x _
```

# repair mode

> To access rescue mode, select rescue from the boot menu, type rescue at the boot: prompt, or boot with the rescue/enable=true boot parameter

https://www.debian.org/releases/jessie/amd64/ch08s07.html.en
