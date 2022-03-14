# live cd persistance

https://help.ubuntu.com/community/LiveCD/Persistence
https://www.kali.org/docs/usb/kali-linux-live-usb-persistence/

# releases

https://app.vagrantup.com/geerlingguy/boxes/ubuntu2004

# upgrade distro version

```bash
sed -i 's/\(Prompt\)=.*/\1=lts/' /etc/update-manager/release-upgrades
apt update -y
apt upgrade -y
# Optional: systemctl reboot
do-release-upgrade

# Third party sources disabled
# => software-properties
```

# package management

```bash
# Edit dependencies
# https://serverfault.com/questions/250224/how-do-i-get-apt-get-to-ignore-some-dependencies
apt download foo
cd deb
ar x ../foo.deb
tar xzf control.tar.gz (will create: postinst postrm preinst prerm md5sums control)
# || tar xf control.tar.xz (will create: postinst postrm preinst prerm md5sums control)
# [After fixing dependencies in control]
tar --ignore-failed-read -cvzf control.tar.gz {post,pre}{inst,rm} md5sums control
# || tar --ignore-failed-read -cvJf control.tar.xz {post,pre}{inst,rm} md5sums control
ar rcs ../foo.deb debian-binary control.tar.gz data.tar.gz

# https://askubuntu.com/questions/148715/how-to-fix-package-is-in-a-very-bad-inconsistent-state-error
dpkg --remove --force-remove-reinstreq foo

# https://askubuntu.com/questions/179060/how-to-not-install-recommended-and-suggested-packages
str_recommends='APT::Install-Recommends "false";'
str_suggests='APT::Install-Suggests "false";'
target=/etc/apt/apt.conf.d/99noextras
grep -q "$str_recommends" "$target" || printf '%s\n%s\n' "$str_recommends" "$str_suggests" >> "$target"

apt-get source package_name

# https://packages.ubuntu.com/
update-dlocatedb
dlocate
apt-cache search package_name
dpkg-query -L package_name
dpkg-query -S file_name

rpm -ql package_name

apt-get install apt-file
apt-file update
apt-file find file_name
apt-file search file_name
apt-file list package_name

dnf provides file_name
```

### conflicting 32-bit packages

```bash
dpkg --add-architecture i386
apt update

# chroot
# https://jblevins.org/log/ubuntu-chroot
apt-get install debootstrap schroot
debootstrap --variant=buildd --arch i386 focal /var/chroot/i386 http://archive.ubuntu.com/ubuntu/
### validate
schroot -l
schroot -c i386 -u root
### delete
schroot --list --all-sessions
schroot -e -c $id
grep '/var/chroot/i386' /etc/mtab | awk '{print $1}' | xargs -I{} umount {}
rm -rf /var/chroot/i386

# container
docker pull i386/ubuntu:focal
docker run -it -v "$PWD":share --platform linux/i386 i386/ubuntu:focal bash

# Optional: set personality
linux32 foo
```

### disable automatic updates

/etc/apt/apt.conf.d/20auto-upgrades

```
APT::Periodic::Update-Package-Lists "0";
APT::Periodic::Unattended-Upgrade "0";
```
