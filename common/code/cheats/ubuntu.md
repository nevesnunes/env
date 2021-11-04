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

### disable automatic updates

/etc/apt/apt.conf.d/20auto-upgrades

```
APT::Periodic::Update-Package-Lists "0";
APT::Periodic::Unattended-Upgrade "0";
```
