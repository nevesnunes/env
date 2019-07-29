#!/bin/sh

set -eux

env_file=${1:-${0%.sh}.env}
. "$env_file"

# Repositories

mount /dev/sr0 /media
cp /media/media.repo /etc/yum.repos.d/rhel7dvd.repo
chmod 644 /etc/yum.repos.d/rhel7dvd.repo
# ```/etc/yum.repos.d/rhel7dvd.repo
# gpgcheck=1
# cost=500
# enabled=1
# baseurl=file:///media/
# gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release
# ```

scp rhel-server-7.4-x86_64-dvd.iso root@HOST:/opt/
mount -o loop /opt/rhel-server-7.4-x86_64-dv d.iso /media/

# X Forwarding

# [server]
yum clean all
subscription-manager clean
yum  --noplugins list
yum  --noplugins update
yum  --noplugins install open-vm-tools
yum update
yum install -y \
    vim \
    libXtst xorg-x11-server-Xorg xorg-x11-xauth xorg-x11-app
# ```/etc/ssh/sshd_config
# X11Forwarding yes
# ```
systemctl restart sshd

# [client]
choco install xming
/c/Program\ Files\ \(x86\)/Xming/Xming -multiwindow -clipboard
env DISPLAY=127.0.0.1:0 ssh root@HOST -Y

# References
# https://serverfault.com/questions/273847/what-does-warning-untrusted-x11-forwarding-setup-failed-xauth-key-data-not-ge
