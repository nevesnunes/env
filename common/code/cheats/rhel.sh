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

scp "$RHEL_DVD_PATH/rhel-server-7.4-x86_64-dvd.iso" root@HOST:/opt/
mount -o loop /opt/rhel-server-7.4-x86_64-dvd.iso /media/

# X Forwarding

# [server]
yum clean all
subscription-manager clean
yum --noplugins list
yum --noplugins update
yum --noplugins install open-vm-tools
yum update
yum install -y \
    libXtst xorg-x11-server-Xorg xorg-x11-xauth xorg-x11-app xorg-x11-utils \
    bind-utils lsof sysstat \
    vim
# /etc/ssh/sshd_config
# ```
# X11Forwarding yes
# ```
systemctl restart sshd

# Validation
stat "$HOME"/.Xautority
command -v xprop -root
command -v xdpyprobe
command -v xdpyinfo

# [client]
choco install xming
/c/Program\ Files\ \(x86\)/Xming/Xming -multiwindow -clipboard
env DISPLAY=127.0.0.1:0 ssh root@HOST -Y

# References
# - https://serverfault.com/questions/273847/what-does-warning-untrusted-x11-forwarding-setup-failed-xauth-key-data-not-ge

# Optional channels

subscription-manager remove --all
subscription-manager unregister
subscription-manager clean
subscription-manager register
subscription-manager refresh
subscription-manager attach --auto
subscription-manager repos --enable rhel-7-server-extras-rpms
subscription-manager repos --enable rhel-7-server-optional-rpms
subscription-manager repos --enable rhel-server-rhscl-7-rpms

# References
# - https://access.redhat.com/solutions/57504   
