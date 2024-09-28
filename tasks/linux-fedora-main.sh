#!/bin/sh

set -eux

. ./lib.sh

sudo dnf -y install \
  "http://download1.rpmfusion.org/free/fedora/rpmfusion-free-release-$(rpm -E %fedora).noarch.rpm" \
  "http://download1.rpmfusion.org/nonfree/fedora/rpmfusion-nonfree-release-$(rpm -E %fedora).noarch.rpm" \
  "http://rpm.livna.org/livna-release.rpm"
cd /etc/yum.repos.d/
sudo wget "http://download.virtualbox.org/virtualbox/rpm/fedora/virtualbox.repo"

sudo rpm --import https://packages.microsoft.com/keys/microsoft.asc
sudo sh -c 'echo -e "[code]\nname=Visual Studio Code\nbaseurl=https://packages.microsoft.com/yumrepos/vscode\nenabled=1\ngpgcheck=1\ngpgkey=https://packages.microsoft.com/keys/microsoft.asc" > /etc/yum.repos.d/vscode.repo'

debloat
sync_gem_packages ./gem-packages.txt
sync_npm_packages ./npm-packages.txt
sync_rpm_packages ./fedora-main.txt
sync_rpm_packages ./fedora-tex.txt

curl --proto '=https' --tlsv1.2 -LsSf https://setup.atuin.sh | sh

curl -s 'https://get.sdkman.io' | sh
sdk install gradle 8.6
sdk install java 21.0.2-open

curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
cargo install biodiff rustfilt

cd ~/opt
wget 'http://pear.php.net/go-pear.phar'
php go-pear.phar
pear install apinstein.pearfarm.org/iphp

systemctl restart cgconfig
chown -R "$USER" /sys/fs/cgroup/memory/browsers/ /sys/fs/cgroup/blkio/browsers/ /sys/fs/cgroup/cpu,cpuacct/browsers/

plymouth-set-default-theme details -R

systemctl enable mlocate-updatedb.timer
systemctl --user daemon-reload
systemctl --user enable continuous-silence dropbox mouse rm-systemd-env

. ./dconf-load.sh

. ./sync-user.sh
