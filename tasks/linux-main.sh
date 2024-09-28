#!/bin/sh

set -eux

. ./lib.sh

sudo sed -i 's/^\(deb\(-src\)\? .* main.*\)/\1 contrib non-free/g' /etc/apt/sources.list

curl https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor > microsoft.gpg
sudo install -o root -g root -m 644 microsoft.gpg /usr/share/keyrings/microsoft-archive-keyring.gpg
sudo sh -c 'echo "deb [arch=amd64,arm64,armhf signed-by=/usr/share/keyrings/microsoft-archive-keyring.gpg] https://packages.microsoft.com/repos/vscode stable main" > /etc/apt/sources.list.d/vscode.list'
rm -f microsoft.gpg
sudo apt update
sudo apt install -y code

debloat
sync_debian_packages ./debian-ctf.txt
sync_debian_packages ./debian-essentials.txt
sync_debian_packages ./debian-graphical.txt
sync_debian_packages ./debian-main.txt
sync_gem_packages ./gem-packages.txt
sync_npm_packages ./npm-packages.txt
sync_python_packages ./python3-site-packages-essentials.txt
sync_python_packages ./python3-site-packages-main.txt
sync_git ./git-ctf.txt
sync_git ./git-essentials.txt

curl --proto '=https' --tlsv1.2 -LsSf https://setup.atuin.sh | sh

curl -s 'https://get.sdkman.io' | sh
sdk install gradle 8.6
sdk install java 21.0.2-open

# Allow separate X servers to be run with sound
sudo usermod -a -G audio "$USER"
# VirtualBox
sudo usermod -a -G wheel "$USER"
sudo usermod -a -G vboxusers "$USER"

sudo sysctl -w kernel.sysrq=1

sudo sed -i '
  s/^#\?\(GRUB_TERMINAL\)=.*/\1=console/g;
  s/^#\?\(GRUB_GFXMODE\)=.*/\1=text/g
' /etc/default/grub
sudo grub-mkconfig -o /boot/grub/grub.cfg

sudo update-initramfs -c -k all

for i in EHC1 EHC2 EHC3 USB1 USB2 USB3 XHC; do
  grep -q "$i.*enabled" /proc/acpi/wakeup \
    && sudo sh -c 'echo "'$i'" > /proc/acpi/wakeup'
done

. ./dconf-load.sh
# dconf load / < ../linux/code/config/dconf.txt
dconf load /org/gnome/desktop/wm/keybindings/ \
  < ../linux/code/config/dconf-wm-keybindings.txt
dconf load /org/gnome/settings-daemon/plugins/media-keys/ \
  < ../linux/code/config/dconf-custom-keybinds.txt

. ./sync-user.sh

# sudo locale-gen --purge
# sudo dpkg-reconfigure locales

# whipper
# sync_debian_packages ./debian-whipper.txt
# sudo apt -t testing install cd-paranoia

# deadbeef
# sync_debian_packages ./debian-deadbeef.txt
# sudo apt -t sid install libdispatch-dev
# env CC=clang CXX=clang++ ./configure --prefix=/usr/local
