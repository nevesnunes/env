#!/bin/sh

set -eux

. ./lib.sh

sudo sed -i 's/^\(deb\(-src\)\? .* main.*\)/\1 contrib non-free/g' /etc/apt/sources.list

sync_debian_packages ./debian-ctf.txt
sync_debian_packages ./debian-essentials.txt
sync_debian_packages ./debian-graphical.txt
sync_debian_packages ./debian-main.txt
sync_python_packages ./python3-site-packages-essentials.txt
sync_python_packages ./python3-site-packages-main.txt
sync_git ./git-ctf.txt
sync_git ./git-essentials.txt

sudo sysctl -w kernel.sysrq=1

sudo sed -i '
  s/^#\?\(GRUB_TERMINAL\)=.*/\1=console/g;
  s/^#\?\(GRUB_GFXMODE\)=.*/\1=text/g
' /etc/default/grub
sudo grub-mkconfig -o /boot/grub/grub.cfg

sudo update-initramfs -c -k all

( cd ~/opt/fzf/ && yes | ./install; )

( cd ~/opt/pwndbg/ && sudo ./setup.sh; )

# sudo locale-gen --purge
# sudo dpkg-reconfigure locales

# whipper
# sync_debian_packages ./debian-whipper.txt
# sudo apt -t testing install cd-paranoia

# deadbeef
# sync_debian_packages ./debian-deadbeef.txt
# sudo apt -t sid install libdispatch-dev
# env CC=clang CXX=clang++ ./configure --prefix=/usr/local
