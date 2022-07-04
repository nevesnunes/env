#!/bin/sh

set -eux

. ./lib.sh

sync_debian_packages ./debian-ctf.txt
sync_debian_packages ./debian-essentials.txt
sync_debian_packages ./debian-graphical.txt
sync_debian_packages ./debian-main.txt
sync_python_packages ./python3-site-packages-essentials.txt
sync_git ./git-ctf.txt
sync_git ./git-essentials.txt

sudo sysctl -w kernel.sysrq=1

sudo sed -i '
  s/^#\?\(GRUB_TERMINAL\)=.*/\1=console/g;
  s/^#\?\(GRUB_GFXMODE\)=.*/\1=text/g
' /etc/default/grub
sudo grub-mkconfig -o /boot/grub/grub.cfg

( cd ~/opt/fzf/ && yes | ./install; )

( cd ~/opt/pwndbg/ && sudo ./setup.sh; )

# whipper
# sudo apt install -y \
#   flac swig \
#   libcdio-dev libdiscid-dev libiso9660-dev libsndfile1-dev
# sudo apt -t testing install -y \
#   cd-paranoia
