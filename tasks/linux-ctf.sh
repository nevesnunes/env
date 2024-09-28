#!/bin/sh

set -eux

. ./lib.sh

debloat
sync_debian_packages ./debian-ctf.txt
sync_debian_packages ./debian-essentials.txt
sync_debian_packages ./debian-graphical.txt
sync_python_packages ./python3-site-packages-ctf.txt
sync_git ./git-ctf.txt
sync_git ./git-essentials.txt

sudo locale-gen en_US.UTF-8
sudo update-locale

sudo sysctl -w kernel.sysrq=1

sudo sed -i '
  s/^#\?\(GRUB_TERMINAL\)=.*/\1=console/g;
  s/^#\?\(GRUB_GFXMODE\)=.*/\1=text/g
' /etc/default/grub
sudo grub-mkconfig -o /boot/grub/grub.cfg

touch "/home/$USER/50-autologin.conf"
cat > "/home/$USER/50-autologin.conf" << EOF
[SeatDefaults]
autologin-user=$USER
autologin-user-timeout=0
EOF
sudo mv "/home/$USER/50-autologin.conf" /usr/share/lightdm/lightdm.conf.d/.

sed -i 's%\(^ExecStart\)=.*%\1='$(command -v tint2)'%g' ~/.config/systemd/user/tint2.service
systemctl --user daemon-reload
systemctl --user enable tint2

. ./sync-user.sh
