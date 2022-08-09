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

( cd ~/opt/fzf/ && yes | ./install; )

( cd ~/opt/pwndbg/ && sudo ./setup.sh; )

# Populate z
find /home/"$USER" -maxdepth 3 -type d | \
  grep -E -v '/(\.)|_[a-zA-Z0-9]' | \
  grep -E -v '/opt/' | \
  sort | uniq | xargs -d'\n' -I{} -n1 -r echo "{}|1|1" \
  > /home/"$USER"/.z

mkdir -p ~/.local/share/fonts
( cd ~/.local/share/fonts && wget 'https://github.com/andreberg/Meslo-Font/raw/master/dist/v1.2.1/Meslo%20LG%20DZ%20v1.2.1.zip' && atool -x 'Meslo LG DZ v1.2.1.zip' && rm -f 'Meslo LG DZ v1.2.1.zip' )

sed -i 's%\(^ExecStart\)=.*%\1='$(command -v tint2)'%g' ~/.config/systemd/user/tint2.service
systemctl --user daemon-reload
systemctl --user enable tint2
