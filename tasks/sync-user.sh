#!/bin/sh

set -eux

sudo chsh -s /usr/bin/zsh "$USER"
tmux source-file ~/.tmux.conf
xrdb -merge ~/.Xresources
xset r rate 300 25

# https://unix.stackexchange.com/questions/94299/dircolors-modify-color-settings-globaly
# man dir_colors
[ -f ~/.dircolors ] && dircolors ~/.dircolors > ~/.lscolors
[ -f ~/.lesskey ] && command -v lesskey > /dev/null 2>&1 && lesskey

# Populate z
find /home/"$USER" -maxdepth 3 -type d \
  | grep -E -v '/(\.)|_[a-zA-Z0-9]' \
  | grep -E -v '/opt/' \
  | sort | uniq | xargs -d'\n' -I{} -n1 -r echo "{}|1|1" \
  > /home/"$USER"/.z

mkdir -p ~/.local/share/fonts
cd ~/.local/share/fonts && wget 'https://github.com/andreberg/Meslo-Font/raw/master/dist/v1.2.1/Meslo%20LG%20DZ%20v1.2.1.zip' && atool -x 'Meslo LG DZ v1.2.1.zip' && rm -f 'Meslo LG DZ v1.2.1.zip'

cd ~/opt/fzf/ && yes | ./install

cd ~/opt/pwndbg/ && sudo ./setup.sh

cd ~
