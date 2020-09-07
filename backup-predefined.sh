#!/bin/sh

if [ "$(id -u)" -eq 0 ]; then
  USER=$(logname)
  if ! [ -d "/home/$USER" ]; then
    echo "[FAIL] No home directory for \$USER=$USER."
    exit 1
  fi
fi

rsync -uva --relative --usermap=:"$USER" --groupmap=:"$USER" \
  --copy-links \
  --exclude='code/snippets/+' \
  --exclude='.git' \
  --exclude='node_modules' \
  --filter='dir-merge,- .gitignore' \
  /home/"$USER"/./code/cheats \
  /home/"$USER"/./code/snippets \
  ./common/

rsync -uva --relative --usermap=:"$USER" --groupmap=:"$USER" \
  --copy-links \
  --exclude='.config/retroarch/playlists' \
  --exclude='.dosbox/capture' \
  --exclude='.local/share/applications/wine*' \
  --exclude='.tmux/resurrect' \
  --exclude='.vim/bundle*' \
  --exclude='.vim/.netrwhist' \
  --exclude='.vim/.VimballRecord' \
  --exclude='bookmarks' \
  --exclude='gimpswap.*' \
  --exclude='.git' \
  --exclude='node_modules' \
  --filter='dir-merge,- .gitignore' \
  /home/"$USER"/./.bashrc* \
  /home/"$USER"/./.bash_profile \
  /home/"$USER"/./.bash_prompt \
  /home/"$USER"/./.clang-format \
  /home/"$USER"/./.ctags \
  /home/"$USER"/./.dircolors \
  /home/"$USER"/./.dosbox* \
  /home/"$USER"/./.eslintrc \
  /home/"$USER"/./.fluxbox \
  /home/"$USER"/./.gdbinit* \
  /home/"$USER"/./.gemrc \
  /home/"$USER"/./.gimp-2.8 \
  /home/"$USER"/./.gitconfig \
  /home/"$USER"/./.gitignore_global \
  /home/"$USER"/./.gtkrc-2.0 \
  /home/"$USER"/./.lesskey \
  /home/"$USER"/./.less_termcap \
  /home/"$USER"/./.icewm \
  /home/"$USER"/./.infokey \
  /home/"$USER"/./.inputrc \
  /home/"$USER"/./.jshintrc \
  /home/"$USER"/./.milkytracker_config \
  /home/"$USER"/./.mostrc \
  /home/"$USER"/./.npmrc \
  /home/"$USER"/./.oh-my-zsh \
  /home/"$USER"/./.pdbrc \
  /home/"$USER"/./.pentadactylrc \
  /home/"$USER"/./.profile \
  /home/"$USER"/./.pryrc \
  /home/"$USER"/./.pwn.conf \
  /home/"$USER"/./.pylintrc \
  /home/"$USER"/./.rlwrap \
  /home/"$USER"/./.rubocop.yml \
  /home/"$USER"/./.screenlayout \
  /home/"$USER"/./.shrc \
  /home/"$USER"/./.stalonetrayrc \
  /home/"$USER"/./.tmux* \
  /home/"$USER"/./.taskrc \
  /home/"$USER"/./.tern-config \
  /home/"$USER"/./.urxvt \
  /home/"$USER"/./.vim \
  /home/"$USER"/./.vimrc \
  /home/"$USER"/./.vimperator/colors \
  /home/"$USER"/./.vimperatorrc \
  /home/"$USER"/./.xbindkeysrc \
  /home/"$USER"/./.xkb \
  /home/"$USER"/./.Xresources* \
  /home/"$USER"/./.zshrc \
  /home/"$USER"/./.chocolate-doom/*.cfg \
  /home/"$USER"/./.config/awesome \
  /home/"$USER"/./.config/beets \
  /home/"$USER"/./.config/compton.conf \
  /home/"$USER"/./.config/darktable \
  /home/"$USER"/./.config/dconf \
  /home/"$USER"/./.config/deadbeef/config \
  /home/"$USER"/./.config/devilspie2 \
  /home/"$USER"/./.config/dunst \
  /home/"$USER"/./.config/flake8 \
  /home/"$USER"/./.config/fontconfig \
  /home/"$USER"/./.config/gtkrc-2.0 \
  /home/"$USER"/./.config/gtk-3.0 \
  /home/"$USER"/./.config/htop \
  /home/"$USER"/./.config/i3 \
  /home/"$USER"/./.config/mimeapps.list \
  /home/"$USER"/./.config/mpv \
  /home/"$USER"/./.config/nautilus \
  /home/"$USER"/./.config/openbox \
  /home/"$USER"/./.config/systemd \
  /home/"$USER"/./.config/pcmanfm \
  /home/"$USER"/./.config/pep8 \
  /home/"$USER"/./.config/pip \
  /home/"$USER"/./.config/pycodestyle \
  /home/"$USER"/./.config/pythonrc \
  /home/"$USER"/./.config/qt5ct \
  /home/"$USER"/./.config/ranger \
  /home/"$USER"/./.config/retroarch \
  /home/"$USER"/./.config/spacefm \
  /home/"$USER"/./.config/switchlayout \
  /home/"$USER"/./.config/sxiv \
  /home/"$USER"/./.config/tint2 \
  /home/"$USER"/./.config/Thunar \
  /home/"$USER"/./.config/Trolltech.conf \
  /home/"$USER"/./.config/uf \
  /home/"$USER"/./.config/viewnior \
  /home/"$USER"/./.config/vifm \
  /home/"$USER"/./.config/xfce4 \
  /home/"$USER"/./.config/yamllint \
  /home/"$USER"/./.config/zathura \
  /home/"$USER"/./.config/zdoom/*.ini \
  /home/"$USER"/./.FBReader \
  /home/"$USER"/./.local/share/applications \
  /home/"$USER"/./.local/share/completions \
  /home/"$USER"/./.local/share/crispy-doom/*.cfg \
  /home/"$USER"/./.local/share/file-manager \
  /home/"$USER"/./.local/share/functions \
  /home/"$USER"/./.local/share/icons/hicolor \
  /home/"$USER"/./.local/share/icons/Uhita \
  /home/"$USER"/./.local/share/nautilus \
  /home/"$USER"/./.local/share/terminfo \
  /home/"$USER"/./.local/share/themes \
  /home/"$USER"/./.local/share/w3m.conf \
  /home/"$USER"/./.local/share/Xresources \
  /home/"$USER"/./.prboom-plus/prboom-plus.cfg \
  /home/"$USER"/./.pulse/presets \
  /home/"$USER"/./.slade3/*.cfg \
  /home/"$USER"/./.ssh/config \
  /home/"$USER"/./.w3m/keymap \
  /home/"$USER"/./bin/*.sh \
  /home/"$USER"/./bin/functions \
  ./linux/


