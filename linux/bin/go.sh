#!/bin/bash

if [ "$(id -u)" -eq 0 ]; then
  USER=$(logname)
  if ! [ -d "/home/$USER" ]; then
    echo "[FAIL] No home directory for \$USER=$USER."
    exit 1
  fi
fi

source "/home/$USER/bin/bin-colors.sh"

function match() {
  echo "$1" | grep -i -E "$2"
}

function install {
  echo -e "${fg_magenta}${bold}[go.sh] Install ${reset}"

  # Repos
  dnf -y install \
    http://download1.rpmfusion.org/free/fedora/rpmfusion-free-release-$(rpm -E %fedora).noarch.rpm \
    http://download1.rpmfusion.org/nonfree/fedora/rpmfusion-nonfree-release-$(rpm -E %fedora).noarch.rpm
    http://rpm.livna.org/livna-release.rpm
  cd /etc/yum.repos.d/
  wget http://download.virtualbox.org/virtualbox/rpm/fedora/virtualbox.repo
  dnf -y update

  rpm --import https://packages.microsoft.com/keys/microsoft.asc
  echo -e "[code]\nname=Visual Studio Code\nbaseurl=https://packages.microsoft.com/yumrepos/vscode\nenabled=1\ngpgcheck=1\ngpgkey=https://packages.microsoft.com/keys/microsoft.asc" > /etc/yum.repos.d/vscode.repo

  flatpak remote-add --if-not-exists flathub https://flathub.org/repo/flathub.flatpakrepo
  flatpak install flathub net.mancubus.SLADE -y
  flatpak install flathub org.audacityteam.Audacity -y

  # Unbloat
  dnf -y remove empathy gnome-documents gnome-software gnome-weather \
  bijiben shotwell rhythmbox empathy geoclue cups

  # Essentials
  dnf -y install \
  chromium chromium-libs-media-freeworld w3m w3m-img \
  rxvt rxvt-unicode tmux zsh util-linux-user \
  bzr cvs svn hg git git-credential-libsecret \
  vim vim-X11 perf most curl cabextract parallel \
  bvi hexedit \
  acpid pv smartmontools sg3_utils sysstat \
  strace pidstat iotop htop nmon inxi lshw nmap wireshark-gnome \
  network-manager-applet NetworkManager-tui \
  atool bsdtar libplist unace unrar p7zip-plugins \
  agrep aria2 bchunk ftp ncdu rlwrap rsync socat \
  fuse-sshfs fuse-exfat exfat-utils ntfsprogs \
  feh gmic gmic-gimp gimp gimp-libs\* ImageMagick shutter \
  libreoffice dictd jq bc sox \
  dconf-editor gnome-tweak-tool setools-console policycoreutils-devel \
  gdm gnome-shell gnome-terminal-nautilus file-roller pcmanfm spacefm ranger \
  gnome-shell-extension-window-list \
  gnome-epub-thumbnailer gnome-kra-ora-thumbnailer viewnior \
  zathura-djvu zathura-pdf-mupdf evince-nautilus evince-djvu \
  adwaita-qt adwaita-qt4 adwaita-qt5 qt5ct \
  redhat-rpm-config rpm-build \
  VirtualBox-5.1 kernel-devel elfutils-libelf-devel dkms \
  nautilus-dropbox pygpgme \
  thunderbird hexchat pidgin telegram-desktop \
  purple-discord purple-telegram purple-skypeweb \
  task keepassx \
  devilspie2 dmenu wmctrl Xephyr xdotool xsel xclip xbindkeys zenity \
  inotify-tools \
  ifuse libimobiledevice libimobiledevice-utils \
  binwalk perl-Image-ExifTool \
  graphviz

  # Laptop
  # dnf -y install \
  # guvcview powertop

  # Xfce
  # dnf -y install \
  # lightdm \
  # xfwm4 xfce4-session xfce4-settings xfce4-power-manager xfce4-battery-plugin xfce4-genmon-plugin xfce4-whiskermenu-plugin

  # Tex
  dnf -y install \
    texworks \
    texlive-acronym \
    texlive-adjustbox \
    texlive-algorithm2e \
    texlive\*appen\* \
    texlive-appendix \
    texlive-babel-portuges \
    texlive-biblatex\* \
    texlive-biblatex-ieee \
    texlive-cellspace \
    texlive-cite \
    texlive-csquotes \
    texlive-ctable \
    texlive-dingbat \
    texlive-ec \
    texlive-epsf\* \
    texlive-epstopdf\* \
    texlive-euenc \
    texlive-europass\* \
    texlive-glossaries \
    texlive-hyphen-english \
    texlive-hyphen-portuguese \
    texlive-IEEEtran \
    texlive-lipsum \
    texlive-mathspec \
    texlive-mathtools \
    texlive-microtype \
    texlive-minitoc \
    texlive-multirow \
    texlive-parskip \
    texlive-pdfpages \
    texlive-pgfplots \
    texlive-subfigure \
    texlive-tabulary \
    texlive-textcase \
    texlive-textpos \
    texlive-ulem \
    texlive-xargs
  dnf -y install \
    texlive \
    texlive-collection-fontsextra \
    texlive-collection-fontsrecommended \
    texlive-collection-latex \
    texlive-collection-latexextra \
    texlive-collection-latexrecommended \
    texlive-collection-mathscience \
    texlive-collection-plaingeneric \
    texlive-latex-fonts \
    texlive-latex-fonts-doc \
    texlive-ucharclasses \
    texlive-xetex

  # Cosmetics
  dnf -y install \
  google-croscore-cousine-fonts google-croscore-arimo-fonts fontconfig \
  mscore-fonts gdouros-symbola-fonts ibus-qt \
  terminus-fonts\* \
  freetype-freeworld gtk-murrine-engine

  # Dev
  dnf -y install \
  bison flex \
  golang java lua rust php \
  gcc gcc-c++ gdb ant waf cpan cpanminus valgrind npm \
  glibc.i686 libgcc.i686 libstdc++.i686 glibc-devel.i686 \
  clang-analyzer clang-tools-extra \
  astyle cloc ctags ShellCheck python3-pylint csslint tidy \
  cargo gem python-pip python\*-tkinter \
  automake autoconf cmake libtool intltool gettext-devel tcl-devel \
  entr

  curl -s "https://get.sdkman.io" | bash
  bash -c 'sdk install gradle 5.6.3'

  # cgroups
  systemctl restart cgconfig
  chown -R "$USER" /sys/fs/cgroup/memory/browsers/ /sys/fs/cgroup/blkio/browsers/ /sys/fs/cgroup/cpu,cpuacct/browsers/

  # Preferences
  chsh -s /usr/bin/zsh "$USER"
  /home/"$USER"/opt/oh-my-zsh/tools/install.sh

  systemctl enable mlocate-updatedb.timer
  plymouth-set-default-theme details -R
  usermod -a -G wheel "$USER"
  usermod -a -G vboxusers "$USER"
}

function install-configs {
  echo -e "${fg_magenta}${bold}[go.sh] Install Configs ${reset}"

  dconf load /org/gnome/desktop/wm/keybindings/ < \
    /home/"$USER"/Dropbox/deploy/+/dconf-wm-keybindings.txt
  dconf load /org/gnome/settings-daemon/plugins/media-keys/ < \
    /home/"$USER"/Dropbox/deploy/+/dconf-custom-keybinds.txt

  rsync -uva --usermap=:"$USER" --groupmap=:"$USER" \
    /home/"$USER"/Dropbox/deploy/home/ /home/
  rsync -uva --usermap=:root --groupmap=:root \
    /home/"$USER"/Dropbox/deploy/system/opt/ /opt/

  rsync -uva --usermap=:root --groupmap=:root \
    /home/"$USER"/Dropbox/deploy/system/etc/ /etc/
  rsync -uva --usermap=:root --groupmap=:root \
    /home/"$USER"/Dropbox/deploy/system/usr/ /usr/

  # adjust rsync permisssions
  chown -R "$USER":"$USER" /usr/share/themes/Uhita/

  systemctl --user daemon-reload
  systemctl --user enable continuous-silence dropbox mouse rm-systemd-env


  mkdir -p /home/"$USER"/.local/share/systemd
  chown -R "$USER":"$USER" /home/"$USER"/.local/share/systemd

  if [ -f /home/"$USER"/.lesskey ] && command -v lesskey &>/dev/null; then
    lesskey
  fi
}

function install-tweaks {
  echo -e "${fg_magenta}${bold}[go.sh] Install Tweaks ${reset}"

  systemctl --user start continuous-silence dropbox mouse

  # Custom keyboard layout
  # cp /home/"$USER"/Dropbox/deploy/+/evdev.xml /usr/share/X11/xkb/rules/evdev.xml
  sudo ln -fs /home/"$USER"/.xkb/symbols/altmagic_symbols /usr/share/X11/xkb/symbols/altmagic
  grep -q '<name>altmagic</name>' /usr/share/X11/xkb/rules/evdev.xml || { \
    tmp_file=$(mktemp) && \
    section='
    <layoutList>
      <layout>
        <configItem>
          <name>altmagic</name>

          <shortDescription>en</shortDescription>
          <description>English (Alt Graph Magic)</description>
          <languageList>
            <iso639Id>eng</iso639Id>
          </languageList>
        </configItem>
        <variantList>
        </variantList>
      </layout>
    ' && \
    awk -v section="$section" '
    /<layoutList>/ {
        print section
        next
    }
    { print }
    ' /usr/share/X11/xkb/rules/evdev.xml > "$tmp_file" && \
    sudo mv "$tmp_file" /usr/share/X11/xkb/rules/evdev.xml
    sudo rm /var/lib/xkb/*.xkm
  }
  setxkbmap altmagic

  # Custom termcap
  tic /home/"$USER"/.local/share/terminfo/r/*
  tic /home/"$USER"/.local/share/terminfo/t/*

  # Workaround GTK3 csd
  session=$(wmctrl -m | awk 'NR == 1 { print $2 }')
  if [[ $(match "$session" "GNOME") ]]; then
    mv "/home/$USER/.config/gtk-3.0/gtk.css" \
       "/home/$USER/.config/gtk-3.0/gtk.css.disabled"
  else
    mv "/home/$USER/.config/gtk-3.0/gtk.css.disabled" \
       "/home/$USER/.config/gtk-3.0/gtk.css"
  fi

  gtksubversion=$(rpm -q 'gtk3' | gawk '
    match($0, /[0-9]*\.([0-9]*)/, e) {
      print e[1]
      exit
    }
  ')
  if [ -z "$gtksubversion" ]; then
    gtksubversion=9999
  fi
  if [ "$gtksubversion" -le 14 ]; then
    cp -alf /usr/share/themes/Uhita/gtk-3.0/3.14/* \
       /usr/share/themes/Uhita/gtk-3.0/.
  elif [ "$gtksubversion" -le 18 ]; then
    cp -alf /usr/share/themes/Uhita/gtk-3.0/3.18/* \
       /usr/share/themes/Uhita/gtk-3.0/.
  elif [ "$gtksubversion" -le 20 ]; then
    cp -alf /usr/share/themes/Uhita/gtk-3.0/3.20/* \
       /usr/share/themes/Uhita/gtk-3.0/.
  else
    cp -alf /usr/share/themes/Uhita/gtk-3.0/3.24/* \
       /usr/share/themes/Uhita/gtk-3.0/.
  fi

  ln -fs /home/"$USER"/opt/bfs/bfs /home/"$USER"/bin/bfs
  ln -fs /usr/bin/gnome-terminal /home/"$USER"/bin/user-terminal

  xdg-mime default pcmanfm.desktop inode/directory

  # Patches
  sed -i 's/\(pygments.formatters\).Terminal[0-9]*Formatter/\1.TerminalFormatter/g' \
    /home/"$USER"/.gdbinit-dashboard

  if [[ -d /home/"$USER"/opt/firefox ]]; then
    ln -fs /home/"$USER"/opt/firefox/firefox /home/"$USER"/bin/user-browser
  else
    ln -fs /usr/bin/firefox /home/"$USER"/bin/user-browser
  fi
  gsettings set org.gnome.Terminal.Legacy.Settings headerbar false
  xdg-settings set default-web-browser "Firefox.desktop"
  sed -i -e 's/google-chrome/firefox/g' \
    /home/"$USER"/.config/mimeapps.list

  # Host specific changes
  hostname=$(hostname)
  if [[ $(match "$hostname" "mnutop") ]]; then
    #if [[ -f /usr/bin/google-chrome-stable ]]; then
    #  ln -fs /usr/bin/google-chrome-stable /home/"$USER"/bin/user-browser
    #else
    #  ln -fs /usr/bin/firefox /home/"$USER"/bin/user-browser
    #fi
    #xdg-settings set default-web-browser "google-chrome.desktop"
    gsettings set \
      org.gnome.desktop.interface font-name 'Sans 12'
    gsettings set \
      org.gnome.desktop.interface document-font-name 'Sans 12'
    gsettings set \
      org.gnome.desktop.interface monospace-font-name 'Monospace 12'
    #sed -i -e 's/firefox/google-chrome/g' \
    #  /home/"$USER"/.config/mimeapps.list
    sed -i -e 's/set guifont=Monospace\\ 14/set guifont=Monospace\\ 12/g' \
      /home/"$USER"/.vim/after/plugin/vimrc*
    sed -i -e 's/set font "Monospace 14"/set font "Monospace 12"/g' \
      /home/"$USER"/.config/zathura/zathurarc
    sed -i \
      -e 's/UXTerm\*faceSize: 14/UXTerm\*faceSize: 12/g' \
      -e 's/URxvt\*letterSpace: -1/URxvt\*letterSpace: 0/g' \
      -e 's/pixelsize=14/pixelsize=12/g' \
      -e 's/xft:Monospace-14/xft:Monospace-12/g' \
      -e 's/rofi\.font: mono 16/rofi\.font: mono 14/g' \
      /home/"$USER"/.Xresources
  else
    gsettings set \
      org.gnome.desktop.interface font-name 'Sans 12'
    gsettings set \
      org.gnome.desktop.interface document-font-name 'Sans 12'
    gsettings set \
      org.gnome.desktop.interface monospace-font-name 'Monospace 14'
    sed -i -e 's/set guifont=Monospace\\ 12/set guifont=Monospace\\ 14/g' \
      /home/"$USER"/.vim/after/plugin/vimrc*
    sed -i -e 's/set font "Monospace 12"/set font "Monospace 14"/g' \
      /home/"$USER"/.config/zathura/zathurarc
    sed -i \
      -e 's/UXTerm\*faceSize: 12/UXTerm\*faceSize: 14/g' \
      -e 's/URxvt\*letterSpace: 0/URxvt\*letterSpace: -1/g' \
      -e 's/pixelsize=12/pixelsize=14/g' \
      -e 's/xft:Monospace-12/xft:Monospace-14/g' \
      -e 's/rofi\.font: mono 14/rofi\.font: mono 16/g' \
      /home/"$USER"/.Xresources
  fi

  if [[ $(match "$hostname" "ctf") ]]; then
    xrandr --output VGA-1 --mode 1366x768
  fi

  tmux source-file ~/.tmux.conf
  xrdb -merge /home/"$USER"/.Xresources
  (sleep 10 && xset r rate 300 25) &disown
  #if [[ $(match "$hostname" "mnu$") ]]; then
      #if [[ $(id -u) -ne 0 ]]; then
        #pulseaudio-equalizer enable
      #fi
  #fi

  # Restart GNOME Shell
  if [[ $(match "$session" "GNOME") ]]; then
    dconf write /org/gnome/shell/extensions/switcher/onboarding-1 "uint32 1"
    dconf write /org/gnome/shell/extensions/switcher/onboarding-2 "uint32 1"
    dconf write /org/gnome/shell/extensions/switcher/onboarding-3 "uint32 1"
    dconf write /org/gnome/shell/extensions/switcher/onboarding-4 "uint32 1"
    dconf write /org/gnome/shell/extensions/switcher/onboarding-5 "uint32 1"
    dbus-send --type=method_call --print-reply --dest=org.gnome.Shell /org/gnome/Shell org.gnome.Shell.Eval string:'global.reexec_self()'
  elif [[ $(match "$session" "Xfwm") ]]; then
    xfsettingsd --replace
  fi

  for i in EHC1 EHC2 EHC3 USB1 USB2 USB3 XHC; do
      grep -q "$i.*enabled" /proc/acpi/wakeup && \
        echo "$i" > /proc/acpi/wakeup
  done
}

function install-user {
  mkdir -p "$GOPATH/src"

  cpan Archive::Zip
  gem install --user-install \
    jekyll bundler \
    pry-byebug rubocop
  npm install -g npm
  npm install -g \
    typescript typescript-language-server \
    eslint @typescript-eslint/parser @typescript-eslint/eslint-plugin \
    tern jshint js-beautify prettier \
    markdown-pdf markdown-toc remark remark-cli \
    d3-pre phantomjs-prebuilt http-server \
    css-semdiff

  pip install --user --upgrade pip
  pip install --user \
    pipenv setuptools waf wheel \
    dbus-python readline requests unidecode pyzmq \
    autopep8 ipdb jedi pylint sqlparse \
    yamllint vim-vint pathlib typing \
    jupyter \
    matplotlib networkx \
    opencv-python cython \
    pyexiv2 pyPDF PDFMiner pdfrw \
    mutagen pygments \
    Distorm3 PyCrypto
  pip install --user \
    scons \
    tesserocr
}

function update-repos {
  while read -r i; do
    target=$(echo "$i" | cut -d':' -f1)
    url=$(echo "$i" | sed 's/[ \t\/]*$//g')
    repo=$(echo "$url" | cut -d':' -f2-)
    name=$(echo "${url##*/}" | sed 's/\.git$//g')
    cd "$target"
    git clone --depth=1 "$repo" "$name"
    cd "$name" && git pull && git fetch --tags
  done < "$1"
}

function install-repos {
  echo -e "${fg_magenta}${bold}[go.sh] Install Repos ${reset}"

  repo_list_dir=/home/"$USER"/Dropbox/deploy
  if [ -n "$1" ]; then
    repo_list_dir=$1
  fi

  # Access user repositories with ssh key
  if ! ssh-add -L | grep -q -i -E "(id_rsa|ssh-rsa)"; then
    ssh-add /home/"$USER"/.ssh/id_rsa
  fi

  hostname=$(hostname)

  # GNOME extensions
  if ! [[ $(match "$hostname" "ctf$") ]]; then
    mkdir -p /home/"$USER"/.local/share/gnome-shell/extensions

    cd /home/"$USER"/.local/share/gnome-shell/extensions
    git clone https://github.com/nevesnunes/TopIcons-plus \
        "TopIcons@phocean.net"
    cd "TopIcons@phocean.net"
    git remote add huttli "https://github.com/huttli/TopIcons-plus"
    git remote add upstream "https://github.com/phocean/TopIcons-plus"
    git pull upstream master

    cd /home/"$USER"/.local/share/gnome-shell/extensions
    git clone https://github.com/home-sweet-gnome/dash-to-panel.git "dash-to-panel@jderose9.github.com"
    cd "dash-to-panel@jderose9.github.com"
    git pull

    cd /home/"$USER"/.local/share/gnome-shell/extensions
    git clone https://github.com/nevesnunes/switcher \
        "switcher@landau.fi"
    cd "switcher@landau.fi"
    git remote add upstream "https://github.com/daniellandau/switcher"
    git pull upstream master

    cd /home/"$USER"/.local/share/gnome-shell/extensions
    git clone https://github.com/HROMANO/nohotcorner/ \
        "nohotcorner@azuri.free.fr"
    cd "nohotcorner@azuri.free.fr"
    git pull
  fi

  if ! [[ $(match "$hostname" "mnu$") ]]; then
    update-repos "$repo_list_dir"/repos-mnutop.txt
  fi
  update-repos "$repo_list_dir"/repos.txt
}

function install-desktop {
  echo -e "${fg_magenta}${bold}[go.sh] Install Desktop ${reset}"

  dconf load / < /home/"$USER"/Dropbox/deploy/+/dconf.txt
  dconf write /org/gnome/settings-daemon/plugins/xsettings/overrides "{'Gtk/ShellShowsAppMenu': <1>, 'Gtk/MenuImages': <1>}"
  dconf write /org/gnome/software/download-updates false
  dconf write /org/gnome/terminal/legacy/profiles:/:b1dcc9dd-5262-4d8d-a863-c897e6d979b9/palette "['#dddddd', '#d22d48', '#37730d', '#622e04', '#4e6cd0', '#8854ab', '#285055', '#222222', '#808080', '#d22d48', '#37730d', '#622e04', '#4e6cd0', '#8854ab', '#285055', '#000000']"
  dconf write /org/gnome/desktop/wm/preferences/audible-bell "false"

  rsync -va --usermap=:"root" --groupmap=:"root" /home/"$USER"/Dropbox/deploy/system/ /

  # GNOME Extensions
  chown "$USER":"$USER" \
    /usr/share/gnome-shell/extensions/window-list@gnome-shell-extensions.gcampax.github.com/stylesheet.css
  rsync -va --usermap=:"$USER" --groupmap=:"$USER" \
    /home/"$USER"/Dropbox/deploy/custom/window-list-stylesheet.css \
    /usr/share/gnome-shell/extensions/window-list@gnome-shell-extensions.gcampax.github.com/stylesheet.css

  # Allow separate X servers to be run with sound
  usermod -a -G audio "$USER"

  # sysrq
  sysctl -w kernel.sysrq=1

  # ssh
  echo "PermitRootLogin no" >> /etc/ssh/sshd_config

  # systemd
  #
  # Dependencies:
  # avahi-daemon.service > wine
  # bluetooth.service > pulseaudio
  systemctl disable \
    avahi-daemon.socket avahi-daemon.service \
    colord.service \
    cups.service \
    gssproxy.service

  systemctl mask \
    abrt-ccpp.service abrt-oops.service abrt-vmcore.service \
    abrt-journal-core.service abrt-pstoreoops.service \
    abrt-xorg.service abrtd.service \
    auditd.service \
    dmraid-activation.service \
    geoclue.service \
    iio-sensor-proxy.service \
    livesys.service livesys-late.service \
    packagekit.service packagekit-offline-update.service \
    plymouth-read-write.service plymouth-start.service \
    plymouth-quit-wait.service \
    systemd-firstboot.service \
    systemd-journald-audit.socket

  systemctl reset-failed

  # systemctl enable dnf-automatic.timer
  # systemctl start dnf-automatic.timer

  # shutter
  sudo chattr -i /usr/share/shutter/resources/system/plugins && \
    sudo rm -rf /usr/share/shutter/resources/system/plugins/*
    sudo chattr +i /usr/share/shutter/resources/system/plugins
  sudo chattr -i /usr/share/shutter/resources/system/upload_plugins && \
    sudo rm -rf /usr/share/shutter/resources/system/upload_plugins/*
    sudo chattr +i /usr/share/shutter/resources/system/upload_plugins

  # pcmanfm
  sudo chattr -i /usr/share/libfm/images/unknown.png && \
    sudo cp /usr/share/icons/Adwaita/512x512/mimetypes/text-x-generic.png /usr/share/libfm/images/unknown.png && \
    sudo chattr +i /usr/share/libfm/images/unknown.png
  sudo chattr -i /usr/share/libfm/images/folder.png && \
    sudo cp /usr/share/icons/Adwaita/512x512/places/folder.png /usr/share/libfm/images/folder.png && \
    sudo chattr +i /usr/share/libfm/images/folder.png

  # filesystem hierarchy
  ln -s /home/"$USER"/.local /home/"$USER"/local
  ln -s /home/"$USER"/.cache/thumbnails /home/"$USER"/.thumbnails
  ln -s ~/.jshintrc.default ~/.jshintrc
  mkdir -p \
    /home/"$USER"/media/cdrom \
    /home/"$USER"/media/disk \
    /home/"$USER"/media/iphone \
    /home/"$USER"/tmp \
    /home/"$USER"/opt
  rsync -uva --usermap=:"$USER" --groupmap=:"$USER" /home/"$USER"/Dropbox/deploy/home/*/opt/ \
    /home/"$USER"/opt/

  # Populate z
  touch /home/"$USER"/.z
  find /home/"$USER" -maxdepth 3 -type d | \
    grep -E -v '/(\.)|_[a-zA-Z0-9]' | \
    grep -E -v '/opt/' | \
    sort | uniq | xargs -d'\n' -I{} -n1 -r echo "{}|1|1" \
    > /home/"$USER"/.z

  cp /home/"$USER"/.local/share/applications/autoruns.desktop \
    /home/"$USER"/.local/share/applications/runapps.desktop \
    /home/"$USER"/.config/autostart/.

  sudo ln -s /usr/bin/plistutil /usr/bin/plutil

  # Multimedia
  dnf -y install \
  brasero calligra-krita darktable kdenlive inkscape \
  audacity-freeworld audacious audacious-plugins-freeworld-mp3 cuetools shntool \
  okular fbreader-gtk ffmpegthumbnailer \
  wine wine-wow wine-mono chocolate-doom prboom-plus dosbox mame vice scummvm \
  milkytracker nfoview fontforge tesseract \
  mono-core gtk-sharp2 gtk-murrine-engine \
  mpv libvdpau-va-gl youtube-dl pulseaudio-equalizer libdvdcss \
  qphotorec \
  xsane

  # Devels
  dnf -y install \
  dbus-glib-devel \
  libmodplug SDL-devel SDL2-devel SDL_mixer\* SDL_net\* SDL2_mixer \
  ncurses-devel ncurses-compat-libs \
  leptonica-devel tesseract-devel \
  python2-devel python3-devel ruby-devel \
  python2-tkinter python3-tkinter \
  gtk3-devel file-devel \
  ffmpeg-devel wxGTK-devel wxGTK3-devel \
  qt5-qtgraphicaleffects qt5-qtquickcontrols \
  xorg-x11-util-macros xorg-x11-server-devel \
  libwnck-devel libwnck3-devel \
  libxcb-devel xcb-util\*devel libxkbcommon-x11-devel \
  kernel-devel mesa-libEGL-devel libv4l-devel libxkbcommon-devel mesa-libgbm-devel Cg libCg zlib-devel freetype-devel libxml2-devel ffmpeg-devel SDL2-devel SDL-devel perl-X11-Protocol perl-Net-DBus pulseaudio-libs-devel openal-soft-devel libusb-devel

  #### Audacity, Deadbeef
  dnf -y install \
  alsa-lib-devel desktop-file-utils expat-devel flac-devel gettext jack-audio-connection-kit-devel ladspa-devel libid3tag-devel taglib-devel libogg-devel libsndfile-devel libvorbis-devel portaudio-devel soundtouch-devel soxr-devel vamp-plugin-sdk-devel zip zlib-devel wxGTK3-devel libmad-devel twolame-devel ffmpeg-devel lame-devel libsamplerate-devel lv2-devel libcurl-devel jansson-devel imlib2-devel pulseaudio-libs-devel faad2-devel

  #### compton
  dnf -y install \
  libconfig-devel libev-devel libxdg-basedir-devel

  #### rofi
  dnf -y install \
  startup-notification-devel librsvg2-devel check-devel

  #### slade3
  dnf -y install \
  freeimage-devel SFML-devel glew-devel ftgl-devel compat-wxGTK3-gtk2\*

  #### zdoom
  dnf -y install gcc-c++ make cmake SDL2-devel git zlib-devel bzip2-devel \
  libjpeg-turbo-devel fluidsynth-devel game-music-emu-devel openal-soft-devel \
  libmpg123-devel libsndfile-devel wildmidi-devel gtk3-devel timidity++ nasm tar \
  chrpath

  #### zeal
  dnf install -y \
  make cmake extra-cmake-modules gcc-c++ \
  desktop-file-utils libarchive-devel \
  qt5-qtbase qt5-qtbase-devel qt5-qtwebkit-devel qt5-qtx11extras-devel \
  sqlite-devel xcb-util-keysyms-devel \
  hicolor-icon-theme

  # Codecs
  dnf -y install \
  gstreamer1-libav gstreamer1-plugins-bad-free-extras gstreamer1-plugins-bad-freeworld gstreamer1-plugins-base-tools gstreamer1-plugins-good-extras gstreamer1-plugins-ugly gstreamer1-plugins-bad-free gstreamer1-plugins-good gstreamer1-plugins-base gstreamer1 gstreamer1-plugins-bad-free-fluidsynth

  # VirtualBox
  VBoxManage setextradata global GUI/SuppressMessages "all"

  # vmware
  ln -s /usr/include/linux/version.h /lib/modules/$(uname -r)/build/include/linux/version.h
  vmware-modconfig --console --install-all

  # Hierarchy
  mkdir -p /home/"$USER"/bookmarks
  cd /home/"$USER"/bookmarks
  ln -fs /home/"$USER"/code/cheats .
  ln -fs /home/"$USER"/code/logbooks .
  ln -fs /home/"$USER"/code/snippets .
  ln -fs /home/"$USER"/code/web/styles .
  ln -fs /home/"$USER"/code/wip .
  ln -fs /home/"$USER"/Dropbox/doc/goals .
}

function install-skype {
  echo -e "${fg_magenta}${bold}[go.sh] Install Skype ${reset}"

  dnf -y install \
  alsa-lib.i686 fontconfig.i686 freetype.i686 \
  glib2.i686 libSM.i686 libXScrnSaver.i686 libXi.i686 \
  libXrandr.i686 libXrender.i686 libXv.i686 libstdc++.i686 \
  pulseaudio-libs.i686 qt.i686 qt-x11.i686 zlib.i686 qtwebkit.i686

  mkdir -p /home/"$USER"/opt/skype
  unzip -d /home/"$USER"/opt /home/"$USER"/Dropbox/deploy/+/skype.zip
  ln -fs /home/"$USER"/opt/skype/skype.desktop /usr/share/applications/skype.desktop
  touch /usr/bin/skype
  chmod 755 /usr/bin/skype
  chown -R root:root /home/"$USER"/opt/skype

cat > /usr/bin/skype << EOF
#!/bin/sh
export SKYPE_HOME="/home/$USER/opt/skype"
\$SKYPE_HOME/skype --resources=\$SKYPE_HOME \$*
EOF
}

function backup {
  echo -e "${fg_magenta}${bold}[go.sh] Backup ${reset}"

  # Purge files we removed on another remote
  while read -r i; do
    target=/home/"$USER"/Dropbox/deploy/"$i"
    if [ -d "$target" ]; then
      echo 'y' | rm -r "$i" 2> /dev/null
      echo 'y' | rm -r "$target" 2> /dev/null
    else
      rm "$i" 2> /dev/null
      rm "$target" 2> /dev/null
    fi
  done < /home/"$USER"/Dropbox/deploy/purged.txt

  dconf dump / > /home/"$USER"/Dropbox/deploy/+/dconf.txt
  dconf dump /org/gnome/desktop/wm/keybindings/ > /home/"$USER"/Dropbox/deploy/+/dconf-wm-keybindings.txt
  dconf dump /org/gnome/settings-daemon/plugins/media-keys/ > /home/"$USER"/Dropbox/deploy/+/dconf-custom-keybinds.txt

  rsync -uva --relative --usermap=:"$USER" --groupmap=:"$USER" \
    --filter="dir-merge,- .gitignore" \
    --no-links \
    /home/"$USER"/bin \
    /home/"$USER"/opt/z.sh \
    /home/"$USER"/Dropbox/deploy/

  rsync -uva --relative --usermap=:"$USER" --groupmap=:"$USER" \
    --exclude=".git" \
    --filter="dir-merge,- .gitignore" \
    /home/"$USER"/code/cheats \
    /home/"$USER"/code/my \
    /home/"$USER"/code/snippets \
    /home/"$USER"/Dropbox/deploy/

  rsync -uva --relative --usermap=:"$USER" --groupmap=:"$USER" \
    --exclude="/home/$USER/.local/share/applications/wine*" \
    --exclude="/home/$USER/.oh-my-zsh/.git" \
    --exclude="/home/$USER/.vim/bundle*" \
    --exclude="/home/$USER/.tmux/resurrect" \
    --filter="dir-merge,- .gitignore" \
    /home/"$USER"/code/web/styles \
    /home/"$USER"/code/config/*.vimrc \
    /home/"$USER"/code/config/Caddyfile \
    /home/"$USER"/code/config/kernel \
    /home/"$USER"/code/config/pulse \
    /home/"$USER"/code/config/selinux \
    /home/"$USER"/code/config/tor \
    /home/"$USER"/.bashrc* \
    /home/"$USER"/.bash_profile \
    /home/"$USER"/.bash_prompt \
    /home/"$USER"/.clang-format \
    /home/"$USER"/.ctags \
    /home/"$USER"/.dircolors \
    /home/"$USER"/.dosbox* \
    /home/"$USER"/.eslintrc \
    /home/"$USER"/.fluxbox \
    /home/"$USER"/.gdbinit* \
    /home/"$USER"/.gemrc \
    /home/"$USER"/.gimp-2.8 \
    /home/"$USER"/.gitconfig \
    /home/"$USER"/.gitignore_global \
    /home/"$USER"/.gtkrc-2.0 \
    /home/"$USER"/.lesskey \
    /home/"$USER"/.less_termcap \
    /home/"$USER"/.icewm \
    /home/"$USER"/.infokey \
    /home/"$USER"/.inputrc \
    /home/"$USER"/.jshintrc \
    /home/"$USER"/.milkytracker_config \
    /home/"$USER"/.mostrc \
    /home/"$USER"/.npmrc \
    /home/"$USER"/.oh-my-zsh \
    /home/"$USER"/.pdbrc \
    /home/"$USER"/.pentadactylrc \
    /home/"$USER"/.profile \
    /home/"$USER"/.pryrc \
    /home/"$USER"/.pwn.conf \
    /home/"$USER"/.pylintrc \
    /home/"$USER"/.rlwrap \
    /home/"$USER"/.rubocop.yml \
    /home/"$USER"/.screenlayout \
    /home/"$USER"/.shrc \
    /home/"$USER"/.stalonetrayrc \
    /home/"$USER"/.tmux* \
    /home/"$USER"/.taskrc \
    /home/"$USER"/.tern-config \
    /home/"$USER"/.urxvt \
    /home/"$USER"/.vim \
    /home/"$USER"/.vimrc \
    /home/"$USER"/.vimperator/colors \
    /home/"$USER"/.vimperatorrc \
    /home/"$USER"/.xbindkeysrc \
    /home/"$USER"/.xkb \
    /home/"$USER"/.Xresources* \
    /home/"$USER"/.zshrc \
    /home/"$USER"/.chocolate-doom/*.cfg \
    /home/"$USER"/.config/awesome \
    /home/"$USER"/.config/beets \
    /home/"$USER"/.config/compton.conf \
    /home/"$USER"/.config/darktable \
    /home/"$USER"/.config/dconf \
    /home/"$USER"/.config/deadbeef/config \
    /home/"$USER"/.config/devilspie2 \
    /home/"$USER"/.config/dunst \
    /home/"$USER"/.config/flake8 \
    /home/"$USER"/.config/fontconfig \
    /home/"$USER"/.config/gtkrc-2.0 \
    /home/"$USER"/.config/gtk-3.0 \
    /home/"$USER"/.config/htop \
    /home/"$USER"/.config/i3 \
    /home/"$USER"/.config/mimeapps.list \
    /home/"$USER"/.config/mpv \
    /home/"$USER"/.config/nautilus \
    /home/"$USER"/.config/openbox \
    /home/"$USER"/.config/systemd \
    /home/"$USER"/.config/pcmanfm \
    /home/"$USER"/.config/pep8 \
    /home/"$USER"/.config/pip \
    /home/"$USER"/.config/pycodestyle \
    /home/"$USER"/.config/pythonrc \
    /home/"$USER"/.config/qt5ct \
    /home/"$USER"/.config/ranger \
    /home/"$USER"/.config/retroarch \
    /home/"$USER"/.config/spacefm \
    /home/"$USER"/.config/switchlayout \
    /home/"$USER"/.config/sxiv \
    /home/"$USER"/.config/tint2 \
    /home/"$USER"/.config/Thunar \
    /home/"$USER"/.config/Trolltech.conf \
    /home/"$USER"/.config/uf \
    /home/"$USER"/.config/viewnior \
    /home/"$USER"/.config/vifm \
    /home/"$USER"/.config/xfce4 \
    /home/"$USER"/.config/yamllint \
    /home/"$USER"/.config/zathura \
    /home/"$USER"/.config/zdoom/*.ini \
    /home/"$USER"/.FBReader \
    /home/"$USER"/.local/share/applications \
    /home/"$USER"/.local/share/completions \
    /home/"$USER"/.local/share/crispy-doom/*.cfg \
    /home/"$USER"/.local/share/file-manager \
    /home/"$USER"/.local/share/functions \
    /home/"$USER"/.local/share/icons/hicolor \
    /home/"$USER"/.local/share/icons/Uhita \
    /home/"$USER"/.local/share/nautilus \
    /home/"$USER"/.local/share/terminfo \
    /home/"$USER"/.local/share/themes \
    /home/"$USER"/.local/share/w3m.conf \
    /home/"$USER"/.local/share/Xresources \
    /home/"$USER"/.prboom-plus/prboom-plus.cfg \
    /home/"$USER"/.pulse/presets \
    /home/"$USER"/.slade3/*.cfg \
    /home/"$USER"/.ssh/config \
    /home/"$USER"/.w3m/keymap \
    /home/"$USER"/Dropbox/deploy/

  rsync -uva --relative --usermap=:"$USER" --groupmap=:"$USER" \
    /usr/share/themes/Uhita/ \
    /opt/cleanup.sh \
    /opt/keyboard.sh \
    /opt/monitor.sh \
    /opt/mouse.sh \
    /opt/notify-battery.sh \
    /opt/notify-tasks.sh \
    /opt/nm.sh \
    /opt/screen-off.sh \
    /opt/tor.pac \
    /home/"$USER"/Dropbox/deploy/system/

  hostname=$(hostname)
  if [[ $(match "$hostname" "mnu$") ]]; then
    rsync -uva --relative --usermap=:"$USER" --groupmap=:"$USER" \
      /root/.vimrc \
      /etc/cgconfig.conf \
      /etc/cgrules.conf \
      /etc/default/grub \
      /etc/dnf/dnf.conf \
      /etc/etckeeper/etckeeper.conf \
      /etc/gdm/custom.conf \
      /etc/hosts \
      /etc/modprobe.d/usbcore.conf \
      /etc/modules-load.d/nf_conntrack.conf \
      /etc/NetworkManager/NetworkManager.conf \
      /etc/pm/sleep.d/ \
      /etc/pulse/daemon.conf \
      /etc/resolv.conf \
      /etc/skel/.bash_profile \
      /etc/sysctl.conf \
      /etc/sysctl.d/30-net.conf \
      /etc/sysctl.d/90-sysrq.conf \
      /etc/systemd/journald.conf \
      /etc/systemd/system.conf \
      /etc/systemd/system/cleanup.service \
      /etc/systemd/system/nm.service \
      /etc/udev/rules.d/99-monitor.rules \
      /etc/udev/rules.d/99-mouse.rules \
      /etc/updatedb.conf \
      /etc/zprofile \
      /usr/local/shim/ \
      /home/"$USER"/Dropbox/deploy/system/
  fi
}

function usage {
	cat <<- EOF
	Usage:
	  -b: backup
	  -c: install configs
	  -d: install desktop
	  -i: install base
	  -s: install skype
	  -t: install tweaks
	  -u: install user
	EOF
}

while getopts "bcdigstu" opt; do
  case "$opt" in
  b)
    backup
    ;;
  c)
    install-configs
    install-tweaks
    ;;
  d)
    install
    install-desktop
    install-repos
    install-configs
    install-tweaks
    ;;
  g)
    shift
    install-repos "$1"
    ;;
  i)
    install
    ;;
  s)
    install-skype
    ;;
  t)
    install-tweaks
    ;;
  u)
    install-user
    ;;
  *)
    usage
    ;;
  esac
done
if [ $OPTIND -eq 1 ]; then
  usage
fi
