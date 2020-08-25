#!/bin/bash

user="/home/fn"

function install { 
    echo "[go.sh] Let's get the party started..."

    # Repos
    dnf --nogpgcheck install http://download1.rpmfusion.org/free/fedora/rpmfusion-free-release-stable.noarch.rpm  http://download1.rpmfusion.org/nonfree/fedora/rpmfusion-nonfree-release-stable.noarch.rpm
    dnf -y update

    # Essentials    
    dnf -y install \
    java lua gcc gcc-c++ gdb ant cmake valgrind automake autoconf \
    clang clang-analyzer \
    vim vim-X11 tmux zsh ht htop iotop perf most bzr git curl cabextract \
    wireshark-gnome \
    atool agrep bsdtar bchunk rsync \
    libreoffice gimp texworks \
    dconf-editor gnome-tweak-tool \
    gdm gnome-shell gnome-terminal-nautilus file-roller \
    gnome-epub-thumbnailer viewnior \
    zathura-djvu zathura-pdf-mupdf evince-nautilus evince-djvu \
    VirtualBox kernel-devel dkms \
    nautilus-dropbox pygpgme \
    thunderbird hexchat \

    # Fonts
    google-croscore-cousine-fonts google-croscore-arimo-fonts fontconfig \
    mscore-fonts gdouros-symbola-fonts ibus-qt \
    freetype-freeworld

    # Preferences
    chsh -s /usr/bin/zsh fn
    plymouth-set-default-theme details -R
    chmod 000 /usr/libexec/tracker-*
    chmod 000 /etc/xdg/autostart/tracker-*
}

function install-configs {
    echo "[go.sh] New fresh configs, just for you!"

    dconf load /org/gnome/desktop/wm/keybindings/ < ${user}/Dropbox/misc/go/+/dconf-wm-keybindings.txt
    dconf load /org/gnome/settings-daemon/plugins/media-keys/ < ${user}/Dropbox/misc/go/+/dconf-custom-keybinds.txt

    mkdir ${user}/bin
    rsync -va --no-owner --no-group ${user}/Dropbox/misc/go/bin/ ${user}/bin/
    mkdir -p ${user}/.local/share/applications
    mkdir -p ${user}/.local/share/gnome-shell
    rsync -va --no-owner --no-group ${user}/Dropbox/misc/go/dot/ ${user}/
    mkdir /usr/share/themes/Uhita
    rsync -va --no-owner --no-group ${user}/Dropbox/misc/go/custom/Uhita/ /usr/share/themes/Uhita/
    rsync -va --no-owner --no-group ${user}/Dropbox/misc/go/system/etc/dnf/ /etc/dnf/
    rsync -va --no-owner --no-group ${user}/Dropbox/misc/go/system/usr/local/ /usr/local/
}

function install-skype {
    dnf -y install alsa-lib.i686 fontconfig.i686 freetype.i686 \
    glib2.i686 libSM.i686 libXScrnSaver.i686 libXi.i686 \
    libXrandr.i686 libXrender.i686 libXv.i686 libstdc++.i686 \
    pulseaudio-libs.i686 qt.i686 qt-x11.i686 zlib.i686 qtwebkit.i686

    mkdir ${user}/tmp
    wget -P ${user}/tmp --trust-server-names \
        http://www.skype.com/go/getskype-linux-dynamic

    mkdir /opt/skype
    tar xvf ${user}/tmp/skype-4.3* -C /opt/skype --strip-components=1
    ln -s /opt/skype/skype.desktop /usr/share/applications/skype.desktop
    touch /usr/bin/skype
    chmod 755 /usr/bin/skype

cat > /usr/bin/skype << EOF
#!/bin/sh
export SKYPE_HOME="/opt/skype"   
\$SKYPE_HOME/skype --resources=\$SKYPE_HOME \$*
EOF
}

function install-desktop {
    echo "[go.sh] Desktop configuration coming up..."

    # Multimedia
    dnf -y install \
    brasero calligra-krita darktable kdenlive inkscape \
    mpv audacity audacious audacious-plugins-freeworld-mp3 xsane \
    okular calibre kchmviewer \
    wine-wow wine-mono chocolate-doom dosbox mame vice \
    milkytracker nfoview fontforge tesseract \
    mono-core gtk-sharp2 gtk-murrine-engine \
    
    # Devels
    intltool ffmpeg-devel wxGTK-devel wxGTK3-devel \
    qt5-qtgraphicaleffects qt5-qtquickcontrols \

    # Codecs
    gstreamer1-libav gstreamer1-plugins-bad-free-extras gstreamer1-plugins-bad-freeworld gstreamer1-plugins-base-tools gstreamer1-plugins-good-extras gstreamer1-plugins-ugly gstreamer1-plugins-bad-free gstreamer1-plugins-good gstreamer1-plugins-base gstreamer1

    # Apps
    rsync -va --no-owner --no-group ${user}/Dropbox/misc/go/system/opt/ /opt/
}

function backup {
    echo "[go.sh] Saving the goods..."
        
    dconf dump / > ${user}/Dropbox/misc/go/+/dconf.txt 
    dconf dump /org/gnome/desktop/wm/keybindings/ > ${user}/Dropbox/misc/go/+/dconf-wm-keybindings.txt
    dconf dump /org/gnome/settings-daemon/plugins/media-keys/ > ${user}/Dropbox/misc/go/+/dconf-custom-keybinds.txt

    rsync -va --no-owner --no-group \
        ${user}/.z \
        ${user}/.i3* \
        ${user}/.vim* \
        ${user}/.tmux* \
        ${user}/.dosbox* \
        ${user}/.taskrc \
        ${user}/.ctags \
        ${user}/.bashrc \
        ${user}/.zshrc \
        ${user}/.profile \
        ${user}/.gdbinit \
        ${user}/.gitconfig \
        ${user}/.milkytracker_config \
        ${user}/.pentadactylrc \
        ${user}/.xbindkeysrc \
        ${user}/.Xresources \
        ${user}/.xkb \
        ${user}/Dropbox/misc/go/dot/

    rsync -va --no-owner --no-group \
        ${user}/.config/gtkrc-2.0 \
        ${user}/.config/vifm \
        ${user}/.config/zathura \
        ${user}/.config/retroarch \
        ${user}/Dropbox/misc/go/dot/.config/

    rsync -va --no-owner --no-group ${user}/.oh-my-zsh/themes/fishier.zsh-theme \
        ${user}/Dropbox/misc/go/dot/.oh-my-zsh/themes/
    rsync -va --no-owner --no-group ${user}/.oh-my-zsh/custom \
        ${user}/Dropbox/misc/go/dot/.oh-my-zsh/

    rsync -va --no-owner --no-group ${user}/.config/fontconfig/fonts.conf \
        ${user}/Dropbox/misc/go/dot/.config/fontconfig/
    rsync -va --no-owner --no-group ${user}/.config/mpv/mpv.conf \
        ${user}/Dropbox/misc/go/dot/.config/mpv/
    rsync -va --no-owner --no-group ${user}/.config/darktable/styles \
        ${user}/Dropbox/misc/go/dot/.config/darktable/

    rsync -va --no-owner --no-group ${user}/.local/share/gnome-shell/ \
        ${user}/Dropbox/misc/go/dot/.local/share/gnome-shell/
    rsync -va --no-owner --no-group ${user}/.local/share/applications/ \
        ${user}/Dropbox/misc/go/dot/.local/share/applications/

    rsync -va ${user}/bin/ \
        ${user}/Dropbox/misc/go/bin/
    rsync -va /usr/local/bin/ \
        ${user}/Dropbox/misc/go/system/usr/local/bin/
    rsync -va /etc/dnf/dnf.conf \
        ${user}/Dropbox/misc/go/system/etc/dnf/dnf.conf
    rsync -va /usr/share/themes/Uhita/ \
        ${user}/Dropbox/misc/go/custom/Uhita/
}

function usage {
    echo "Usage: "
    echo "  -b: backup"
    echo "  -i: install base"
    echo "  -c: install configs"
    echo "  -d: install base + configs + desktop"
    echo "  -s: install skype"
}

while getopts "hbicds" opt; do
    case "$opt" in
    b)
        backup
        ;;
    i)
        install
        ;;
    c)  
        install-configs
        ;;
    d)
        install-desktop
        ;;
    s)
        install-skype
        ;;
    h|\?)
        usage
        ;;
    esac
done
if [ $OPTIND -eq 1 ]; then
    usage
fi
