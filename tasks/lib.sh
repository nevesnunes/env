#!/bin/sh

. "../linux/bin/functions/packages.sh"

debloat() {
  if os | grep -qi 'ubuntu'; then
    # use .deb packaged browsers
    sudo su -c 'yes | add-apt-repository ppa:mozillateam/ppa'
    sudo apt update
    sudo apt install -y -t 'o=LP-PPA-mozillateam' firefox
    sudo su -c 'cat << EOF > /etc/apt/preferences.d/mozillateam.pref
Package: firefox*
Pin: release o=LP-PPA-mozillateam
Pin-Priority: 501
EOF'

    # oh snap!
    sudo su -c 'cat << EOF > /etc/apt/preferences.d/nosnap.pref
Package: snapd
Pin: release a=*
Pin-Priority: -10
EOF'
    if command -v snap >/dev/null 2>&1; then
      if [ "$(snap list | wc -l)" -gt 0 ]; then
        sudo snap remove $(snap list | awk '!/^Name|^core/ {print $1}')
      fi
      sudo apt remove --purge -y snapd gnome-software-plugin-snap
    fi

    # mask services
    sudo systemctl mask apt-daily avahi-daemon hddtemp irqbalance lm-sensors ModemManager ondemand sys-kernel-debug.mount

    # can't remove gnome bloat without uninstalling gnome...
    for i in /etc/xdg/autostart/org.gnome.Software.desktop /usr/bin/gnome-software; do
      sudo sh -c 'echo > "'$i'" && chattr +i "'$i'"'
    done
  elif os | grep -qi 'fedora'; then
    sudo dnf -y remove \
      bijiben \
      cups \
      empathy \
      evolution \
      evolution-ews \
      evolution-help \
      geoclue \
      gfbgraph \
      gnome-boxes \
      gnome-calendar \
      gnome-contacts \
      gnome-dictionary \
      gnome-documents \
      gnome-getting-started-docs \
      gnome-initial-setup \
      gnome-maps \
      gnome-online-miners \
      gnome-photos \
      gnome-user-docs \
      gnome-user-share \
      gnome-weather \
      rhythmbox \
      shotwell \
      simple-scan \
      tracker-miners
  fi
}

sync_debian_packages() {
  packages=$(grep -v '^#' "$1" | paste -sd' ' "$1")
  if os | grep -qi 'ubuntu'; then
    packages=$(echo "$packages" | sed '
      s/chromium//g;
      s/firefox-esr//g;
    ')
  fi
  sudo apt update
  sudo apt install -y $packages
}

sync_gem_packages() {
  packages=$(grep -v '^#' "$1" | paste -sd' ')
  gem install --user-install $packages
}

sync_npm_packages() {
  packages=$(grep -v '^#' "$1" | paste -sd' ')
  npm install -g npm
  npm install -g $packages
}

sync_rpm_packages() {
  packages=$(grep -v '^#' "$1" | paste -sd' ')
  sudo dnf -y update
  sudo dnf -y install $packages
}

sync_python_packages() {
  pip install --user --upgrade pip
  pip install --user $(grep -v '^#' "$1" | paste -sd' ')
}

sync_git() {
  old_pwd=$PWD
  while read -r i; do
    target=$HOME/$(echo "$i" | cut -d':' -f1)
    url=$(echo "$i" | sed 's/[ \t\/]*$//g')
    repo=$(echo "$url" | cut -d':' -f2-)
    name=${url##*/}
    mkdir -p "$target"
    cd "$target"
    if [ ! -d "$name" ]; then
      git clone --depth=1 "$repo" "$name"
    else
      cd "$name" && git pull && git fetch --tags
    fi
  done < "$1"
  cd "$old_pwd"
}
