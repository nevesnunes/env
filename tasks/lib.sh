#!/bin/sh

. "$HOME/bin/functions/packages.sh"

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
  fi
}

sync_debian_packages() {
  packages=$(paste -sd' ' "$1")
  if os | grep -qi 'ubuntu'; then
    packages=$(echo "$packages" | sed '
      s/chromium//g;
      s/firefox-esr//g;
    ')
  fi
  sudo apt update
  sudo apt install -y $packages
}

sync_python_packages() {
  pip install --user --upgrade pip
  pip install --user $(paste -sd' ' "$1")
}

sync_git() {
  old_pwd=$PWD
  while read -r i; do
    target=$HOME/$(echo "$i" | cut -d':' -f1)
    url=$(echo "$i" | sed 's/[ \t\/]*$//g')
    repo=$(echo "$url" | cut -d':' -f2-)
    name=$(echo "${url##*/}" | sed 's/\.git$//g')
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
