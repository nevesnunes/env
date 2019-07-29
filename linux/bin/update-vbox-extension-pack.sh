#!/usr/bin/env sh

set -eu

VBOX_LATEST_VERSION=$(curl http://download.virtualbox.org/virtualbox/LATEST.TXT)
target=/tmp/Oracle_VM_VirtualBox_Extension_Pack-"$VBOX_LATEST_VERSION".vbox-extpack
wget -c http://download.virtualbox.org/virtualbox/"$VBOX_LATEST_VERSION"/Oracle_VM_VirtualBox_Extension_Pack-"$VBOX_LATEST_VERSION".vbox-extpack -O "$target" 
sudo VBoxManage extpack uninstall "Oracle VM VirtualBox Extension Pack"
sudo VBoxManage extpack cleanup
sudo VBoxManage extpack install "$target" --accept-license=56be48f923303c8cababb0bb4c478284b688ed23f16d775d729b89a2e8e5f9eb
