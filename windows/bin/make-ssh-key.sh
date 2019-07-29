#!/usr/bin/env bash

# See:
#
# ~/.ssh/config
# Host ...
#
# /etc/ssh/sshd_config
# AllowUsers you@192.168.0.0/16
# ListenAddress 192.168.0.10
# PasswordAuthentication no
# Port 22550
#
# sudo mkdir -p /home/%%%/.ssh
# sudo chmod 700 /home/%%%/.ssh
# sudo cat %%%.pub >> /home/%%%/.ssh/authorized_keys
# sudo chmod 640 /home/%%%/.ssh/authorized_keys
#
# sudo semanage port -a -t ssh_port_t -p tcp 22550
# sudo dnf install -y openssh-server
# sudo systemctl start sshd.service
# sudo systemctl enable sshd.service

set -eu

mkdir -p ~/.ssh
read -r -p "Host: " host
ssh-keygen -t ed25519 -a 100 -f ~/.ssh/"$host"
