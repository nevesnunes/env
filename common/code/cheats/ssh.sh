#!/usr/bin/env sh

sshfs -o Ciphers=arcfour -o Compression=no server://some_folder /mnt/some_local_folder
rsync -e"ssh -c arcfour -o Compression=no"

# SSH server with `AllowTCPPortForwarding` disabled
socat TCP-LISTEN:<local_port>,reuseaddr,fork "EXEC:ssh <server> nc localhost <remote_port>"
