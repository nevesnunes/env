#!/usr/bin/env sh

# Supercedes: telnet, rsh

# On Windows:
# https://github.com/billziss-gh/sshfs-win
#     net use \\sshfs\USER@HOST[\PATH]
#     https://github.com/billziss-gh/sshfs-win/issues/98
#     https://github.com/billziss-gh/sshfs-win/issues/33
#     https://github.com/billziss-gh/winfsp
# https://github.com/feo-cz/win-sshfs
#     csharp, inactive

# Better performance
# Requires: SSH server with sftp support
sshfs -o Ciphers=arcfour -o Compression=no server://some_folder /mnt/some_local_folder
rsync -e"ssh -c arcfour -o Compression=no"

# Requires: SSH server with `AllowTCPPortForwarding` disabled
local_port=
remote_host=
remote_port=
socat TCP-LISTEN:$local_port,reuseaddr,fork "EXEC:ssh $remote_host nc localhost $remote_port"


