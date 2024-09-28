#!/bin/sh

set -eux

. ./lib.sh

sync_debian_packages ./debian-dev.txt
sync_git ./git-essentials.txt

curl --proto '=https' --tlsv1.2 -LsSf https://setup.atuin.sh | sh

. ./dconf-load.sh

. ./sync-user.sh
