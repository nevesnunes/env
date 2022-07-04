#!/bin/sh

set -eux

. ./lib.sh

sync_debian_packages ./ubuntu-ctf.txt

# Unbloat services
sudo systemctl mask apache2 apt-daily avahi-daemon hddtemp irqbalance lm-sensors ModemManager nginx ondemand postfix smbd sys-kernel-debug.mount
