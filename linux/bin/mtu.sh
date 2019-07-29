#!/bin/sh

set -eux

mtu=1500
while true; do
  ping -M 'do' -s "$mtu" -W 5 -c 1 www.google.com && \
    break
  mtu=$((mtu-10))
done
sudo ifconfig eth0 mtu "$mtu"
