#!/usr/bin/env sh

set -eux

if [ "$#" -gt 0 ]; then
  magnet=$*
else
  read -r magnet
fi

# Magnet file must contain hash
echo "$magnet" | grep -q 'xt=urn:btih:[^&/]\+'

# Generate port to listen on
# Note: Must be 1024 or greater, to avoid collisions with the 'Well Known Ports'
used_ports=$(netstat -antu | \
  sed -ne 's/.*[0-9\.]\+:\([0-9]\+\).*/\1/p' | \
  uniq)
is_port_range_valid=1
while [ "$is_port_range_valid" -eq 1 ]; do
  port=$(tr -dc '0-9' </dev/urandom | \
    head -c 5 | \
    sed 's/^0*//g')
  [ "$port" -gt 1024 ] && \
    [ "$port" -lt 65535 ] && \
    ! echo "$used_ports" | grep -q "$port" && \
    is_port_range_valid=0
done

exec aria2c \
  --bt-metadata-only=true \
  --bt-save-metadata=true \
  --listen-port="$port" \
  --enable-dht \
  --dht-listen-port="$port" "$magnet"
