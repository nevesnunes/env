#!/usr/bin/env sh

set -eux

read -r magnet

# Magnet file must contain hash
echo "$magnet" | grep -q 'xt=urn:btih:[^&/]\+'

# Generate port to listen on
# Note: Must be 1024 or greater, to avoid collisions with the 'Well Known Ports'
used_ports=$(netstat -antu | \
  sed -ne 's/.*[0-9\.]\+:\([0-9]\+\).*/\1/p' | \
  sort -u)
port=""
while [ -z "$port" ] || "$port" -lt 1024 || echo "$used_ports" | grep -q "$port"; do
  port=$(tr -dc '0-9' </dev/urandom | head -c 4)
done

aria2c \
  --bt-metadata-only=true \
  --bt-save-metadata=true \
  --listen-port="$port" \
  --enable-dht \
  --dht-listen-port="$port" "$magnet"
