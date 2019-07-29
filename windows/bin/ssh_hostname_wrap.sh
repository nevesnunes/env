#!/usr/bin/env sh

set -eux

# FIXME: ssh server still attempts dns lookup
# even if hostname matches the format of an ip address

host=$(hostname)
ip_address=$(netsh interface ip show address "Ethernet" | \
  gawk 'match($0, /IP Address:[[:space:]]*([0-9\.:]*)/, e){print e[1]}')
reg add 'HKLM\System\CurrentControlSet\Services\Tcpip\Parameters' -v 'Hostname' -t 'REG_SZ' -d "$ip_address" -f
ssh "$@"
reg add 'HKLM\System\CurrentControlSet\Services\Tcpip\Parameters' -v 'Hostname' -t 'REG_SZ' -d "$host" -f
