#!/bin/sh

# Exaustive scan
# - TCP SYN: -sS
# - Service detection: -sV --version-all
# - OS detection: -O
# - Port scan: -p- --reason == -p1-65535 --reason
# - Treat host as online: -Pn
# - Skip DNS resolution: -n
nmap -sSV -O -p- -Pn -n --version-all --reason 10.0.2.0/24
# || OS detection, version detection, script scanning, traceroute: -A
nmap -sS -A -p- -Pn -n --version-all --reason 10.0.2.0/24
# || UDP:
nmap -sU -A -p- -Pn -n --version-all --reason 10.0.2.0/24
# Alternatives:
# - report connection status only (-z)
nc -z -v -w 1 10.0.2.4 80
# - enumerate app servers
netstat -tulpn | \
    gawk 'match($0, /.*:([0-9]+).*LISTEN/, r){print r[1]}' | \
    xargs -i sh -c '
        printf "HEAD / HTTP/1.0\r\n\r\n" | \
        nc -n -i 2 localhost "$1" | \
        grep "HTTP/[0-9\.]\+\ " && echo "Found server listening at port = $1"\
    ' _ {}

# OS and version detection, script scanning, traceroute
# ~= nmap -O -sV -sC
nmap -A

# List IP range of addresses
# == -sP
nmap -sn 192.168.123.0/24
# || Combine with different types of requests
# -sL: PTR records of DNS
# -PS/PA/PU/PY[portlist]: TCP SYN/ACK, UDP or SCTP discovery to given ports
# -PE/PP/PM: ICMP echo, timestamp, and netmask request discovery probes
# -PO[protocol list]: IP Protocol Ping
# -PR: ARP Ping

# Debug
# -vvv
# --packet-trace
# - https://security.stackexchange.com/questions/124394/nmap-says-host-down-when-host-is-up
#     - under specific network (-e)
# - https://stackoverflow.com/questions/40514044/nmap-rttvar-has-grown-to-over-2-3-seconds-decreasing-to-2-0
#     - avoiding RTTVAR error (--host-timeout 2)

# References
# - [NMAP Tips: RTFM?](https://blog.zsec.uk/nmap-rtfm/)
