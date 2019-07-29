#!/usr/bin/env bash

# See:
# https://github.com/rapid7/metasploit-framework/blob/9eb335ad5ca3d282e286c3ff5d80bf108a1344ec/modules/payloads/singles/cmd/unix/reverse_bash.rb

set -eu

exec 3<> /dev/tcp/checkip.amazonaws.com/80
printf "GET / HTTP/1.1
Host: checkip.amazonaws.com
Connection: close

" >&3
tail -n1 <&3
