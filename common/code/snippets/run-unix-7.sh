#!/bin/bash
set -euo pipefail

qemumonitor() {
    if [[ $1 =~ sendkey.* ]]
    then
        nc 127.0.0.1 "$LISTENPORT" <<END >/dev/null 2>&1
$@
END
    else
        nc 127.0.0.1 "$LISTENPORT" <<END | grep -v '^(qemu)'
$@
END
    fi
}

qemudelaysend() {
    local mystring="$*"
    local i
    local s
    sleep 1
    for ((i=0;i<${#mystring};++i))
    do
    s="${mystring:$i:1}"
    case "$s" in
        [A-Z]) qemumonitor sendkey shift-${s,,} ;;
        ,) qemumonitor sendkey comma ;;
        =) qemumonitor sendkey equal ;;
        -) qemumonitor sendkey minus ;;
        /) qemumonitor sendkey slash ;;
        .) qemumonitor sendkey dot ;;
        ' ') qemumonitor sendkey spc ;;
        '(') qemumonitor sendkey shift-9 ;;
        ')') qemumonitor sendkey shift-0 ;;
        '$') qemumonitor sendkey shift-4 ;;
        ';') qemumonitor sendkey semicolon ;;
        ':') qemumonitor sendkey shift-semicolon ;;
        '\') qemumonitor sendkey backslash ;;
        '>') qemumonitor sendkey shift-dot ;;
        *) qemumonitor sendkey "${s}" ;;
    esac
    done
}

LISTENPORT=9300
qemu-system-i386 -boot d -cdrom ~/vms/pdp11.iso -m 32 -monitor "tcp:127.0.0.1:$LISTENPORT,server,nowait" &>/dev/null &

lines=()
lines+=('b')
lines+=('boot' $'\x1f')
lines+=('rl(0,0)rl2unix' $'\x1f')
for l in "${lines[@]}"; do
  if echo "$l" | grep -q $'\x1f'; then
      qemumonitor sendkey ret
      continue
  fi

  clear
  echo "Press any key to send: $l"
  read -r -n1
  qemudelaysend "$l"
done
clear
wait
