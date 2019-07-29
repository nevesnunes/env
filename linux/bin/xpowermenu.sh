#!/usr/bin/env bash

descriptions=()
actions=()
descriptions+=('Suspend')
actions+=('systemctl suspend')
descriptions+=('Reboot')
actions+=('systemctl reboot')
descriptions+=('Power Off')
actions+=('systemctl poweroff')

options=""
size=${#descriptions[@]}
for (( i=0; i<$size; i++ )); do
  option=${descriptions[$i]}
  options+="$option\n"
done
options=${options%\\n}

result=$(echo -e "$options" | rofi -dmenu -i -format i -p "window:")
number='^(0x)*[0-9a-f]+$'
if [[ $result =~ $number ]] ; then
    ${actions[$result]}
fi
