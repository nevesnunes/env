#!/bin/bash

number='^[0-9]+$'
function focus_if_window {
    if [[ $1 =~ $number ]] ; then
        xdotool windowactivate --sync $1
        exit 0
    fi
}

desktop=$(xdotool get_desktop)
window_ids=($(xdotool search --desktop $desktop "."))
size=${#window_ids[@]}
if [[ $size -eq 0 ]]; then
    exit 0
fi

window_names=()
options=""
for (( i=0; i<$size; i++ )); do
    id=${window_ids[$i]}
    name=$(xdotool getwindowname $id)
    window_names[$i]="$name"

    class_temp=$(xprop -id $id | grep WM_CLASS | awk -F " " '{print $4}')
    class="${class_temp%\"}"
    class="${class#\"}"
    class="$(printf '%-15s' $class)"

    options+="$class  $name\n"
done
options=${options%\\n}

result=$(echo -e "$options" | rofi -dmenu -i -format i -p "window:")
if [[ $result =~ $number ]] ; then
    focus_if_window "${window_ids[$result]}"
fi
