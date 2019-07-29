#!/bin/bash

number='^[0-9]+$'
function focus_if_window {
    if [[ $1 =~ $number ]] ; then
        xdotool windowactivate --sync "$1"
        exit 0
    fi
}

desktop=$(xdotool get_desktop)
window_ids=($(xdotool search --desktop "$desktop" "."))
size=${#window_ids[@]}
if [[ $size -eq 0 ]]; then
    exit 0
fi

option=""
while getopts "hjkl" opt; do
    case "$opt" in
    h) option="h" ;;
    j) option="j" ;;
    k) option="k" ;;
    l) option="l" ;;
    esac
done

function update_delta {
    diff_x_focus=$((($x - $focus_x) * $1))
    diff_x_focus=${diff_x_focus#-}
    diff_y_focus=$((($y - $focus_y) * $2))
    diff_y_focus=${diff_y_focus#-}
    delta=$(($diff_x_focus + $diff_y_focus))
    if [[ $delta -lt $result_delta ]]; then
        result_delta=$delta
        result_id=$id
    fi
}

# Focus the nearest window in the choosen direction.
# Desambiguate candidates by choosing the one closest to the currently 
# focused window, i.e. smallest delta.
# Penalization is applied to windows straying into the perpendicular axis.
focus_id=$(xdotool getwindowfocus)
focus_corner=$(xwininfo -id "$focus_id" | grep Corners | awk -F " " '{print $2}')
focus_x=$(echo "$focus_corner" | awk -F "+" '{print $2}')
focus_y=$(echo "$focus_corner" | awk -F "+" '{print $3}')
result_id=$focus_id
result_delta=9999
for (( i=0; i<$size; i++ )); do
    id=${window_ids[$i]}
    corner=$(xwininfo -id "$id" | grep Corners | awk -F " " '{print $2}')
    x=$(echo $corner | awk -F "+" '{print $2}')
    y=$(echo $corner | awk -F "+" '{print $3}')

    if [[ "$option" == "h" ]] && [[ $x -lt $focus_x ]]; then
        update_delta 1 2
    elif [[ "$option" == "j" ]] && [[ $y -gt $focus_y ]]; then
        update_delta 2 1
    elif [[ "$option" == "k" ]] && [[ $y -lt $focus_y ]]; then
        update_delta 2 1
    elif [[ "$option" == "l" ]] && [[ $x -gt $focus_x ]]; then
        update_delta 1 2
    fi
done
focus_if_window "$result_id"
