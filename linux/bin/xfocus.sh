#!/usr/bin/env bash

desktop=$(xdotool get_desktop)
window_ids=($(xdotool search --desktop "$desktop" "."))
size=${#window_ids[@]}
if [[ $size -eq 0 ]]; then
    exit 0
fi

number='^(0x)*[0-9a-f]+$'
function focus_if_window {
    if [[ $1 =~ $number ]] ; then
        xdotool windowactivate --sync "$1"
        exit 0
    fi
}

focus_id=$(xdotool getwindowfocus)
focus_corner=$(xwininfo -id "$focus_id" | grep Corners | awk -F " " '{print $2}')
focus_x=$(echo "$focus_corner" | awk -F "+" '{print $2}')
focus_y=$(echo "$focus_corner" | awk -F "+" '{print $3}')

# Subtract window frame dimensions from position
frame=$(xprop -id "$focus_id" | grep _NET_FRAME_EXTENTS)
if [[ "$frame" != "" ]]; then
    frame_left=$(echo "$frame" | cut -d' ' -f3 | cut -d',' -f1)
    frame_top=$(echo "$frame" | cut -d' ' -f5 | cut -d',' -f1)
    focus_x=$(($focus_x - $frame_left))
    focus_y=$(($focus_y - $frame_top))
fi

# Focus the nearest window in the choosen direction.
# Desambiguate candidates by choosing the one closest to the currently 
# focused window, i.e. smallest delta.
# Penalization is applied to windows straying into the perpendicular axis.
result_id=$focus_id
result_delta=9999
function update_delta {
    # Skip initial window 
    if [[ "$id" == "$focus_id" ]]; then
      return
    fi

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

option=""
while getopts "hjkl" opt; do
    case "$opt" in
    h) option="h" ;;
    j) option="j" ;;
    k) option="k" ;;
    l) option="l" ;;
    esac
done
for (( i=0; i<$size; i++ )); do
    id=${window_ids[$i]}
    corner=$(xwininfo -id "$id" | grep Corners | awk -F " " '{print $2}')
    x=$(echo "$corner" | awk -F "+" '{print $2}')
    y=$(echo "$corner" | awk -F "+" '{print $3}')

    # Subtract window frame dimensions from position
    frame=$(xprop -id "$id" | grep _NET_FRAME_EXTENTS)
    if [[ "$frame" != "" ]]; then
        frame_left=$(echo "$frame" | cut -d' ' -f3 | cut -d',' -f1)
        frame_top=$(echo "$frame" | cut -d' ' -f5 | cut -d',' -f1)
        x=$(($x - $frame_left))
        y=$(($y - $frame_top))
    fi

    if [[ "$option" == "h" ]] && [[ $x -lt $focus_x ]]; then
        update_delta 1 2
    elif [[ "$option" == "j" ]] && [[ $y -gt $focus_y ]]; then
        update_delta 2 1
    elif [[ "$option" == "k" ]] && [[ $y -le $focus_y ]]; then
        update_delta 2 1
    elif [[ "$option" == "l" ]] && [[ $x -gt $focus_x ]]; then
        update_delta 1 2
    fi
done
focus_if_window "$result_id"
