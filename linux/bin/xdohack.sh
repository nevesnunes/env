#!/bin/bash

app=$1
number='^[0-9]+$'

function focus_if_window {
    if [[ $1 =~ $number ]] ; then
        xdotool windowactivate --sync $1
        exit 0
    fi
}

# Give priority to a window in the current workspace
desktop=$(xdotool get_desktop)
window=$(xdotool search --desktop $desktop $app | head -1)
focus_if_window "$window"

# Iterate through all workspaces
desktops=$(xdotool get_num_desktops)
for (( i=0; i<$desktops; i++ )) ; do
    window=$(xdotool search --desktop $i $app | head -1)
    focus_if_window "$window"
done
