#!/bin/bash

source bin-colors.sh

function manage {
    echo -e "${bg_blue}${fg_white}${bold} * Note Wiz * ${reset}"
    PS3='Please enter your choice:'
    options=("Option 1" "Option 2" "Option 3" "Quit")
    select opt in "${options[@]}"
    do
        case $opt in
            "Option 1")
                echo "you chose choice 1"
                ;;
            "Option 2")
                echo "you chose choice 2"
                ;;
            "Option 3")
                echo "you chose choice 3"
                ;;
            "Quit")
                break
                ;;
            *) echo invalid option;;
        esac
    done
}

function usage {
    echo "Usage: "
    echo "  -m: manage"
}

if [ $OPTIND -eq 1 ]; then
    manage
    exit 0
fi
while getopts "h?m:" opt; do
    case "$opt" in
    m)
        manage
        exit 0
        ;;
    h|\?)
        usage
        exit 0
        ;;
    esac
done
