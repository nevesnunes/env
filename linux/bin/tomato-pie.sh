#!/usr/bin/env bash

let ifdefault=0

while getopts ":d" opt; do
    let work=1500
    let wcopy=$work
    let spause=300
    let scopy=$spause
    let bpause=900
    let bcopy=$bpause
    let number=4
    let backupnumber=$number
    let ifdefault=1
done

if [ $ifdefault -eq 0 ]
then
    read -p "Insert work time (minutes): " work
    let work=$work\*60
    let wcopy=$work
    read -p "Insert small pause time (minutes): " spause
    let spause=$spause\*60
    let scopy=$spause
    read -p "Insert big pause time (minutes): " bpause
    let bpause=$bpause\*60
    let bcopy=$bpause
    read -p "Insert number of small breaks: " number
    let backupnumber=$number
fi

let number=$number-1

while [ $backupnumber -ne 0 ]
do
    while [ $number -ne 0 ]
    do
        echo "Work time!"
        while [ $work -gt 0 ]; do
            echo -ne "$(($work%3600/60)) minutes $(($work%60)) seconds\033[0K\r"
            sleep 1
            : $((work--))
        done
        let number=$number-1
        echo "Take a slice of pie!"
        while [ $spause -gt 0 ]; do
            echo -ne "$(($spause%3600/60)) minutes $(($spause%60)) seconds\033[0K\r"
            sleep 1
            : $((spause--))
        done
        let work=$wcopy
        let spause=$scopy
    done
    echo "Work time!"
    while [ $work -gt 0 ]; do
        echo -ne "$(($work%3600/60)) minutes $(($work%60)) seconds\033[0K\r"
        sleep 1
        : $((work--))
    done
    echo "Take an entire pie now!"
    while [ $bpause -gt 0 ]; do
        echo -ne "$(($bpause%3600/60)) minutes $(($bpause%60)) seconds\033[0K\r"
        sleep 1
        : $((bpause--))
    done
    read -p "Do you want to go again? [y/n] " cond
    if [ "$cond" = "y" ]
    then
        let number=$backupnumber
        let work=$wcopy
        let spause=$scopy
    elif [ "$cond" = "n" ]
    then
        exit 0
    fi
done
