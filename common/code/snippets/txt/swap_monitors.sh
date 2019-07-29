#!/bin/bash
# swap_monitor.sh (original version)
# Moves the active window to the other screen of a dual-screen Xinerama setup.
#
# movewin.sh (modified version)
# allows movement of windows left and right between multiple monitors
#
# Requires: wmctrl, xprop, xwininfo
#
# Original Author: Raphael Wimmer
# raphman@gmx.de
#
# Modified by: Gary Fixler
# gfixler+bash@gmail.com

function getNumberOfMonitors
{
    # simply must be hardcoded
    # e.g. MatroxTripleHead2Go can service 3 screens,
    # but appears as only one monitor to the computer

    # change to your number of monitors
    echo 3
}

function getMonitorWidth
{
    numberOfMonitors=$(getNumberOfMonitors)
    monitorLine=$(xwininfo -root | grep "Width")
    monitorWidth=$((${monitorLine:8}/$numberOfMonitors ))
    echo $monitorWidth
}

function getActiveWindowID
{
    activeWinLine=$(xprop -root | grep "_NET_ACTIVE_WINDOW(WINDOW)")
    activeWinID="${activeWinLine:40}"
    echo $activeWinID
}

function getActiveWindowHorizontalPosition
{
    activeWinID=$(getActiveWindowID)
    xPosLine=$(xwininfo -id $activeWinID | grep "Absolute upper-left X")
    xPos=${xPosLine:25}
    echo $xPos
}

function getActiveWindowWidth
{
    activeWinID=$(getActiveWindowID)
    xWidthLine=$(xwininfo -id $activeWinID | grep "Width")
    xWidth=${xWidthLine:8}
    echo $xWidth
}

function getActiveWindowCurrentMonitor
{
    numberOfMonitors=$(getNumberOfMonitors)
    monitorWidth=$(getMonitorWidth)
    activeWinID=$(getActiveWindowID)
    xPos=$(getActiveWindowHorizontalPosition)
    i="0"
    while [ $xPos -gt $monitorWidth ]
    do
        xPos=$[$xPos-$monitorWidth]
        i=$[$i+1]
    done
    echo $i
}

function getActiveWindowPositionOneMonitorToTheLeft
{
    monitorWidth=$(getMonitorWidth)
    currentMonitor=$(getActiveWindowCurrentMonitor)
    activeWinID=$(getActiveWindowID)
    xPos=$(getActiveWindowHorizontalPosition)
    xPos=$[$xPos-$monitorWidth]
    echo $xPos
}

function getActiveWindowPositionOneMonitorToTheRight
{
    monitorWidth=$(getMonitorWidth)
    numberOfMonitors=$(getNumberOfMonitors)
    currentMonitor=$(getActiveWindowCurrentMonitor)
    activeWinID=$(getActiveWindowID)
    xPos=$(getActiveWindowHorizontalPosition)
    xPos=$[$xPos+$monitorWidth]
    echo $xPos
}

function changeActiveWindowMonitor
{
    activeWinID=$(getActiveWindowID)
    if [ $1 -eq "0" ]
    then
        newXPos=$(getActiveWindowPositionOneMonitorToTheLeft)
        newXPos=$[$newXPos-5]
    else
        newXPos=$(getActiveWindowPositionOneMonitorToTheRight)
        newXPos=$[$newXPos-5]
    fi

    winState=$(xprop -id ${activeWinID} | grep "_NET_WM_STATE(ATOM)" )

    if [[ `echo ${winState} | grep "_NET_WM_STATE_MAXIMIZED_HORZ"` != "" ]]
        then
        maxH=1
        wmctrl -i -r ${activeWinID} -b remove,maximized_horz
    fi

    if [[ `echo ${winState} | grep "_NET_WM_STATE_MAXIMIZED_VERT"` != "" ]]
        then
        maxV=1
        wmctrl -i -r ${activeWinID} -b remove,maximized_vert
    fi

    if [[ `echo ${winState} | grep "_NET_WM_STATE_FULLSCREEN"` != "" ]]
        then
        fulls=1
        wmctrl -i -r ${activeWinID} -b remove,fullscreen
    fi

    # move window (finally)
    wmctrl -i -r ${activeWinID} -e 0,${newXPos},-1,-1,-1

    # restore maximization
    ((${maxV})) && wmctrl -i -r ${activeWinID} -b add,maximized_vert
    ((${maxH})) && wmctrl -i -r ${activeWinID} -b add,maximized_horz
    ((${fulls})) && wmctrl -i -r ${activeWinID} -b add,fullscreen

    # raise window (seems to be necessary sometimes)
    wmctrl -i -a ${activeWinID}

}

function moveActiveWindowOneMonitorToTheLeft
{
    changeActiveWindowMonitor 0
}

function moveActiveWindowOneMonitorToTheRight
{
    changeActiveWindowMonitor 1
}

"$1"

exit 0
