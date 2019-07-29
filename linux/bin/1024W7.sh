#!/bin/bash
xrandr --output VGA1 --mode 1024x768
virtualbox --startvm W7 --fullscreen
xrandr --output VGA1 --mode 1920x1080
