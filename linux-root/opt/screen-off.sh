#!/bin/sh

slock >/dev/null 2>&1 &
sleep 0.5
xset dpms force off 
