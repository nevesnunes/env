#!/bin/sh

#export LD_DEBUG=all
export LD_LIBRARY_PATH="/run/host/usr/lib64:/run/host/usr/lib64/pulseaudio:$LD_LIBRARY_PATH"

# OK:
# /run/host/usr/bin/ulimit -a

# NOK:
# /run/host/usr/bin/ls /foo
# /run/host/usr/bin/gdb
# /run/host/usr/bin/gdb -ex 'handle SIGABRT stop print nopass' -ex 'r' -ex 'bt' -ex 'q' --args /run/host/usr/bin/prboom-plus "@"
# /run/host/usr/bin/prboom-plus "@"
"/home/$USER/opt/prboom2/src/prboom-plus" "@"
