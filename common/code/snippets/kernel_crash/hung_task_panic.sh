#!/bin/sh

dd if=/dev/zero of=/tmp/foo bs=1 count=$((8*1024*1024)) &
fsfreeze -f /tmp
