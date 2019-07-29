#!/usr/bin/env bash

set -eu

cat -e -t -v Makefile
make clean
make

sudo insmod hello.ko

dmesg | tail -n5
journalctl --since="5 minutes ago" --dmesg | tail -n5

sudo rmmod hello.ko
