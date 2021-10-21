#!/bin/sh

BOOT=c
HD=hd.img
MEM=64m
qemu-system-i386 -M pc -cpu 486 -m $MEM -enable-kvm \
  -name "386BSD 1.0" \
  -smp cpus=1,cores=1,threads=1,sockets=1,maxcpus=1 \
  -hda $HD \
  -boot $BOOT -no-fd-bootchk \
  -k en-us -rtc base="1994-01-01"
