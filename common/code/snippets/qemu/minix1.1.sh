#!/bin/sh

qemu-system-i386 \
	-machine isapc \
	-drive file=Disk01.img,format=raw,if=floppy,media=disk,readonly=off,index=0,snapshot=on \
	-boot a \
	-no-fd-bootchk \
	-monitor telnet::2222,server,nowait \
	-serial mon:stdio
