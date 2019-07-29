#!/bin/sh

# This script brings my system online, as in it performs all the basic early boot tasks needed to actually run programs just after the kernel has been loaded.
# 
# The trick is that most systems that distributions use have to work for everyone as such they contain a tonne of detection mechanisms about your system which makes the code far larger and slower. My system essentially assumes a particular state which I can do because I control my own system.
# 
# To walk it through:
# 
# The first thing it does is mount the pseudofilesystems, Linux exposes most of its internal state through a set of files which are generated on demand whenever a process reads of it. The most important three are located in /dev which contains information about devices, /proc which contains information about current processes and /sys which contains information about the current state of the system. You can look into those directories and see a bunch of files, those files are abstract and don't actually exist on your drive, they're so called virtual files but you can open and read them all the same and write to them which allow you to control your system.
# 
# Programs assume those files exist there because they read and write to them in order to say report battery state, alter the brightness of your screen andsoforth. So the first thing we do is enable those filesystems, this has to go before all others because the rest of the things depend on it.
# 
# For instance, to test one of those files, try sudo cat /dev/input/mouse0 (might be another number) and move your mouse, you'll notice random text appearing when you move your mouse as you read that file, yes, that's how programs access input information, they just read a file, the kernel is responsible for generating that content as the input devices move.
# 
# After that's done we mount the cgroup system. cgroups are a Linux-specific control interface to group processes together and essentially let multiple processes behave like a single one. This is again manipulated and inspected through virtual files.
# 
# After that is done udev is started, udev is the userspace tool that manages the /dev directory, this used to be done in the kernel directly but nowadays typically a userspace device manager is used for this, udev being one of the more popular ones, udev is responsible for detecting the insertion of new devices and re-arranging `/dev accordingly.
# 
# After udev's set up we perfork fsck, the file system integrity check, it's important to note that up unti this point nothing but the root filesystem was mounted and it was mounted read-only, it could not be written to, it wasn't needed up to that point. The filesystem needs to be read-only or not mounted at all for the integrity check to take place. You can't check a filesystem that's bein written to
# 
# Once that is done, we mount all other filesystems and remount the root filesystem read-write, from this point on we can write to it.
# 
# Once that is done we simply bring up the networking devices so we can hav internet, pretty simple
# 
# And then we set the hostname of the system to "X", note how the hostname is set by writing to a file in /proc, the kernel responds by changing the hostname if that file is written to.
# 
# Then we enable the swap partition, swap is basically an extension of working memory on the drive itself, it's not really needed but I have a swap partition anyway which almost never gets filled
# 
# then sysctl sets its default stored state, it reads some configuration files and sets the paramaters of the system like what scheduler you want to use andsoforth, this is again done by the sysctl tool itsel actually writing to /sys.
# 
# And finally, the user-defined scripts in /etc/local.d and ~/.config/local.d` are ran at the end of boot.
# 
# After that is done, the system is considered ready and the actual services like login and all that shit can be started which happens after that.
# 
# This system is highly specific and does not do a couple of things which are expected of a normal bootup:
# 
#     It doesn't load kernel modules, because I have none
#     It doesn't load binfmt to allow esoteric binary formats, as I only use ELF
#     It does't correctly set up locales, dates and timezones because my system is UTC
#     it doesn't correctly seed urandom to provide high quality kernel-provided RNG because I'm not using this machine for anything security sensitive
#     it doesn't correctly detect and handle encrypted partitions because I have none of them.
#     it doesn't perform the steps needed to bring various filesystems online because I only use EXT4 which doesn't need any specific things like Btrfs and ZFS do.

set -u   
export PATH=/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin

echo "mounting pseudo filesystems ..."
mount -o nosuid,noexec,nodev        -t proc proc /proc
mount -o nosuid,noexec,nodev        -t sysfs sys /sys
mount -o size=100%,mode=755,noatime -t tmpfs tmpfs /run
mount -o mode=0755,nosuid           -t devtmpfs dev /dev
ln -s sda5 /dev/root

mkdir -p -m0755 /dev/pts /dev/shm
mkdir -p -m1777 /dev/mqueue
mount -o noexec,nosuid,nodev -n -t mqueue mqueue /dev/mqueue
mount -o mode=0620,gid=5,nosuid,noexec -n -t devpts devpts /dev/pts
mount -o mode=1777,nosuid,nodev -n -t tmpfs shm /dev/shm

echo "mounting cgroups ..."
mount -o mode=0755 -t tmpfs cgroup /sys/fs/cgroup
for cgroup in $(grep -v '^#' /proc/cgroups | cut -f1); do
    mkdir -p /sys/fs/cgroup/$cgroup &&
    mount -t cgroup -o $cgroup cgroup /sys/fs/cgroup/$cgroup
    done

echo "starting udev ..."
/sbin/udevd --daemon
udevadm trigger --action=add --type=subsystems
udevadm trigger --action=add --type=devices
#   udevadm settle

echo "fscking ..."
fsck -A -T -a -t noopts=_netdev
echo "remouting root read-write ..."
mount -o remount,rw /
echo "mountin all other local filesystems ..."
mount -a -t "nosysfs,nonfs,nonfs4,nosmbfs,nocifs" -O no_netdev

echo "starting networking ..."
ip addr add 127.0.0.1/8 dev lo brd + scope host
ip route add 127.0.0.0/8 dev lo scope host
ip link set lo up

echo "setting hostname ..."
cat /etc/hostname > /proc/sys/kernel/hostname

echo "enabling swap ..."
swapon -a

echo "setting sysctl ..."
sysctl -q --system

echo "running /etc/local.d/*,start ..."
for f in /etc/local.d/*.start; do
    [ -x "$f" ] && "$f"
    done

echo "running /home/*/.config/local.d/*.start & ..."
for f in /home/*/.config/local.d/*.start; do
    if [ -x "$f" ]; then
        ug="$(stat -c '-u %U -g %G' -- "$f")"
        sudo $ug -- "$f" >/dev/null 2>&1 &
    fi
done
