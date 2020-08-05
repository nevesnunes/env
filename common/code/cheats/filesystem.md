# memory-mapped temporary files

```bash
shm_dir=$(mktemp -p /dev/shm/)
dd if=/dev/zero of="$shm_dir" bs=500M count=1
# xref. `top` - used memory increased by 500M
# ref. https://superuser.com/questions/45342/when-should-i-use-dev-shm-and-when-should-i-use-tmp

mount -t tmpfs -o size=500M tmpfs /mnt/ramdisk
# ref. https://unix.stackexchange.com/questions/188536/how-to-make-a-temporary-file-in-ram

mknod -m 660 /dev/ramdisk b 1 1
chown root:disk /dev/ramdisk
dd if=/dev/zero of=/dev/ramdisk bs=1k count=4k
/sbin/mkfs -t ext2 -m 0 /dev/ramdisk 4096
mount -t ext2 /dev/ramdisk /mnt/ramdisk
# ref. http://surfer.nmr.mgh.harvard.edu/partition/ramdisk.html
```

# testing graceful degradation on constrained environment

```bash
mount -t tmpfs -o size=10M,nr_inodes=10,mode=700 tmpfs /mnt/low_nr_inodes_disk
```

# partitioning

```bash
sudo parted /dev/hdz
# print
# mkpart TYPE linux-swap START END

# || On error: unable to satisfy all constraints
sudo fdisk /dev/hdz
# || GPT
sudo gdisk /dev/hdz
# p => print
# n => new
# t => change partition type
# w => write changes
sudo mkfs -t vfat /dev/hdz1
# || NTFS, fast format
sudo mkntfs -f /dev/hdz1 --label foo

mkswap /dev/hdz2
swapon /dev/hdz2

# Validation:
cat /proc/swaps
# Filename  Type      Size    Used Priority
# /dev/hdz2 partition 2047996 0-2
cat /etc/fstab
# /dev/hdz2 swap swap defaults 0 0
```

https://www.tldp.org/HOWTO/Partition/fdisk_partitioning.html


