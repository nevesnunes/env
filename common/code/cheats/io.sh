# monitor

### On terminal 1
sudo iotop
### On terminal 2
dd if=/dev/urandom of=200 bs=10M count=20
sync; sudo su -c 'echo 3 > /proc/sys/vm/drop_caches'
cat 200 >/dev/null

# rpm

sudo sginfo -a /dev/sda
sudo smartctl --all /dev/sda | grep -i rotation
# rpm/iops
# - 5400/60 = 90
# - 7200/100 = 72
# - 10000/150 = 66
# - 15000/200 = 75
