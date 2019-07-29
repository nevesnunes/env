# rpm

sudo sginfo -a /dev/sda
sudo smartctl --all /dev/sda | grep -i rotation

# rpm/iops
#
# 5400/60 = 90
# 7200/100 = 72
# 10000/150 = 66
# 15000/200 = 75
