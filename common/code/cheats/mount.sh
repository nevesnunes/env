sudo systemctl start nbd-server.service
sudo nbd-server -C /dev/null -r 9000 /dev/cdrom

modprobe nbd
lsmod | grep nbd
sudo nbd-client mnu -name cdrom /dev/nbd0 -persist
sudo nbd-client -d /dev/nbd0
sudo dd if=/dev/nbd0 of=disc.raw

# https://en.wikipedia.org/wiki/CDfs
# https://superuser.com/questions/902175/run-wine-totally-headless
