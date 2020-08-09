# Clean cache, unused packages

pacman -Scc
paccache -rk0

# GPGME errors

rm -rf /etc/pacman.d/gnupg
pacman-key --init
pacman-key --populate msys2
pacman-key --refresh-keys
# ||
# Incompatible lib installed

# Search package providing file
pacman -Fy
pacman -F ssh.exe
# ||
pacman -Fx 'ssh(.exe)?'
