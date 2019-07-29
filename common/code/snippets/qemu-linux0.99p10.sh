qemu-system-i386 \
  -machine isapc -m 32M -boot menu=on \
  -vga cirrus -display gtk \
  -device ne2k_isa,netdev=slirp -netdev user,id=slirp,smb=share \
  -serial msmouse -rtc base="1993-12-14" \
  -device sb16,iobase=0x220,irq=7,dma=3
