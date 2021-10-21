# keybinds

- `Alt+Enter`: Switch fullscreen
- `Alt+Pause`: Pause emulation
- `Ctrl+F1`: Key mapper
- `Ctrl+F5`: Take screenshot
- `Ctrl+F10`: Release mouse
- `Ctrl+F11`: Decrease DOSBox cycles (slows down the emulation)
- `Ctrl+F12`: Increase DOSBox cycles (speeds up the emulation)

- https://www.dosbox.com/wiki/Special_Keys

### debugger

- `Alt+Pause`: Break on current instruction
    - Mapper event: `hand_debugger`
- `F3`: Previous command in history
- `F4`: Next command in history
- `F5`: Run / Resume from break
- `F9`: Set / Remove breakpoint
- `F10/F11`: Step over / trace into instruction
- `Ctrl+F10`: Release mouse

- `Alt+D/E/S/X/B`: Set data view to DS:SI/ES:DI/SS:SP/DS:DX/ES:BX
- `C / D [segment]:[offset]`: Set code / data view address.
- `SR [reg] [value]`: Set register value
- `SM [seg]:[off] [value]`: Set memory value

- `BPINT [intNr] [ah] [al]`: Set interrupt breakpoint
- `BPM [segment]:[offset]`: Set memory breakpoint (memory change)
- `BPPM [selector]:[offset]`: Set pmode-memory breakpoint (memory change)
- `BPLM [linear address]`: Set linear memory breakpoint (memory change)
- `INT [nr] / INTT [nr]`: Execute / Trace into interrupt

- [Guide to the DOSBox debugger \- VOGONS](https://www.vogons.org/viewtopic.php?t=3944)

# debug

```bash
# Given `.conf` with content:
# debug main.exe
~/opt/dosbox-0_74_3/src/dosbox -conf dosbox.conf
```

```
memdumpbin ds:0 ffffff

heavylog
log 20000

# read key press
# https://en.wikipedia.org/wiki/INT_16H
bpint 16 10
```

Alternatives:

- Protected mode: Watcom Debugger
- Real mode: SoftICE

# 3.1

- Graphics
    1. dosbox.conf: machine=svga_et4000
    2. Program Manager > Main > Windows Setup > Display: SVGA 256 colors
- Sound
    - ~/share/311/SB16W3x/INSTALL.EXE
    - IRQ: 7

# MS-DOS 6.22

```bash
qemu-img create -f qcow msdos.disk 2G

# install
qemu-system-i386 -hda msdos.disk -m 64 -L . -fda dos622_1.img -boot a
# ||
sudo mount -o rw -t vfat Disk1.img ~/media/floppy/1
qemu-system-i386 -hda msdos.disk -m 64 -L . -fda fat:floppy:rw:$HOME/media/floppy/1 -boot a
# (qemu) change floppy0 dos622_2.img

# run
qemu-system-i386 -hda msdos.disk -m 64 -L . -soundhw sb16,adlib,pcspk

# share
dd if=/dev/zero of="$HOME/media/floppy/image" bs=1440K count=1
mkfs.vfat ~/media/floppy/image
mkdir -p ~/media/floppy/mount
sudo mount -o rw -t vfat ~/media/floppy/image ~/media/floppy/mount
```

- Sound
    ```
    BLASTER=A220 I5 D1 H5 P330 T5
    ```
- Graphics
    ```
    edit windows\system.ini
    # display.drv=VGA.DRV
    ```

# case studies

- https://cloakedthargoid.wordpress.com/hacking-with-dosbox-debugger/
- https://astralvx.com/debugging-16-bit-in-qemu-with-gdb-on-windows/
