# keybinds

- `Alt+Enter`: Switch fullscreen
- `Alt+Pause`: Pause emulation
- `Ctrl+F1`: Key mapper
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

# case studies

- https://cloakedthargoid.wordpress.com/hacking-with-dosbox-debugger/
- https://astralvx.com/debugging-16-bit-in-qemu-with-gdb-on-windows/
