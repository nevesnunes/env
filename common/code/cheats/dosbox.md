# shortcuts

- `Alt+Enter`: Switch fullscreen
- `Alt+Pause`: Pause emulation
- `Ctrl+F1`: Key mapper
- `Ctrl+F10`: Release mouse
- `Ctrl+F11`: Decrease DOSBox cycles (slows down the emulation)
- `Ctrl+F12`: Increase DOSBox cycles (speeds up the emulation)

- https://www.dosbox.com/wiki/Special_Keys

### debugger

- `Alt+Pause`: Break on current instruction
- `F5`: Run
- `F9`: Set/Remove breakpoint
- `F10/F11`: Step over / trace into instruction
- `Ctrl+F10`: Release mouse
- `Alt+D/E/S/X/B`: Set data view to DS:SI/ES:DI/SS:SP/DS:DX/ES:BX

# debug

[Guide to the DOSBox debugger \- VOGONS](https://www.vogons.org/viewtopic.php?t=3944)

~/opt/dosbox-0_74_3/src/dosbox -conf dosbox.conf

```
debug main.exe
```

- f5 = resume from break
- alt-pause = break at current instruction
    - Mapper event: `hand_debugger`

```
heavylog
log 20000
# read key press
# https://en.wikipedia.org/wiki/INT_16H
bpint 16 10
```

# case studies

https://cloakedthargoid.wordpress.com/hacking-with-dosbox-debugger/
