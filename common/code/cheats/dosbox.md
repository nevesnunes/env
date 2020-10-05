# debug

https://www.vogons.org/viewtopic.php?t=3944

~/opt/dosbox-0_74_3/src/dosbox -conf dosbox.conf

```
debug main.exe
```

- f5 = resume from break
- alt-pause = break at current instruction

```
heavylog
log 20000
# read key press
# https://en.wikipedia.org/wiki/INT_16H
bpint 16 10
```


