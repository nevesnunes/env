# +

- [Map \- Unprotect Project](https://search.unprotect.it/map)
- https://github.com/CheckPointSW/Evasions
- https://github.com/seifreed/awesome-sandbox-evasion

# anti-debugging

### LD_PRELOAD

- https://haxelion.eu/article/LD_NOT_PRELOADED_FOR_REAL/

### ptrace(PTRACE_TRACEME, 0, 0)

debugger bypass:

```gdb
catch syscall ptrace
commands 1
set $rax = 0
continue
end
```

library hook:

```c
long ptrace(int request, int pid, void *addr, void *data) {
    return 0;
}
```

```bash
env LD_PRELOAD=ptrace.so ./foo
```


