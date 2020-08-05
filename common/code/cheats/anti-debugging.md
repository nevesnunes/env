# anti-debugging

https://haxelion.eu/article/LD_NOT_PRELOADED_FOR_REAL/

## ptrace(PTRACE_TRACEME, 0, 0)

debugger bypass

```gdb
catch syscall ptrace
commands 1
set ($eax) = 0
continue
end
```

library hook

```c
int ptrace(int i, int j, int k, int l) {
    return 0;
}
// ||
long ptrace(int request, int pid, void *addr, void *data) {
    return 0;
}
```

```bash
env LD_PRELOAD=ptrace.so ./foo
```

