# +

- [GitHub \- brendangregg/bpf\-perf\-workshop](https://github.com/brendangregg/bpf-perf-workshop)
- [proctrace \- a high level profiler for process lifecycle events &middot; Tinkering](https://tinkering.xyz/proctrace/)
    - filtering threads vs. processes
- [Uprobe\-tracer: Uprobe\-based Event Tracing &mdash; The Linux Kernel  documentation](https://www.kernel.org/doc/html/v5.0/trace/uprobetracer.html)

```sh
# Trace libc calls 
# - /!\ need to scope glob, use dynamic syms: ~/bin/libctrace.sh
sudo bpftrace -e '
BEGIN { @start = nsecs; } 
uprobe:/usr/lib64/libc-2.33.so:* /@start != 0 && pid == cpid/ { 
    printf("%-08d %-04d %s\n", tid, (nsecs - @start) / 1000000, func); 
}' -c '/bin/sleep 2'

# Trace user functions
sudo bpftrace -e 'uprobe:/bin/bash:readline {
    printf("%s\n", ustack(perf, 10));
}'

# C++
readelf -Ws /foo | grep methodName
#69: 00000000004007ee    30 FUNC    WEAK   DEFAULT   14 _ZN6BigApp10methodNameEv
bpftrace -e 'uprobe:/foo:_ZN6BigApp10methodNameEv { printf("1"); }'
bpftrace -e 'uprobe:/foo:"function signature" { printf("1"); }'
```

```sh
# Files opened by process
bpftrace -e 'tracepoint:syscalls:sys_enter_open { printf("%s %s\n", comm, str(args->filename)); }'

# Syscall count by program
bpftrace -e 'tracepoint:raw_syscalls:sys_enter { @[comm] = count(); }'

# Read bytes by process:
bpftrace -e 'tracepoint:syscalls:sys_exit_read /args->ret/ { @[comm] = sum(args->ret); }'

# Read size distribution by process:
bpftrace -e 'tracepoint:syscalls:sys_exit_read { @[comm] = hist(args->ret); }'

# Show per-second syscall rates:
bpftrace -e 'tracepoint:raw_syscalls:sys_enter { @ = count(); } interval:s:1 { print(@); clear(@); }'

# Trace disk size by process
bpftrace -e 'tracepoint:block:block_rq_issue { printf("%d %s %d\n", pid, comm, args->bytes); }'

# Count page faults by process
bpftrace -e 'software:faults:1 { @[comm] = count(); }'

# Count LLC cache misses by process name and PID (uses PMCs):
bpftrace -e 'hardware:cache-misses:1000000 { @[comm, pid] = count(); }'

# Profile user-level stacks at 99 Hertz, for PID 189:
bpftrace -e 'profile:hz:99 /pid == 189/ { @[ustack] = count(); }'

# Files opened, for processes in the root cgroup-v2
bpftrace -e 'tracepoint:syscalls:sys_enter_openat /cgroup == cgroupid("/sys/fs/cgroup/unified/mycg")/ { printf("%s\n", str(args->filename)); }'
```

- [GitHub \- iovisor/bpftrace: High\-level tracing language for Linux eBPF](https://github.com/iovisor/bpftrace)
    - [bpftrace/tutorial\_one\_liners\.md at master · iovisor/bpftrace · GitHub](https://github.com/iovisor/bpftrace/blob/master/docs/tutorial_one_liners.md)
    - [bpftrace/reference\_guide\.md at master · iovisor/bpftrace · GitHub](https://github.com/iovisor/bpftrace/blob/master/docs/reference_guide.md)
