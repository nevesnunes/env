# +

- [perf-oneliners](./perf-oneliners.md)
- ~/code/snippets/sysadmin/linux-trouble-shooting-cheat-sheet.md
- https://www.brendangregg.com/USEmethod/use-linux.html
- https://medium.com/netflix-techblog/linux-performance-analysis-in-60-000-milliseconds-accc10403c55
- https://medium.com/netflix-techblog/netflix-at-velocity-2015-linux-performance-tools-51964ddb81cf

```bash
# top10
uptime
dmesg | tail
vmstat 1
mpstat -P ALL 1
pidstat 1
iostat -xz 1
free -m
sar -n DEV 1
sar -n TCP,ETCP 1
top

# host statistics
# - r > number of cpus => saturation
# - si, so > 0 => oom, swapping
vmstat -w 1
vmstat | sort -b -n -k2
# natural sort by given order of columns
vmstat | sort -b -n -k2b,2 -k1,1
# include disk, mem
vmstat -w -a -d | sort -b -n -k2b,2 -k1,1
# xref:
# - /proc/meminfo
# - /proc/stat
# - /proc/*/stat

# cpu utilization
# - single hot => single-threaded app hanging
mpstat -P ALL 1 # sum fields except "%idle" and "%iowait"
sar -P ALL
# cpu saturation
sar -q # "runq-sz" > CPU count
perf sched latency # avg, max
# cpu count
nproc --all

# process statistics
pidstat 1 # cpu
pidstat -l 1 -p $JAVA_PID
# include threads
pidstat -lt 1
# include disk, mem, page faults
pidstat -d -r 60 -T ALL
pidstat -d -l -r 1 -p $JAVA_PID
# On interrupt: prints averages
# Sort: `sort -b -n -k8 < pidstat.txt > pidstat-sort_by_mem.txt`

# all fds
lsof -p 1234
# filter common regular fds
lsof -a -d '^mem' -p 24090 | grep -v '\.\(jar\|log\|out\)$' > /java_heap_dumps/lsof_24090
lsof -a -d '^mem' -p 27380 | grep '^java' | grep -v '\.\(jar\|log\|out\)$' > /tmp/lsof_27380
# fds bound to port 22
lsof -a -i :22 -p 1234
# non-blocking, no dns resolution
lsof -a -i :22 -p 1234 -P -n

# skip blocking kernel calls
lsof -b
# skip dns resolution
lsof -n
# skip network sockets
lsof -X
ls -l /proc/15232/fd | wc -l

# Memory utilization
# Expect: buffers > 0, cached > 0
free -m # "Mem:" (main memory), "Swap:" (virtual memory)
sar -r # "%memused"
slabtop -s c # kmem slab allocator cache
grep Slab /proc/meminfo
# Memory saturation
vmstat 1 # "si"/"so" (swapping)
sar -B # "pgscank" + "pgscand" (scanning)
sar -W # per-process: 10th field (min_flt) from /proc/PID/stat for minor-fault rate
dmesg | grep killed # OOM killer

# Disk r/w kb/s
iostat -xz 1 # "%util"
sar -d
iotop # per process
pidstat -d
cat /proc/PID/sched # "se.statistics.iowait_sum"
# Disk saturation
iostat -xnz 1 # "avgqu-sz" > 1, or high "await" => saturation on non-parallel/non-virtual devices

# Average disk r/w Mb/s
#
# Parameters:
# - $3: # sectors read
# - $7: # sectors written
# - Given sector size = 512, then $x * 512 / 1024 = $x / 2
#
# References:
# - [LKML: Theodore Ts'o: Re: Why is SECTOR\_SIZE = 512 inside kernel ?](https://lkml.org/lkml/2015/8/17/269)
# - https://stackoverflow.com/questions/37248948/how-to-get-disk-read-write-bytes-per-second-from-proc-in-programming-on-linux
# - https://www.kernel.org/doc/Documentation/iostats.txt
# - https://www.kernel.org/doc/Documentation/block/stat.txt
awk '{print "r:"($3 / 2 / 1024)" w:"($7 / 2 / 1024)}' /sys/block/sda/stat

# i/o wait delays
# Note: compile ./foo with `-fno-omit-frame-pointer`
perf stat -e sched:sched_stat_iowait ./foo
# ||
perf record -e sched:sched_stat_iowait:r -f -R -c 1 ./foo
perf trace
# ||
perf report -g fractal --no-children

# identify candidate functions to optimize
# - https://perf.wiki.kernel.org/index.php/Perf_examples
perf report --sort comm,dso,symbol

# resource utilization
# vmstat + iostat
sar -A

# network interface throughtput
sar -n DEV 1
ip -s link
# network interface saturation
ifconfig # "overruns", "dropped"
netstat -s # "segments retransmited"
sar -n EDEV # *drop and *fifo metrics; /proc/net/dev, RX/TX "drop"

# TCP metrics
# Expect: retrans = 0
sar -n TCP,ETCP 1
# On interrupt: prints averages

# interactive
# - shift+m
# - shift+f, s, Enter, q
top
# batch mode - shows all entries
top -b
# split threads, each with unique pid
# java: convert to hex, then search in jstack output
#    e.g. bash: printf '0x%x\n' 25938
#    [xref] catalina.out
# -- https://backstage.forgerock.com/knowledge/kb/article/a39551500
# -- http://middlewaremagic.com/weblogic/?p=4884
# -- http://javaeesupportpatterns.blogspot.com/2012/02/prstat-linux-how-to-pinpoint-high-cpu.html
top -n 1 -H -p $pid
# || with thread start time
ps -p $pid -Lo pid,tid,lwp,nlwp,ruser,pcpu,lstart,stime,etime

# Filesystem partitions
df -h
fdisk -l
```

```bash
# - http://man7.org/linux/man-pages/man7/inode.7.html
# - https://linux.die.net/man/8/lsof
# - [How can lsof report a higher number of open files than what ulimit says should be allowed? \- Server Fault](https://serverfault.com/a/964752)
lsof | \
    awk '{print $1 " " $2}' | \
    sort | \
    uniq -c | \
    sort -n
lsof -d '^cwd,^err,^ltx,^mem,^mmap,^pd,^rtd,^txt' -a | \
    awk '/\d+/{print $2}' | \
    uniq | \
    xargs -I{} -d'\n' sh -c "lsof -p "{}" -d '^cwd,^err,^ltx,^mem,^mmap,^pd,^rtd,^txt' -a | wc -l" | \
    sort -n && \

# - [gnome terminal \- How to run ulimit in a script with other application \- Unix &amp; Linux Stack Exchange](https://unix.stackexchange.com/questions/379187/how-to-run-ulimit-in-a-script-with-other-application)
ulimit -Hn
sudo su user1 -c "ulimit -Hn"
```

# resources

```bash
# process resource limits
ulimit -a

# single cpu affinity
taskset -p -c 1 1234

# less cpu time
renice -n 19 -p 1234

# https://github.com/torden/cpulimit
cpulimit -l 25 -p 1234

# https://www.linux.org/docs/man8/turbostat.html
turbostat ls >/dev/null

# cgroups
# For multiple processes of same binary: https://scoutapm.com/blog/restricting-process-cpu-usage-using-nice-cpulimit-and-cgroups
sudo cgcreate -g cpu:/cpulimited
sudo cgset -r cpu.shares=512 cpulimited
sudo cgexec -g cpu:cpulimited ./foo
# For max cpu time in a given interval: https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/6/html/resource_management_guide/sec-cpu#sect-cfs
# e.g. 0.2 seconds out of 1 second
sudo cgset -r cpu.cfs_quota_us=200000 cpulimited
sudo cgset -r cpu.cfs_period_us=1000000 cpulimited
# Alternative: Using systemd slices: https://blog.monosoul.dev/2020/09/15/using-cgroups-to-make-local-test-runs-less-painful/
cat <<EOF >/usr/lib/systemd/system/foo.slice
[Unit]
Before=slices.target
[Slice]
CPUQuota=200%
MemoryMax=500M
EOF
cat <<EOF >/usr/lib/systemd/system/foo.service
[Service]
Slice=foo.slice
EOF

# suspend and resume process
kill -TSTP $pid
kill -CONT $pid
```

### systemd

```bash
man systemd.resource-control
man systemd.slice
sudo systemctl edit --force user-1234.slice
```

```ini
[Slice]
CPUQuota=10%
```

# eBPF

```bash
# top10
execsnoop  # New processes (via exec(2)); table
opensnoop  # Files opened; table
ext4slower # Slow filesystem I/O; table
biolatency # Disk I/O latency histogram; heat map
biosnoop   # Disk I/O per-event details; table, offset heat map
cachestat  # File system cache statistics; line charts
tcplife    # TCP connections; table, distributed graph
tcpretrans # TCP retransmissions; table
runqlat    # CPU scheduler latency; heat map
profile    # CPU stack trace samples; flame graph

# exit reason
exitsnoop
# syscall trace
perf trace -e 'syscalls:sys_enter_*kill'
# signal stacks
bpftrace -e 't:signal:signal_generate /comm == "slack"/ { printf("%d, %s%s\n", args->sig, kstack, ustack); }'
```

- https://github.com/iovisor/bcc/blob/master/docs/tutorial.md

# `strace` for mac and bsd

```bash
ktrace -p PID
kdump -l
```

# detecting multithreading

```sh
strace -f -e trace=clone git grep 'class TestDefaultNameNodePort' 2>&1 | grep -c '] +++ exited with '
# 8

strace -f -e trace=clone grep -rI --exclude=.git 'class TestDefaultNameNodePort' *  2>&1 | grep -c '] +++ exited with '
# 0
```

- https://news.ycombinator.com/item?id=7167897

# case studies

- [A Kernel Dev&\#39;s Approach to Improving Mutt&\#39;s Performance \- Part 1](https://www.codeblueprint.co.uk/2016/12/19/a-kernel-devs-approach-to-improving.html)
