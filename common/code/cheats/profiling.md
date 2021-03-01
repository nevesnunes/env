# +

```bash
# - https://medium.com/netflix-techblog/linux-performance-analysis-in-60-000-milliseconds-accc10403c55
# - https://medium.com/netflix-techblog/netflix-at-velocity-2015-linux-performance-tools-51964ddb81cf
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
```

```bash
# host statistics
# - r > number of cpus => saturation
# - si, so > 0 => oom, swapping
vmstat 1
vmstat | sort -b -n -k2
# natural sort by given order of columns
vmstat | sort -b -n -k2b,2 -k1,1
# include disk, mem
vmstat -a -d | sort -b -n -k2b,2 -k1,1
# xref:
# - /proc/meminfo
# - /proc/stat
# - /proc/*/stat

# per cpu
# - single hot => single-threaded app hanging
mpstat -P ALL 1

# process statistics
pidstat 1
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

slabtop
# ||
grep Slab /proc/meminfo

nproc --all

dmesg | tail

# Expect: buffers > 0, cached > 0
free -m

# avgqu-sz > 1 => saturation on non-parallel/non-virtual devices
iostat -xz 1

ulimit -a

# resource utilization
# vmstat + iostat
sar -A
# network interface throughtput
sar -n DEV 1
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
# single process
taskset -p -c 1 45678

# less cpu time
renice -n 19 -p 1234

# https://github.com/torden/cpulimit
cpulimit -l 25 -p 1234

# cgroups
# For multiple processes of same binary: https://scoutapm.com/blog/restricting-process-cpu-usage-using-nice-cpulimit-and-cgroups
sudo cgcreate -g cpu:/cpulimited
sudo cgset -r cpu.shares=512 cpulimited
sudo cgexec -g cpu:cpulimited ./foo
# For max cpu time in a given interval: https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/6/html/resource_management_guide/sec-cpu#sect-cfs
# e.g. 0.2 seconds out of 1 second
sudo cgset -r cpu.cfs_quota_us=200000 cpulimited
sudo cgset -r cpu.cfs_period_us=1000000 cpulimited

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

# `strace` for mac and bsd

```bash
ktrace -p PID
kdump -l
```
