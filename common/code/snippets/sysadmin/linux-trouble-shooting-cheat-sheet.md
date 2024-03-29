# Linux Trouble Shooting Cheat Sheet

Published at 2020-05-05 | Last Update 2020-05-05

  - [1. Physical Resources](#1-physical-resources)
      - [1.1 CPU](#11-cpu)
      - [1.2 Memory](#12-memory)
      - [1.3 Network Interfaces](#13-network-interfaces)
      - [1.4 Storage Device I/O](#14-storage-device-io)
      - [1.5 Storage Capacity](#15-storage-capacity)
      - [1.6 Storage Controller](#16-storage-controller)
      - [1.7 Network Controller](#17-network-controller)
      - [1.8 CPU Interconnect](#18-cpu-interconnect)
      - [1.9 Memory Interconnect](#19-memory-interconnect)
      - [1.10 I/O Interconnect](#110-io-interconnect)
  - [2. Software Resources](#2-software-resources)
      - [2.1 Kernel mutex](#21-kernel-mutex)
      - [2.2 User mutex](#22-user-mutex)
      - [2.3 Task Capacity](#23-task-capacity)
      - [2.4 File descriptors](#24-file-descriptors)
  - [3. Tracing](#3-tracing)
      - [3.1 `trace-cmd` (ftrace)](#31-trace-cmd-ftrace)

-----

Contents from the wonderful book ***Systems Performance***: Enterprise and the Cloud, and author’s website: [USE Method: Linux Performance Checklist](http://www.brendangregg.com/USEmethod/use-linux.html).

Will be updated according to my own needs.

# 1\. Physical Resources

## 1.1 CPU

    +-----+-------------+----------------------------------------------------------------------------------+
    |     |             | 1. per CPU                                                                       |
    |     |             |     * `mpstat -P ALL 1`: `%idle`                                                 |
    |     |             |     * `sar -P ALL`     : `%idle`                                                 |
    |     |             | 2. system wide                                                                   |
    |     |             |     * `vmstat 1`  : `id`                                                         |
    |     |             |     * `sar -u 1 5`: `%idle`                                                      |
    |     |             |     * `dstat -c`  : `idl`                                                        |
    |     |             | 3. per process                                                                   |
    |     | Utilization |     * `top`       : `%CPU`                                                       |
    |     |             |     * `htop`      : `%CPU`                                                       |
    |     |             |     * `ps -o pcpu`: `%CPU`                                                       |
    |     |             |     * `pidstat 1` : `CPU`                                                        |
    |     |             | 4. per kernel thread                                                             |
    |     |             |     * `top` : `VIRT`                                                             |
    |     |             |     * `hotp`: press `K` to sort, see `VIRT` column                               |
    |     +-------------+----------------------------------------------------------------------------------|
    |     |             | 1. system wide                                                                   |
    | CPU |             |     * `vmstat 1`  : column `r` > CPU count                                       |
    |     |             |     * `sar -q 1 5`: column `runq-sz` > CPU count                                 |
    |     |             | 2. per process                                                                   |
    |     | Saturation  |     * `cat /proc/<pid>/schedstat`: 2nd column (`sched_info`, `run_delay`)        |
    |     |             |     * `getdelays.c`              : CPU                                           |
    |     |             |     * `perf sched latency`       : show avg and max delay per schedule           |
    |     |             |     * dynamic tracing, e.g. SystemTap `schedtimes.stp` queued (us)               |
    |     +-------------+----------------------------------------------------------------------------------|
    |     |             | * `perf` (LPE): if processor-specific error events (CPC) are available, e.g.     |
    |     | Errors      |   AMD64's Single-bit ECC Errors                                                  |
    |     |             |                                                                                  |
    +-----+-------------+----------------------------------------------------------------------------------+

Explainations:

    `sar -P ALL`: `%idle`

stands for: executing `sar -P ALL`, then check the `%idle` column in the output. The others are similar.

## 1.2 Memory

    +--------+-------------+-------------------------------------------------------------------------------+
    |        |             | 1. system wide                                                                |
    |        |             |     * `free -m`     : `Mem`, `Swap`                                           |
    |        |             |     * `vmstat 1`    : `swpd`, `free`                                          |
    |        |             |     * `sar -r 1 5`  : `%memused`                                              |
    |        | Utilization |     * `dstat -m`    : `free`                                                  |
    |        |             |     * `slabtop -s c`: sort by cache size                                      |
    |        |             | 2. per process                                                                |
    |        |             |     * `top`/`htop`  : `RES` (resident memory), `VIRT` (virtual memory), `MEM` |
    |        +-------------+-------------------------------------------------------------------------------|
    |        |             | 1. system wide                                                                |
    |        |             |     * `vmstat 1`  : `si`/`so` (swap)                                          |
    |        |             |     * `sar -B 1 5`: `pgscank` + `pgscand` (scanning)                          |
    |        |             |     * `sar -W 1 5`: `pswpin/s` + `pswpout/s`                                  |
    | Memory | Saturation  | 2. per process                                                                |
    |        |             |     * `getdelays.c`                             : SWAP                        |
    |        |             |     * `cat /proc/<pid>/stat | awk '{print $10}'`: stands for minor fault rate |
    |        |             |       (`min_flt`), or dynamic tracing                                         |
    |        |             |     * `dmesg -T | grep killed`                  : OOM killer                  |
    |        +-------------+-------------------------------------------------------------------------------|
    |        |             | * `dmesg`: for physical failures                                              |
    |        | Errors      | * dynamic tracing, e.g. `uprobes` for failed `malloc` (DTrace, SystemTap)     |
    |        |             |                                                                               |
    +--------+-------------+-------------------------------------------------------------------------------+

## 1.3 Network Interfaces

    +------------+-------------+---------------------------------------------------------------------------+
    |            |             | * `ip -s link`    : statistics                                            |
    |            | Utilization | * `sar -n DEV 1 5`: real time stats, e.g. rx pkts/s, rx bytes/s           |
    |            |             |                                                                           |
    |            +-------------+---------------------------------------------------------------------------|
    |            |             | * `ifconfig`         : overruns, dropped                                  |
    |  Network   |             | * `netstat -s`       : protocol statistics, e.g. IP, ICMP, UDP, TCP       |
    | Interfaces | Saturation  | * `sar -n EDEV 1 5`  : real time interface errors                         |
    |            |             | * `cat /proc/net/dev`: RX/TX drop                                         |
    |            |             | * dynamic tracing of other TCP/IP stack queueing                          |
    |            +-------------+---------------------------------------------------------------------------|
    |            |             | * `ifconfig`                                   : errors, dropped          |
    |            |             | * `netstat -i`                                 : RX-ERR, TX-ERR           |
    |            |             | * `ip -s link`                                 : errors                   |
    |            | Errors      | * `sar -n EDEV 1 5`                            : rxerr/s, txerr/s         |
    |            |             | * `cat /proc/net/dev`                          : errs, drop               |
    |            |             | * `cat /sys/class/net/<interface>/statistics/*`:                          |
    |            |             | * dynamic tracing of driver function returns                              |
    +------------+-------------+---------------------------------------------------------------------------+

## 1.4 Storage Device I/O

    +------------+-------------+---------------------------------------------------------------------------+
    |            |             | 1. system wide                                                            |
    |            |             |     * `iostat -xz 1`: `%util`                                             |
    |            |             |     * `sar -d 1 5`  : `%util`                                             |
    |            | Utilization | 2. per process                                                            |
    |            |             |     * `iotop`                                                             |
    |            |             |     * `cat /proc/<pid>/sched`                                             |
    |  Storage   +-------------+---------------------------------------------------------------------------|
    | Device I/O |             | * `iostat -xz 1`: `avgqu-sz` > 1, or high await                           |
    |            |             | * `sar -d 1 5`  : `%util`                                                 |
    |            | Saturation  | * LPE block probes for queue length/latency                               |
    |            |             | * dynamic/static tracing of I/O subsystem (including LPE block probes)    |
    |            |             |                                                                           |
    |            +-------------+---------------------------------------------------------------------------|
    |            |             | * `cat /sys/devices/../ioerr_cnt`                                         |
    |            | Errors      | * `smartctl`                                                              |
    |            |             | * dynamic/static tracing of I/O subsystem response codes                  |
    +------------+-------------+---------------------------------------------------------------------------+

## 1.5 Storage Capacity

    +----------+-------------+-----------------------------------------------------------------------------+
    |          |             | * `swapon -s`                                                               |
    |          |             | * `free`                                                                    |
    |          | Utilization | * `cat /proc/meminfo`: `SwapTotal`, `SwapFree`                              |
    |          |             | * `df -h`            : `Size`, `Use%`                                       |
    |          |             |                                                                             |
    |          +-------------+-----------------------------------------------------------------------------|
    |          |             |                                                                             |
    | Storage  | Saturation  | No sure this one makes sense —— once it's full, `ENOSPC`.                   |
    | Capacity |             |                                                                             |
    |          +-------------+-----------------------------------------------------------------------------|
    |          |             | 1. file system                                                              |
    |          |             |     * `strace` for `ENOSPC`                                                 |
    |          | Errors      |     * dynamic tracing for `ENOSPC`                                          |
    |          |             |     * `/var/log/messages` errs                                              |
    |          |             |     * application log errors                                                |
    +----------+-------------+-----------------------------------------------------------------------------+

## 1.6 Storage Controller

    +------------+-------------+----------------------------------------------------------------------------+
    |            |             |                                                                            |
    |            | Utilization | * `iostat -xz 1`: sum devices and compare to known IOPS/tput limits/card   |
    |            |             |                                                                            |
    |            +-------------+----------------------------------------------------------------------------|
    |  Storage   |             |                                                                            |
    | Controller | Saturation  | see storage device I/O saturation in the above.                            |
    |            |             |                                                                            |
    |            +-------------+----------------------------------------------------------------------------|
    |            |             |                                                                            |
    |            | Errors      | see storage device I/O errors in the above.                                |
    |            |             |                                                                            |
    +------------+-------------+----------------------------------------------------------------------------+

## 1.7 Network Controller

    +------------+-------------+---------------------------------------------------------------------------+
    |            |             | * `ip -s link`                                                            |
    |            |             | * `sar -n DEV 1 5`                                                        |
    |            | Utilization | * `cat /proc/net/dev`                                                     |
    |            |             | * supplementary by myself:                                                |
    |            |             |     * `iftop`                                                             |
    |  Network   +-------------+---------------------------------------------------------------------------|
    | Controller |             |                                                                           |
    |            | Saturation  | see network interfaces, saturation in the above.                          |
    |            |             |                                                                           |
    |            +-------------+---------------------------------------------------------------------------|
    |            |             |                                                                           |
    |            | Errors      | see network interfaces, errors.                                           |
    |            |             |                                                                           |
    +------------+-------------+---------------------------------------------------------------------------+

## 1.8 CPU Interconnect

    +--------------+-------------+-------------------------------------------------------------------------+
    |              |             |                                                                         |
    |              | Utilization | * LPE (CPC) for CPU interconnect ports, tput/max.                       |
    |              |             |                                                                         |
    |              +-------------+-------------------------------------------------------------------------|
    |    CPU       |             |                                                                         |
    | Interconnect | Saturation  | * LPE (CPC) for stall cycles.                                           |
    |              |             |                                                                         |
    |              +-------------+-------------------------------------------------------------------------|
    |              |             |                                                                         |
    |              | Errors      | * LPE (CPC) for whatever is available.                                  |
    |              |             |                                                                         |
    +--------------+-------------+-------------------------------------------------------------------------+

## 1.9 Memory Interconnect

    +--------------+-------------+-------------------------------------------------------------------------+
    |              |             | * LPE (CPC) for for memory busses, tput/max                             |
    |              |             | * CPI >= N, e.g. N=10                                                   |
    |              | Utilization | * CPC local vs. remote counters                                         |
    |              |             |                                                                         |
    |              +-------------+-------------------------------------------------------------------------|
    |   Memory     |             |                                                                         |
    | Interconnect | Saturation  | * LPE (CPC) for stall cycles.                                           |
    |              |             |                                                                         |
    |              +-------------+-------------------------------------------------------------------------|
    |              |             |                                                                         |
    |              | Errors      | * LPE (CPC) for whatever is available.                                  |
    |              |             |                                                                         |
    +--------------+-------------+-------------------------------------------------------------------------+

## 1.10 I/O Interconnect

    +--------------+-------------+-------------------------------------------------------------------------+
    |              |             | * LPE (CPC) for tput/max                                                |
    |              | Utilization | * inference via known tput from iostat/ip/...                           |
    |              |             |                                                                         |
    |              +-------------+-------------------------------------------------------------------------|
    |     I/O      |             |                                                                         |
    | Interconnect | Saturation  | * LPE (CPC) for stall cycles.                                           |
    |              |             |                                                                         |
    |              +-------------+-------------------------------------------------------------------------|
    |              |             |                                                                         |
    |              | Errors      | * LPE (CPC) for whatever is available.                                  |
    |              |             |                                                                         |
    +--------------+-------------+-------------------------------------------------------------------------+

# 2\. Software Resources

## 2.1 Kernel mutex

    +--------+-------------+--------------------------------------------------------------------------------+
    |        |             |                                                                                |
    |        |             | * `cat /proc/lock_stat` (With `CONFIG_LOCK_STATS=y`): "holdtime-totat" /       |
    |        | Utilization |   "acquisitions" (also see "holdtime-min", "holdtime-max") [8]                 |
    |        |             | * dynamic tracing of lock functions or instructions (maybe)                    |
    |        |             |                                                                                |
    |        +-------------+--------------------------------------------------------------------------------|
    |        |             | * `/proc/lock_stat` (With `CONFIG_LOCK_STATS=y`): "waittime-total",            |
    | Kernel |             |   "contentions" (also see "waittime-min", "waittime-max")                      |
    | Mutex  | Saturation  | * dynamic tracing of lock functions or instructions (maybe)                    |
    |        |             | * spinning shows up with profiling (`perf record -a -g -F 997` ...,            |
    |        |             |   oprofile, dynamic tracing)                                                   |
    |        +-------------+--------------------------------------------------------------------------------|
    |        |             | * dynamic tracing (eg, recusive mutex enter)                                   |
    |        | Errors      | * other errors can cause kernel lockup/panic, debug with kdump/crash           |
    |        |             |                                                                                |
    +--------+-------------+--------------------------------------------------------------------------------+

## 2.2 User mutex

    +--------+-------------+--------------------------------------------------------------------------------+
    |        |             | * `valgrind --tool=drd --exclusive-threshold=...` (held time)                  |
    |        | Utilization | * dynamic tracing of lock to unlock function time                              |
    |        |             |                                                                                |
    |        +-------------+--------------------------------------------------------------------------------|
    | User   |             | * `valgrind --tool=drd` to infer contention from held time                     |
    | Mutex  | Saturation  | * dynamic tracing of synchronization functions for wait time                   |
    |        |             | * profiling (oprofile, PEL, ...) user stacks for spins                         |
    |        +-------------+--------------------------------------------------------------------------------|
    |        |             | * `valgrind --tool=drd` various errors                                         |
    |        | Errors      | * dynamic tracing of `pthread_mutex_lock()` for `EAGAIN`, `EINVAL`,            |
    |        |             |   `EPERM`, `EDEADLK`, `ENOMEM`, `EOWNERDEAD`, ...                              |
    +--------+-------------+--------------------------------------------------------------------------------+

## 2.3 Task Capacity

    +----------+-------------+------------------------------------------------------------------------------+
    |          |             | * `top`/`htop`: "Tasks" (current)                                            |
    |          | Utilization | * `sysctl kernel.threads-max`                                                |
    |          |             | * `/proc/sys/kernel/threads-max` (max)                                       |
    |          +-------------+------------------------------------------------------------------------------|
    |          |             |                                                                              |
    |   Task   |             | * threads blocking on memory allocation                                      |
    | Capacity | Saturation  | * `sar -B`: at this point the page scanner ("pgscan*") should be running,    |
    |          |             |   else examine using dynamic tracing                                         |
    |          |             |                                                                              |
    |          +-------------+------------------------------------------------------------------------------|
    |          |             | * "can't fork()" errors                                                      |
    |          | Errors      | * user-level threads: pthread_create() failures with EAGAIN, EINVAL, ...     |
    |          |             | * kernel: dynamic tracing of kernel_thread() ENOMEM                          |
    +----------+-------------+------------------------------------------------------------------------------+

## 2.4 File descriptors

    +-------------+-------------+---------------------------------------------------------------------------+
    |             |             | 1. system-wide                                                            |
    |             |             |     * `sar -v`, "file-nr" vs `/proc/sys/fs/file-max`                      |
    |             |             |     * `dstat --fs`: "files"                                               |
    |             | Utilization |     * `cat /proc/sys/fs/file-nr`                                          |
    |             |             | 2. per-process                                                            |
    |             |             |     * `ls /proc/<PID>/fd | wc -l` vs `ulimit -n`                          |
    |             |             |                                                                           |
    |    File     +-------------+---------------------------------------------------------------------------|
    |             |             |                                                                           |
    | Descriptors |             | does this make sense? I don't think there is any queueing or blocking,    |
    |             | Saturation  | other than on memory allocation.                                          |
    |             |             |                                                                           |
    |             +-------------+---------------------------------------------------------------------------|
    |             |             |                                                                           |
    |             | Errors      | * strace errno == EMFILE on syscalls returning fds (eg, open(),           |
    |             |             |   accept(), ...).                                                         |
    +-------------+-------------+---------------------------------------------------------------------------+

# 3\. Tracing

## 3.1 `trace-cmd` (ftrace)

Trace kernel function calls.

    $ trace-cmd record -p function_graph -P <PID>
    $ trace-cmd record -e sched:sched_switch <CMD>
    $ trace-cmd record -p function_graph -l do_IRQ -e irq_handler_entry sleep 10
    $ trace-cmd record -e kmalloc_node -f 'bytes_req > 1000'
    $ trace-cmd report
    
    # functions could be traced
    $ trace-cmd list -f
    
    # events could be traced
    $ cat /sys/kernel/debug/tracing/available_events
    
    # record events
    #   * -e [ <event> | <subsystem> | <subsystem:even> | all ]
    $ trace-cmd record -e sched:sched_switch

references:

1.  [ftrace: trace your kernel functions\!](https://jvns.ca/blog/2017/03/19/getting-started-with-ftrace/)
2.  [LWN.net: trace-cmd: A front-end for Ftrace](https://lwn.net/Articles/410200/)

[« Monitoring Network Stack](/blog/monitoring-network-stack/) [\[笔记\] Systems Performance: Enterprise and the Cloud (Prentice Hall, 2013) »](/blog/systems-performance-notes-zh/)
