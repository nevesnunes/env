# Fault injection

- use byte value of surrounding data to bypass input sanitization
- apply faults at elements separated by delimiters to reduce test cases
- apply deltas to common buffer sizes (e.g. k^2, k^10, -+20)

### Syscalls

```bash
strace -e mprotect -e fault=all:error=EPERM:when=1 \
    pwd
strace -e inject=write:delay_exit=100000 -e write -o/dev/null \
    dd if=/dev/zero of=/dev/null bs=1M count=10
```

- Modern strace - Dmitry Levin
- Can strace make you fail? - Dmitry Levin

### Network

```bash
# packet loss
iptables -A INPUT -m statistic --mode random --probability 0.1 -j DROP
iptables -A OUTPUT -m statistic --mode random --probability 0.1 -j DROP
# network latency, limited bandwidth, and packet loss
tc qdisc add dev eth0 root netem delay 250ms loss 10% rate 1mbps
# network latency w/ jitter
tc qdisc add dev eth0 root netem delay 50ms 20ms distribution normal
# re-order, duplicate, and corrupt packets.
tc qdisc add dev eth0 root netem reorder 0.02 duplicate 0.05 corrupt 0.01
```

- https://bravenewgeek.com/sometimes-kill-9-isnt-enough/

### OS

- https://docs.kernel.org/fault-injection/fault-injection.html

### Feedback based fuzzing

```fasm
; store old reg values
lea rsp, [rsp-98h]
mov [rsp+a0h+var_a0], rdx
mov [rsp+a0h+var_98], rcx
mov [rsp+a0h+var_90], rax
; instrumentation
mov rcx, 0be80h
call __afl_maybe_log
; restore old reg values
mov rax, [rsp+a0h+var_90]
mov rcx, [rsp+a0h+var_98]
mov rdx, [rsp+a0h+var_a0]
lea rsp, [rsp+98h]
```

- without recompilation
    - qemu target
        - https://www.mathyvanhoef.com/2015/09/csaw-ctf-solving-reversing-wyvern-500.html
        ```bash
        afl-fuzz -Q -i indir -o sync_dir -M fuzzer01 ./wyvern
        afl-fuzz -Q -i indir -o sync_dir -S fuzzer02 ./wyvern
        ```
    - https://github.com/GJDuck/e9afl
- redirect socket to stdin/stdout
    - https://lolware.net/blog/2015-04-28-nginx-fuzzing/
    ```bash
    echo 'GET / HTTP/1.1 [...]' > testcases/in.txt
    LD_PRELOAD=preeny/Linux_x86_64/desock.so afl-fuzz -i testcases -o findings ./nginx
    ```
- emulation
    - https://hackernoon.com/afl-unicorn-part-2-fuzzing-the-unfuzzable-bea8de3540a5

# Directory busting

```bash
grep -v '%' ~/opt/dirbustlist/dirbuster/directory-list-2.3-medium.txt > /tmp/wordlist
gobuster dir --url http://vulnerable --wordlist /tmp/wordlist
# ||
gobuster dir --url http://vulnerable --wordlist ~/opt/zap-extensions/tree/master/addOns/directorylistv2_3/src/main/zapHomeFiles/fuzzers/dirbuster/directory-list-2.3-medium.txt
# ||
gobuster dir --url http://vulnerable --wordlist SecLists/Discovery/Web_Content/raft-large-files.txt
for i in files directories; do gobuster dir -t 30 -u http://vulnerable -w SecLists/Discovery/Web_Content/raft-medium-$i.txt; done

# Specific file extensions
gobuster -x .php,.html
gobuster -x .js,.json
gobuster -x .aspx

# Boolean-based filter by response length
ffuf -c -w ~/code/guides/ctf/SecLists/Passwords/Leaked-Databases/rockyou-75.txt -u 'https://foo?FUZZ' -fs 123
ffuf -c -w ~/code/guides/ctf/SecLists/Passwords/Leaked-Databases/rockyou-75.txt -u 'https://foo?bar=FUZZ' -fs 234
```

- https://github.com/zaproxy/zap-extensions/tree/beta/src/org/zaproxy/zap/extension/bruteforce

# Parameter discovery

- [GitHub \- Sh1Yo/x8: Hidden parameters discovery suite](https://github.com/sh1yo/x8)
    - [Parameter discovery tools comparison](https://4rt.one/blog/1.html)

# Wordlists

- https://wordlists.assetnote.io/
- [Contextual Content Discovery: You've forgotten about the API endpoints &\#8211; Assetnote](https://blog.assetnote.io/2021/04/05/contextual-content-discovery/)
    - https://github.com/assetnote/kiterunner
    - https://wordlists-cdn.assetnote.io/data/kiterunner/swagger-wordlist.txt
    - https://wordlists-cdn.assetnote.io/data/kiterunner/routes-large.kite.tar.gz
- https://github.com/danielmiessler/SecLists
- https://github.com/allyshka/dirbustlist/tree/master/dirbuster
- https://github.com/zaproxy/zap-extensions/tree/master/addOns/directorylistv2_3/src/main/zapHomeFiles/fuzzers/dirbuster
