# Methodology

- [CodenomiCON 2010 \- Charlie Miller \- part \#1 \- An Analysis of Fuzzing 4 Products with five lines\.\.\. \- YouTube](https://www.youtube.com/watch?v=Xnwodi2CBws)
    - use valgrind to find subset of test cases with maximum coverage
    - catch buffer overflows with jemalloc
    - take unique eip from crashes, compare exploitable vs. non-exploitable cases
    - mutation
        ```python
        num_writes = random.randrange(math.ceil((float(len(buf)) / fuzz_factor))) + 1
        for j in range(num_writes):
            rbyte = random.randrange(256)
            rn = random.randrange(len(buf))
            buf[rn] = "%c" % rbyte
        ```
- [Fuzzing Like A Caveman \- The Human Machine Interface](https://h0mbre.github.io/Fuzzing-Like-A-Caveman/)
    - given source code: recompile with asan
        ```bash
        cc -fsanitize=address -ggdb -o foo foo.c
        ```
- [Intro to Rust Fuzzing \| anthok](https://www.anthok.com/posts/intro-to-rust-fuzzing/)
- [GitHub \- mykter/afl\-training: Exercises to learn how to fuzz with American Fuzzy Lop](https://github.com/mykter/afl-training)

### Targets

- [fuzzing/good\-fuzz\-target\.md at master · google/fuzzing · GitHub](https://github.com/google/fuzzing/blob/master/docs/good-fuzz-target.md)
- [Picking a Target \| nedwill’s security blog](https://nedwill.github.io/blog/jekyll/update/2019/04/08/picking-a-target.html)
- [2022 CWE Top 25 Most Dangerous Software Weaknesses](https://cwe.mitre.org/top25/archive/2022/2022_cwe_top25.html)
- [List of codecs \- Wikipedia](https://en.wikipedia.org/wiki/List_of_codecs)
- [Comparison of file systems \- Wikipedia](https://en.wikipedia.org/wiki/Comparison_of_file_systems)

# Case studies

- [Hacking TMNF: Part 1 \- Fuzzing the game server \| bricked\.tech](https://blog.bricked.tech/posts/tmnf/part1/)
- [The search for animal 0\-day: From fuzzing Apache httpd server to CVE\-2017\-7668 and a $1500 bounty](https://animal0day.blogspot.com/2017/07/from-fuzzing-apache-httpd-server-to-cve.html)
- [Root Cause Analysis \– Integer Overflows \| Corelan Cybersecurity Research](https://www.corelan.be/index.php/2013/07/02/root-cause-analysis-integer-overflows/)

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

### Coverage / Feedback based fuzzing

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
- [GitHub \- google/honggfuzz: Security oriented software fuzzer\. Supports evolutionary, feedback\-driven fuzzing based on code coverage \(SW and HW based\)](https://github.com/google/honggfuzz)
- [libFuzzer – a library for coverage\-guided fuzz testing\. &\#8212; LLVM 16\.0\.0git documentation](https://llvm.org/docs/LibFuzzer.html)
    - [fuzzing/libFuzzerTutorial\.md at master · google/fuzzing · GitHub](https://github.com/google/fuzzing/blob/master/tutorial/libFuzzerTutorial.md)

### Mutation based fuzzing

- [Aki Helin / radamsa · GitLab](https://gitlab.com/akihe/radamsa)

### System fuzzing

- [oss\-fuzz/infra/experimental/SystemSan at master · google/oss\-fuzz · GitHub](https://github.com/google/oss-fuzz/tree/master/infra/experimental/SystemSan)

# Directory busting

- burp
    - Scope > Target Scope > Host / IP range > add target domains
    - Site Map > select entry, open context menu, select "Send to Intruder"
    - Positions > add variable `$foo$` as request header "Host" value, "Attack type" = "Cluster bomb"
        - Payloads > "Payload type" = "Simple list", add subdomains
        - check: http 200, https 301...
        - extract links from resources (.html, .js), wayback machine...
    - Positions > add variable `/$foo$` as host, "Attack type" = "Sniper"
        - Payloads > "Payload type" = "Simple list", add wordlist, limit concurrent requests to 100
        - check: http 200, https 301...
    - [Bug Bounty 101: \#18 \- Approaching a Public Target \(Pinterest\) \- YouTube](https://www.youtube.com/watch?v=LeQ8RIK6OpE)

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

- [Param Miner \- PortSwigger](https://portswigger.net/bappstore/17d2949a985c4b7ca092728dba871943)
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
- https://github.com/fuzzdb-project/fuzzdb
