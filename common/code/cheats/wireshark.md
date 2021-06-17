# +

- https://wiki.wireshark.org/Tools
- https://paulcimino.com/customizing-wireshark-for-malware-analysis/

# Filters

```
ip.addr==1.2.3.4 and http.request.method==GET
http.request.method==CONNECT

ip.host matches "1.2.3." && ip.host matches "^2..\."
not (ip.host matches "^192") and not arp

tcp.flags.fin eq 1 or tcp.flags.reset eq 1
ip.host matches "\.123$"

tcp matches "(?i)soap.*action"

((usb.transfer_type == 0x01) && (frame.len == 73)) && !(usb.capdata == 00:00:00:00:00:00:00:00)
```

```bash
tshark -p -n -i eno1 -f "tcp port 40000" -a files:10 -b files:10 -b filesize:1024 -w /var/log/tshark/tcpds
tshark -Y http.request.uri -r foo.pcap
tshark -T json -r foo.pcap

tshark -r usb.pcap -T fields -e usb.bus_id -e usb.device_address -e usb.idVendor -e usb.idProduct "usb.idVendor > 0" 2>/dev/null
tshark -r usb.pcap -T fields -e usb.capdata "usb.urb_type==URB_SUBMIT" and "usb.endpoint_number.direction==OUT" and "frame.protocols==\"usb\"" > data
```

```ps1
.\tshark.exe -r tcpdump.pcap -Y 'tcp.flags.reset == 1' > ~\tmp\tcpdump-tcp_flags_reset_eq_1.txt
```

- capture filter syntax
    - https://wiki.wireshark.org/CaptureFilters
- read filter syntax
    - https://www.wireshark.org/docs/man-pages/wireshark-filter.html

### Display Filter Reference

```bash
tshark -G fields | grep _
```

https://www.wireshark.org/docs/dfref/

# Capture raw sockets

```bash
rawcap -f 127.0.0.1 localhost.pcap
tail -c +1 -f localhost.pcap | wireshark -k -i -
```

- http://www.nirsoft.net/utils/socket_sniffer.html
- https://github.com/simsong/tcpflow

# Winpcap, npf

```
sc qc npf
sc start npf
sc config npf start= auto
```

# DNS resolution, hostname

View > Name Resolution

# RDP

```
tcp.dstport == 3389 and tcp.flags.syn == 1
tcp port 3389 and tcp[0xd]&18=2
```

https://wiki.wireshark.org/RDP

# Real-time Transport Protocol (RTP)

- [!] May be presented as UDP traffic
    1. On packet, open context menu > Decode As... > Current = RTP
    2. Telephony > RTP > RTP Streams > On stream, open context menu > Analyse

# OpenVPN

```
udp port 1194 or tcp port 1194
```

# SQL Server

```
tds
```

# Decrypt TLS

- `CLIENT_RANDOM $1 $2`:
    - `$1`: 32 bytes client random value, encoded in hex (can be used when Session ID = 0)
        - Packet Details > Handshake Protocol: Client Hello > Random
    - `$2`: 48 bytes cleartext master secret, encoded in hex
    - Preferences > SSL > (Pre)-Master-Secret log
        - https://wiki.wireshark.org/TLS#Using_the_.28Pre.29-Master-Secret
    - Filter:
        ```
        dst host 192.168.1.214
            and tcp dst port 443  # Outbound packets on port 443/TCP
            and tcp[13]&8!=0      # PSH flag set
            and tcp[32]==22       # SSL Handshake Content Type
            and tcp[37]==1        # Client Hello Handshake Type
        ```
- If key exchange algorithm = PSK:
    - Cleartext Pre-Shared Key
        - Preferences > SSL > Pre-Shared Key
- If key exchange algorithm = RSA:
    - Server Private Key, encoded in PEM (used to decrypt the Pre-Master Secrets)
        - Preferences > SSL > RSA keys list
        - `openssl genrsa -out private.pem`
    - Master Key / Master Secret: PRF(Decrypted Pre-Master Secret, "master secret", Client Random + Server Random)[0..47]
        - Key Derivation Function / Pseudo Random Function (PRF): [GitHub \- trevp/tlslite: TLS Library in python](https://github.com/trevp/tlslite)
        - Pre-Master Secret: another client random, encrypted with Server Public Key
            - Packet Details > Handshake Protocol: Certificate > Export Packet Bytes...
    - `RSA $1 $2`:
        - `$1`: first 8 bytes of encrypted Pre-Master Secret, encoded in hex
        - `$2`: Cleartext Pre-Master Secret, encoded in hex
    - `RSA Session-ID:$1 Master-Key:$2`:
        - `$1`: SSL session ID, encoded in hex (used to resume a cached session)
        - `$2`: Cleartext Master Secret, encoded in hex
- If key exchange algorithm = Diffie-Hellman:
    - https://crypto.stackexchange.com/questions/19203/diffie-hellman-and-man-in-the-middle-attacks
    - https://blog.dragonsector.pl/2014/03/ructf-2014-quals-tls-crypto-300.html
- If key exchange algorithm = SIDH:
    - https://github.com/cstanfill/sidh-writeup
- If non-standard port
    - Packet List > Decode As...

- https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/how-to-decrypt-ruby-ssl-communications-with-wireshark/
- https://community.cisco.com/t5/security-documents/troubleshoot-tls-using-wireshark/ta-p/3396123
- https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/Key_Log_Format

# dump certificates

- Ensure traffic decoded as SSL - Analyze > Decode As > SSL analyzer
- Packet Details > Secure Socket Layer > select: certificate > open: context menu > Export Packet Bytes (e.g. cert.der)

- Validation: `openssl x509 -inform der -in cert.der -text`
- Convert to PEM: `openssl x509 -inform der -in cert.der -outform pem -out cert.crt`

# dump files

- File > Export Object > HTTP

# memory efficient

split:

```bash
# wireshark > Create new profile
#     wireshark > Analyze > Enabled Protocols > Disable All
tshark -C new_profile
# https://github.com/wanduow/libtrace/wiki/tracesplit
tracesplit --starttime=1484908320 --endtime=1484937840 -compress-type=none pcapfile:dia5_20Jan17.pcap pcapfile:1.pcap
# https://www.wireshark.org/docs/man-pages/editcap.html
editcap -A "2017-01-20 10:32:00" -B "2017-01-20 18:44:00" infile.pcap outfile.pcap
```

# specific packets

- range: `frame.number > 865900 && frame.number < 865999`
- conversation: `tcp.stream == 70098`

# statistics

- On menu bar: Statistics > Conversations > TCP (if highest count of packets)

```bash
tshark -r foo.pcap -qz io,stat,0,ip.src==1.2.3.4,ip.dst==1.2.3.4,tcp.dstport==80
tshark -r foo.pcap -qz conv,ip,ip.src==1.2.3.4
tshark -r foo.pcap -qz endpoints,ip,ip.src==1.2.3.4
tshark -r foo.pcap -qz flow,tcp,any,ip.src==1.2.3.4
tshark -r foo.pcap -qz follow,tcp,raw,ip.src==1.2.3.4
tshark -r foo.pcap -qz http,stat
tshark -r foo.pcap -qz http,tree
# Also `grep` to remove payload-less TCP packets
tshark -r foo.pcap -qz proto,colinfo,ip.src==1.2.3.4,foo.bar -T fields -e _ws.col.Info | grep foo.bar
```

```
===================================================================
IO Statistics
Column #0: ip.src==1.2.3.4
Column #1: ip.dst==1.2.3.4
Column #2: tcp.dstport==80
                |   Column #0    |   Column #1    |   Column #2
Time            |frames|  bytes  |frames|  bytes  |frames|  bytes
000.000-            725     52048    663    340474     28      2494
===================================================================
```

### payloads

```bash
# 1. filter `tcp.payload`, write values to files
~/code/snippets/pcap/time_delta.py <(tshark -r patience.pcap -Y 'tcp' -T json) | ~/code/my/aggregables/captures/matplotlib/bar.py

# 2. simplify values
ls -1 | xargs -i sed -i 's/22 Sep 2020 20:[0-9]*:[0-9]*/_/g' {}

# 3. remove duplicates
fdupes -r -f . | grep -v '^$' | xargs rm -v
```

### timestamps

- On menu bar: Statistics > I/O Graph
    - Display Filter: frame
    - Y Axis: SUM(Y Field)
    - Y Field: tcp.time_delta

```bash
# filter `tcp.payload`, write values to csv, render as bar chart
~/code/snippets/pcap/time_delta.py <(tshark -r patience.pcap -Y 'tcp' -T json) | ~/code/my/aggregables/captures/matplotlib/bar.py
```

Examples:

- [morse code encoded in time_delta](https://ajdin.io/posts/ctf-balccon-2020/#forensicspatience)
- [ssh keystroke timing attack](https://jasonmurray.org/posts/2020/zeekweeksudosu/)
    - https://corelight.blog/2019/05/07/how-zeek-can-provide-insights-despite-encrypted-communications/
    - https://security.stackexchange.com/questions/47192/how-does-ssh-defend-against-keystroke-timing-attacks

### frequency analysis

```bash
gron <(tshark -r foo.pcap -Y 'tcp.payload' -T json) \
    | awk '
        match($0, /^json\[[0-9]*\]\./) {
            s = substr($0, RLENGTH + 1, length($0))
            a[s]++
        }
        END {
            for (i in a) {
                if (a[i] > 0) {
                    print a[i] " " i
                } } }' \
    | sort -n \
    | vim -
```

# packet crafting / creation

```python
from scapy import *
packet = Ether()/IP(dst='8.8.8.8')/TCP(dport=53,flags='S')
send(packet)
```

- https://0xbharath.github.io/art-of-packet-crafting-with-scapy/network_recon/pcap_analysis/index.html
- [GitHub \- kbandla/dpkt: fast, simple packet creation / parsing, with definitions for the basic TCP/IP protocols](https://github.com/kbandla/dpkt)

# tcp replay / session mocking

```python
from scapy import *
sendp(rdpcap("/tmp/pcapfile"))
```
