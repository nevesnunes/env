# +

https://wiki.wireshark.org/Tools

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

# OpenVPN

```
udp port 1194 or tcp port 1194
```

# sqlserver

```
tds
```

# dump certificates

- Ensure traffic decoded as SSL - Analyze > Decode As > SSL analyzer
- Packet Details > Secure Socket Layer > select: certificate > open: context menu > Export Packet Bytes (e.g. cert.der)

- Validation: `openssl x509 -inform der -in cert.der -text`
- Convert to PEM: `openssl x509 -inform der -in cert.der -outform pem -out cert.crt`

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

# packet crafting / creation

```python
from scapy import *
packet = Ether()/IP(dst='8.8.8.8')/TCP(dport=53,flags='S')
send(packet)
```

https://0xbharath.github.io/art-of-packet-crafting-with-scapy/network_recon/pcap_analysis/index.html
https://github.com/kbandla/dpkt

# tcp replay / session mocking

```python
from scapy import *
sendp(rdpcap("/tmp/pcapfile"))
```
