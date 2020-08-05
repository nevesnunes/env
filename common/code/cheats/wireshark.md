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
