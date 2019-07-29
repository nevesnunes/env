# +

ip.addr==93.184.216.34 and http.request.method==GET
http.request.method==CONNECT

ip.host matches "192.168.70." && ip.host matches "^2..\."

tcp.flags.fin eq 1 or tcp.flags.reset eq 1
ip.host matches "\.149$"

# Winpcap, npf

sc qc npf 
sc start npf
sc config npf start= auto

# Capture raw sockets

rawcap -f 127.0.0.1 localhost.pcap
tail -c +1 -f localhost.pcap | wireshark -k -i -

http://www.nirsoft.net/utils/socket_sniffer.html
    java.exe

https://github.com/simsong/tcpflow

# Filters

```
tcp matches "(?i)soap.*action"
```

https://stackoverflow.com/questions/31426860/read-all-http-urls-from-pcap-file

# DNS resolution, hostname

View > Name Resolution

# RDP

tcp.dstport == 3389 and tcp.flags.syn == 1
tcp port 3389 and tcp[0xd]&18=2

https://wiki.wireshark.org/RDP

# OpenVPN

udp port 1194 or tcp port 1194
