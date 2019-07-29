#!/usr/bin/env python2
# -*- encoding: utf-8 -*-

# Usage:
# ./ipspoof.py 111.111.111.111 127.0.0.1
# tcpdump -i lo

import socket,sys
from impacket import import ImpactDecoder, ImpactPacket
     
if __name__ == "__main__":
    src = sys.argv[1]
    dst = sys.argv[2]
     
    # Create a new IP packet and set its source and destination addresses
     
    ip = ImpactPacket.IP()
    ip.set_ip_src(src)
    ip.set_ip_dst(dst)
     
    # Create a new ICMP packet
     
    icmp = ImpactPacket.ICMP()
    icmp.set_icmp_type(icmp.ICMP_ECHO)
     
    # Include a small payload inside the ICMP packet
    # and have the ip packet contain the ICMP packet
    icmp.contains(ImpactPacket.Data("a"*100))
    ip.contains(icmp)
     
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
     
    # Give the ICMP packet some ID
    icmp.set_icmp_id(1)

    # Calculate checksum
    icmp.set_icmp_cksum(0)
    icmp.auto_checksum = 0
    s.sendto(ip.get_packet(), (dst, 0))
