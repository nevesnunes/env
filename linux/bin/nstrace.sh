#!/bin/sh

set -eu

# Capture network traffic of a single process.
# Reference: https://askubuntu.com/questions/11709/how-can-i-capture-network-traffic-of-a-single-process/499850#499850

bin=$1
iface=${2:-eth0}
ip=${3:-$(hostname -I | awk '{print $1}')}

# create a test network namespace
ip netns add test

# create a pair of virtual network interfaces (veth-a and veth-b)
ip link add veth-a type veth peer name veth-b

# change the active namespace of the veth-a interface
ip link set veth-a netns test

# configure the IP addresses of the virtual interfaces
ip netns exec test ifconfig veth-a up 192.168.163.1 netmask 255.255.255.0
ifconfig veth-b up 192.168.163.254 netmask 255.255.255.0

# configure the routing in the test namespace
ip netns exec test route add default gw 192.168.163.254 dev veth-a

# activate ip_forward and establish a NAT rule to forward the traffic coming in from the namespace you created (you have to adjust the network interface and SNAT ip address; you can also use the MASQUERADE rule if you prefer)
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -s 192.168.163.0/24 -o "$iface" -j SNAT --to-source "$ip"

# finally, you can run the process you want to analyze in the new namespace, and wireshark too; you'll have to monitor the veth-a interface
ip netns exec test "$bin"
ip netns exec test wireshark
