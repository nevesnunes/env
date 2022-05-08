#!/usr/bin/env python3
# https://gist.github.com/EONRaider/32c5dbf467c786f393bd0e7601246ddf
__author__ = 'EONRaider @ keybase.io/eonraider'

"""
A low-level network sniffer for TCP/IP packets.
"""

import struct
from binascii import hexlify
from itertools import count
from socket import inet_ntoa, ntohs, socket, PF_PACKET, SOCK_RAW

i = ' ' * 4  # Basic indentation level


def packet_sniffer():
    ETH_FRAME = slice(14)
    IP_PACKTS = slice(14, 34)
    TCP_SEGMT = slice(34, 54)

    print('[>>>] Sniffer initialized. Waiting for incoming packets...')

    with socket(PF_PACKET, SOCK_RAW, ntohs(0x800)) as sock:
        for packet_number in count(1):
            try:
                packet = sock.recvfrom(2048)
                print(f'\n[>] Packet #{packet_number}:')

                ethernet_header = packet[0][ETH_FRAME]
                ethernet_info = struct.unpack('!6s6s2s', ethernet_header)
                dest_mac, source_mac, _ = ethernet_info
                print(f"{i}[+] MAC: {hexlify(source_mac, ':').decode()} -> "
                      f"{hexlify(dest_mac, ':').decode()}")

                ip_header = packet[0][IP_PACKTS]
                ip_info = struct.unpack('!12s4s4s', ip_header)
                _, source_ip, dest_ip = ip_info
                print(f'{i}[+] IP: {inet_ntoa(source_ip)} -> '
                      f'{inet_ntoa(dest_ip)}')

                tcp_header = packet[0][TCP_SEGMT]
                tcp_info = struct.unpack('!HH9ss6s', tcp_header)
                source_port, dest_port, _, flags, _ = tcp_info
                print(f'{i}[+] TCP: {source_port} -> {dest_port} '
                      f'// Flags: {hexlify(flags).decode()}')

            except KeyboardInterrupt:
                raise SystemExit('Aborting...')


if __name__ == '__main__':
    packet_sniffer()
