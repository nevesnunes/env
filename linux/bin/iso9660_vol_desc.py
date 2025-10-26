#!/usr/bin/env python3

# Extracts and outputs fields from the "Primary Volume Descriptor".

# References:
# - https://wiki.osdev.org/ISO_9660

import re
import sys

CHUNK_SIZE = 8192

with open(sys.argv[1], "rb") as f:
    seen_bytes = 0
    while chunk := f.read(CHUNK_SIZE):
        match = re.search(rb"\x01CD001", chunk)
        if match:
            print(f"                                 @ {hex(seen_bytes + match.start())}")
            s = match.start()
            i = s
            print(f"                        Type Code: 0x{chunk[i:i+1].hex()}")
            i = s + 1
            print(f"              Standard Identifier: {chunk[i:i+5].decode()}")
            i = s + 6
            print(f"                          Version: 0x{chunk[i:i+1].hex()}")
            i = s + 7
            print(f"                           Unused: 0x{chunk[i:i+1].hex()}")
            i = s + 8
            print(f"                System Identifier: {chunk[i:i+32].decode().rstrip()}")
            i = s + 40
            print(f"                Volume Identifier: {chunk[i:i+32].decode().rstrip()}")
            print("                             [...]")
            i = s + 318
            print(f"             Publisher Identifier: {chunk[i:i+128].decode().rstrip()}")
            i = s + 446
            print(f"         Data Preparer Identifier: {chunk[i:i+128].decode().rstrip()}")
            i = s + 574
            print(f"           Application Identifier: {chunk[i:i+128].decode().rstrip()}")
            i = s + 702
            print(f"        Copyright File Identifier: {chunk[i:i+37].decode().rstrip()}")
            i = s + 739
            print(f"         Abstract File Identifier: {chunk[i:i+37].decode().rstrip()}")
            i = s + 776
            print(f"    Bibliographic File Identifier: {chunk[i:i+37].decode().rstrip()}")
            i = s + 813
            print(f"    Volume Creation Date and Time: {chunk[i:i+17].decode()}")
            i = s + 830
            print(f"Volume Modification Date and Time: {chunk[i:i+17].decode()}")
            i = s + 847
            print(f"  Volume Expiration Date and Time: {chunk[i:i+17].decode()}")
            i = s + 864
            print(f"   Volume Effective Date and Time: {chunk[i:i+17].decode()}")
            i = s + 881
            print(f"           File Structure Version: 0x{chunk[i:i+1].hex()}")
            i = s + 882
            print(f"                           Unused: 0x{chunk[i:i+1].hex()}")
            i = s + 883
            print(f"                 Application Used: {chunk[i:i+512].decode().rstrip()}")
            exit()
        seen_bytes += CHUNK_SIZE
