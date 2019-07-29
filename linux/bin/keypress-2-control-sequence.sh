#!/usr/bin/env bash

# Alternatives:
# cat

stty raw min 1 time 20 -echo
dd count=1 2> /dev/null | od -vAn -tx1 | tee >(hex2char.py)
stty sane
