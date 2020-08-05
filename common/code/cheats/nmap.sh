#!/usr/bin/env bash

# OS and version detection, script scanning, traceroute
nmap -A
# ~= nmap -O -sV -sC

# Debug
# -vv
# --packet-trace

# https://security.stackexchange.com/questions/124394/nmap-says-host-down-when-host-is-up
# => under specific network (-e)
# https://stackoverflow.com/questions/40514044/nmap-rttvar-has-grown-to-over-2-3-seconds-decreasing-to-2-0
# => avoiding RTTVAR error (--host-timeout 2)
