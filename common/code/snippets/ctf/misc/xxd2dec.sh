#!/bin/bash

hex=$(xxd -p "$1" | tr -d '\n')
hex="0x$hex"
dec=$(printf "%llu" "$hex")
echo $dec
