#!/usr/bin/env bash

dd if=$1 of="$1-chunk-$2-$3" skip=$((0x$2)) count=$((0x$3)) iflag=skip_bytes,count_bytes
