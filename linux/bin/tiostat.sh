#!/bin/sh

set -eu

device=$1

prev_ds=$(cat "/sys/block/$device/stat" 2> /dev/null)
prev_ts=$(date +%s)
while true; do
  sleep 1
  curr_ds=$(cat "/sys/block/$device/stat" 2> /dev/null)
  curr_ts=$(date +%s)

  poll_time=$((curr_ts - prev_ts))
  sector_rd_begin=$(echo "$prev_ds" | awk '{print $3}')
  sector_rd_end=$(echo "$curr_ds" | awk '{print $3}')
  sector_wr_begin=$(echo "$prev_ds" | awk '{print $7}')
  sector_wr_end=$(echo "$curr_ds" | awk '{print $7}')
  read_kbps=$(($((sector_rd_end - sector_rd_begin / poll_time / 2)) / 1024 / 1024))
  write_kbps=$(($((sector_wr_end - sector_wr_begin / poll_time / 2)) / 1024 / 1024))
  echo "r:$read_kbps w:$write_kbps"

  prev_ds=$curr_ds
  prev_ts=$curr_ts
done
