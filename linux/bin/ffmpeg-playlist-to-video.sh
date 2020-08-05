#!/bin/sh

# References:
# - https://stackoverflow.com/questions/42901942/how-do-we-download-a-blob-url-video
# - https://superuser.com/questions/1260846/downloading-m3u8-videos

# Input:
# - Browser > Dev Tools > Network > Filter: m3u > Extract: Request URL

set -eu

exec ffmpeg \
  -protocol_whitelist file,http,https,tcp,tls,crypto \
  -i "$1" \
  -c copy \
  ~/Videos/"$(date +%s)".mp4
