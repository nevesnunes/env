#!/bin/sh

# References:
# - https://stackoverflow.com/questions/42901942/how-do-we-download-a-blob-url-video
# - https://superuser.com/questions/1260846/downloading-m3u8-videos
# - https://gist.github.com/niemasd/1c5abb067808ef890a45c08fc4318069

# Input:
# - Browser > Dev Tools > Network > Filter: m3u > Extract: Request URL

set -eu

exec ffmpeg \
  -headers "User-Agent: Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:97.0) Gecko/20100101 Firefox/97.0" \
  -hide_banner \
  -protocol_whitelist file,http,https,tcp,tls,crypto \
  -i "$1" \
  -c copy \
  ~/Videos/"$(date +%s)".mp4
