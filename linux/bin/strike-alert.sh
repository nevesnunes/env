#!/usr/bin/env bash

set -eu

links=( \
  http://feeds.tsf.pt/TSF-Ultimas.xml \
  http://feeds.tsf.pt/TSF-Portugal.xml \
  http://www.dnoticias.pt/rss/home.xml \
  http://www.dnoticias.pt/rss/pais.xml \
  https://feeds.feedburner.com/PublicoRSS \
  https://feeds.feedburner.com/obs-ultimas \
  https://ionline.sapo.pt/rss.xml \
)

for link in "${links[@]}"; do (
  feedstail -u "$link" -f "[{link}] {title} - {summary}" | \
    while read -r i; do
      echo "$i" | grep -i 'Greve' && notify-send 'Greve' "$i"
    done
) &
done
