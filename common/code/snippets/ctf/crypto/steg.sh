#!/bin/bash
for i in {0..255}; do
  python ./change_palette.py "steg.png" "single-color-${i}.png" "${i}"
done
