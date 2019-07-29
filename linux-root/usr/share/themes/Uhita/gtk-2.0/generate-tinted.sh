#!/usr/bin/env bash

images=$(find . -type f | grep -E "(gif|jpe?g|png)")
array_images=("$images")
for i in "${array_images[@]}"; do
  # `#ffffff` (255) becomes `#dddddd` (221)
  convert "$i" -fill black -colorize 13.333333% "$i"
done
