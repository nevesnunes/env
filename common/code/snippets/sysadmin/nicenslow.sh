#!/bin/bash

mkdir result
for f in ./*.JPG; do
convert "$f" -resize 60% -compress jpeg -quality 98 "result/$f"
done
