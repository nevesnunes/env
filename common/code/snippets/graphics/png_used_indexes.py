#!/usr/bin/env python3

from PIL import Image
import sys

im = Image.open(sys.argv[1])
data = im.getdata()
palette = im.getpalette()
print(palette)
indexes = {}
for i in range(im.width):
    for j in range(im.height):
        k = data.getpixel((i, j))
        v = (palette[k * 3], palette[k * 3 + 1], palette[k * 3 + 2])
        indexes[k] = v
print(indexes)
