#!/usr/bin/env python3

from PIL import Image
import numpy as np
import sys

im = Image.open(sys.argv[1])
data = im.getdata()
data2 = np.zeros((im.width, im.height, 4), dtype=np.uint8)
bitdepth = 8
for i in range(0, im.width, 2):
    for j in range(0, im.height, 2):
        p1 = data.getpixel((i, j))
        # Fully opaque
        # Reference: https://www.w3.org/TR/PNG-DataRep.html
        data2[j, i] = (p1[0], p1[1], p1[2], (2 ** bitdepth) - 1)
img = Image.fromarray(data2, "RGBA")
img.show()
