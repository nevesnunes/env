#!/usr/bin/env python3

from PIL import Image
import math
import numpy as np
import sys

im = Image.open(sys.argv[1])
data = im.getdata()
data2 = np.zeros((im.width // 2, im.height // 2, 3), dtype=np.uint8)
palette = im.getpalette()
indexes = {}
for i in range(0, im.width, 2):
    for j in range(0, im.height, 2):
        p1 = data.getpixel((i, j))
        p2 = data.getpixel((i, j + 1))
        p3 = data.getpixel((i + 1, j))
        p4 = data.getpixel((i + 1, j + 1))
        v1 = (palette[p1 * 3], palette[p1 * 3 + 1], palette[p1 * 3 + 2])
        v2 = (palette[p2 * 3], palette[p2 * 3 + 1], palette[p2 * 3 + 2])
        v3 = (palette[p3 * 3], palette[p3 * 3 + 1], palette[p3 * 3 + 2])
        v4 = (palette[p4 * 3], palette[p4 * 3 + 1], palette[p4 * 3 + 2])
        v = (
            math.ceil((v1[0] + v2[0] + v3[0] + v4[0]) / 4),
            math.ceil((v1[1] + v2[1] + v3[1] + v4[1]) / 4),
            math.ceil((v1[2] + v2[2] + v3[2] + v4[2]) / 4),
        )
        data2[j // 2, i // 2] = tuple(map(lambda x: 0 if x < max(v) else 255, v))
img = Image.fromarray(data2, "RGB")
img.show()
