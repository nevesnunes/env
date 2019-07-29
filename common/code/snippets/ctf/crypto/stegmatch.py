# -*- coding: utf-8 -*-
from __future__ import absolute_import, unicode_literals
import sys
from PIL import Image

path = sys.argv[1]
output_path = "sample_red.png"
img = Image.open(path)
img = img.convert('RGB')


def matched_pixel(r, g, b):
    return r % 8 == g % 8 == b % 8 == 1


for y in range(img.size[1]):
    for x in range(img.size[0]):
        r, g, b = img.getpixel((x, y))
        if matched_pixel(r, g, b):
            # 指定座標を赤色に書き換える
            img.putpixel((x, y), (255, 0, 0))
        else:
            img.putpixel((x, y), (0, 0, 0))

img.save(output_path, "PNG", optimize=True)
