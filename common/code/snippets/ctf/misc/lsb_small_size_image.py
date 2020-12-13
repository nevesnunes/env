#!/usr/bin/env python3

# Usage:
# ./$0 foo.png RGBRGB

from itertools import cycle
from PIL import Image
import numpy as np
import sys
import matplotlib.pyplot as plt

image = Image.open(sys.argv[1])
message = np.array(image)
x_dim = len(message)
y_dim = len(message[0])
message = []

order = cycle(sys.argv[2])

for rgb in list(image.getdata()):
    channel = next(order)
    if channel == "R":
        message.append(rgb[0] & 1)
    if channel == "G":
        message.append(rgb[1] & 1)
    if channel == "B":
        message.append(rgb[2] & 1)

message2 = np.zeros((x_dim // 8, y_dim // 8))
for i in range(0, len(message), 8):
    v = 0
    for j in range(8):
        bit = message[i + j]
        if bit:
            v |= 1 << bit
    x = i // y_dim // 8
    y = i % y_dim // 8
    message2[x][y] = v * 255

im = Image.fromarray(message2, mode="RGB")
im.save("out.small_size_img.png")
