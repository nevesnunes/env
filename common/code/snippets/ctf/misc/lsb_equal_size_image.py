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

order = cycle(sys.argv[2])

for i, rgb in enumerate(list(image.getdata())):
    x = int(i / y_dim)
    y = i % y_dim
    channel = next(order)
    extracted_rgb = list(rgb[:])
    if channel == "R":
        extracted_rgb[0] = (rgb[0] & 1) * 255
    if channel == "G":
        extracted_rgb[1] = (rgb[1] & 1) * 255
    if channel == "B":
        extracted_rgb[2] = (rgb[2] & 1) * 255
    message[x][y] = extracted_rgb

im = Image.fromarray(message)
im.save("out.equal_size_img.png")

#plt.imshow(message)
#plt.show()
#plt.savefig("out2.png")
