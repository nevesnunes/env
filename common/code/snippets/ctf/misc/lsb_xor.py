#!/usr/bin/env python3

# Usage:
# ./$0 foo.png

# References:
# - https://stackoverflow.com/questions/58194992/python-image-manipulation-using-pillsb

from PIL import Image
import numpy as np
import sys
import matplotlib.pyplot as plt

image = Image.open(sys.argv[1])
message = np.array(image)

extracted = (message[..., 0] ^ message[..., 1] ^ message[..., 2]) & 0x07
# ~=
# extracted = np.zeros(message.shape, dtype=int)
# for i in range(len(message)):
#     for j in range(len(message)):
#         extracted[i][j] = (message[i][j][0] ^ message[i][j][1] ^ message[i][j][2]) & 0x07

plt.imshow(extracted)
plt.show()
