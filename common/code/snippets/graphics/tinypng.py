# Use `convert` to generate raw RGB data file.

import sys
import zlib

WIDTH = 570
HEIGHT = 453
IMG_RGB = open(sys.argv[1], "rb")


def pack_chunk(chunktype, chunkdata):
    chunk = len(chunkdata).to_bytes(4, "big")
    chunk += chunktype
    chunk += chunkdata
    chunk += zlib.crc32(chunk[4:]).to_bytes(4, "big")
    return chunk


ihdr = WIDTH.to_bytes(4, "big")  # width
ihdr += HEIGHT.to_bytes(4, "big")  # height
ihdr += (8).to_bytes(1, "big")  # bit depth
ihdr += (2).to_bytes(1, "big")  # colour type (coloured)
ihdr += (0).to_bytes(1, "big")  # compression method (DEFLATE)
ihdr += (0).to_bytes(1, "big")  # filter method (basic)
ihdr += (0).to_bytes(1, "big")  # interlace method (none)

idat_raw = b""
for y in range(HEIGHT):
    idat_raw += (0).to_bytes(1, "big")  # filter type (None)
    idat_raw += IMG_RGB.read(WIDTH * 3)

with open("out.png", "wb") as pngfile:
    pngfile.write(b"\x89PNG\r\n\x1a\n")
    pngfile.write(pack_chunk(b"IHDR", ihdr))
    pngfile.write(pack_chunk(b"IDAT", zlib.compress(idat_raw)))
    pngfile.write(pack_chunk(b"IEND", b""))
