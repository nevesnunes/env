import png
import random

pixels = []

counter = 0
colors = []
for i in xrange(256):
    colors.append(list([i, i, i]))

print colors
print len(colors)
for i in xrange(32):
    line = []
    for j in xrange(32):
        line.append(colors[counter][0])
        line.append(colors[counter][1])
        line.append(colors[counter][2])
        counter = (counter + 1) % len(colors)
    pixels.append(line)
png_writer = png.Writer(32, 32)
png_writer.write(open('orig.png', 'wb'), pixels)
