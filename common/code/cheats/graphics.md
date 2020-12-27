# +

- [RAW Pixels Viewer](https://rawpixels.net/)

# image from bytes

- ~/code/guides/ctf/write-ups-2015/pragyan-ctf-2015/misc/255_255_255_is_the_best_color/go.py

# animation

```bash
ffmpeg -framerate 75 -i 'input%04d0000.png' output.gif

# `-delay n`: 100/n FPS
# `-loop 0`: repeat forever
convert -delay 2 -loop 0 input*.png output.gif
```

# convert

```bash
# SVG to PNG
for i in *.svg ; do inkscape -z -f "${i}" -w48 -h48 -e "${i%.svg}.png" ; done

# PCD to PNG
find . -name "*.pcd" -type f -exec convert '{}[5]' ../../pngs/'{}'.png \;
```

# write / export from plaintext

```bash
{
  # magic, width, height, max component value
  echo "P3 250 250 255"
  for ((y=0; y<250; y++)) {
    for ((x=0; x<250; x++)) {
      # r, g, b
      echo "$((x^y)) $((x^y)) $((x|y))"
    }
  }
} | convert ppm:- png:- >foo.png
```

Alternatives:

- NetPBM: `pnmtopng < foo.ppm > foo.png`
    - [Use echo/printf to write images in 5 LoC with zero libraries or headers &\#8211; Vidar&\#039;s Blog](https://www.vidarholen.net/contents/blog/?p=904)

# seams

layer > transform > offset

# light balance

duplicate layer
gaussian blur
invert colours
layer tab > mode > overlay

# lighten

duplicate layer
gradient tool
layer tab > mode > addition

# posterize, alpha channel

https://orbitingweb.com/blog/optimizing-png-images/

# xor

```bash
# highlight differences
compare i1.png i2.png -metric RMSE o.png
# render differences
composite i1.png i2.png -compose difference o.png
```

# combine

```python
import numpy as np
from PIL import Image

data = np.zeros((2000,2000,4), dtype=np.uint8)

for i in range(100):
    for j in range(100):
        #modify_file("flag_{}_{}.jpg".format(i,j))
        im = Image.open("flag_{}_{}.png".format(i,j))
        array = np.array(im.getdata()).reshape(20,20,4)
        data[20*i:20*(i+1), 20*j:20*(j+1)] = array

img = Image.fromarray(data, 'RGBA')
img.save('flag.png')
```

```bash
montage -mode concatenate -tile 1x in-*.jpg out.jpg
```

https://superuser.com/questions/290656/combine-multiple-images-using-imagemagick

# cut

```bash
# 1366x768
convert in.png -crop "$((1366-$((1366-752+2))))x$((768-$((768-464+26))))+1+26" out.png
# 1/3 of 1366x768
convert in.png -crop "$((490-20-2))x$((736-10-34))+11+34" out.png
```

# visual regression testing

- python - selenium webdriver `save_screenshot()` + Pillow `ImageChops.difference()`
    - https://jounileino.com/2019/05/17/visual-regression-testing.html
    - https://stackoverflow.com/questions/41721734/take-screenshot-of-full-page-with-selenium-python-with-chromedriver
- {!} changes in one element displace others => compute diff in DOM tree, style only changed elements

### responsive layouts

- [GitHub \- redecheck/redecheck: Automatically Detecting Layout Failures in Responsive Web Pages](https://github.com/redecheck/redecheck)
    - ~/Downloads/ReDeCheck - An Automatic Layout Failure Checking Tool for Responsively Designed Web Pages.pdf
    - user-defined layout constraints checked against different viewports

# levels

http://www.imagemagick.org/discourse-server/viewtopic.php?t=27719

# reversing gaussian blur

With G'MIC plugin:

Details > Sharpening

- Richardson-Lucy Deconvolution
- Gold-Meinel Deconvolution

# aligning rotations

[By FFT, what rotation?](http://im.snibgo.com/whatrotfft.htm)

# untwist

Filters > Distorts > Whirl and Pinch...

# frequency domain

[Frequency Domain Image Compression and Filtering | Hacker News](https://news.ycombinator.com/item?id=24997191)
