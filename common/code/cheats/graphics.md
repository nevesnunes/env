# +

[RAW Pixels Viewer](https://rawpixels.net/)

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
