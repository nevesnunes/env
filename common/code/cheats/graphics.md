# +

- [RAW Pixels Viewer](https://rawpixels.net/)
- [GitHub \- lovell/sharp: High performance Node\.js image processing, the fastest module to resize JPEG, PNG, WebP, AVIF and TIFF images\. Uses the libvips library\.](https://github.com/lovell/sharp)
- [Fred's ImageMagick Scripts](http://www.fmwconcepts.com/imagemagick/index.php)

# graphs

- https://dreampuf.github.io/GraphvizOnline
- https://manpages.debian.org/testing/graphviz/gvpr.1.en.html

# textures

- [Graphics/Texture finders and viewers \- XeNTaX](https://forum.xentax.com/viewtopic.php?t=15540)
- http://wiki.polycount.com/wiki/DXT

# graphics api

- [RenderDoc](https://renderdoc.org/)
- [GitHub \- apitrace/apitrace: Tools for tracing OpenGL, Direct3D, and other graphics APIs](https://github.com/apitrace/apitrace)

### GLSL

- [GLSL Sandbox Gallery](http://glslsandbox.com/)
- [Shadertoy BETA](https://www.shadertoy.com/)
- [The Book of Shaders](https://thebookofshaders.com/glossary/)
- [WebGLRenderingContext \- Web APIs \| MDN](https://developer.mozilla.org/en-US/docs/Web/API/WebGLRenderingContext)

- [GLSL\-Debugger : A GLSL source level debugger](http://glsl-debugger.github.io/)
- [opengl \- How to debug a GLSL shader? \- Stack Overflow](https://stackoverflow.com/questions/2508818/how-to-debug-a-glsl-shader)

```javascript
if (!gl.getShaderParameter(shader, gl.COMPILE_STATUS)) {
    alert(gl.getShaderInfoLog(shader));
}
```

```glsl
void main() {
  float bug = 0.0;
  vec3 tile = texture2D(colMap, coords.st).xyz;
  vec4 col = vec4(tile, 1.0);

  if (crash) {
    bug = 1.0;
  }
  col.x += bug;

  gl_FragColor = col;
}
```

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

# PhotoCD (PCD) to PNG
# FIXME: Low brightness using `-colorspace RGB`
find . -name "*.pcd" -type f -exec convert '{}[5]' ../../pngs/'{}'.png \;
# Alternatives:
g++ main.cpp pcdDecode.cpp -ljpeg -lpthread -o pcdtojpeg
find . -name "*.pcd" -type f -exec pcdtojpeg -r 5 '{}' \;

# PDF to JPEG
pdfimages -all foo.pdf ./out/
pdftoppm -tiff -r 300 foo.pdf ./out/pg
pdftoppm -jpeg -jpegopt quality=100 -r 300 foo.pdf ./out/pg
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

# scale

```bash
for i in *.png; do convert -strip -quality 92% -resize x2600\>  "$i" "$i".jpg; done
```

# stitch, panorama

- if scanned images, then use 5 degrees
  - [Autostiching scan with Hugin \- David Revoy](https://www.davidrevoy.com/article314/autostiching-scan-with-hugin)
  - [Hugin tutorial &\#8212; Stitching flat scanned images](http://hugin.sourceforge.net/tutorials/scans/en.shtml)
- control points
  - [How to stitch photos together on Linux](https://www.xmodulo.com/stitch-photos-together-linux.html)

# visual regression testing

- python - selenium webdriver `save_screenshot()` + Pillow `ImageChops.difference()`
    - https://jounileino.com/2019/05/17/visual-regression-testing.html
    - https://stackoverflow.com/questions/41721734/take-screenshot-of-full-page-with-selenium-python-with-chromedriver
- {!} changes in one element displace others => compute diff in DOM tree, style only changed elements

### responsive layouts

- [GitHub \- redecheck/redecheck: Automatically Detecting Layout Failures in Responsive Web Pages](https://github.com/redecheck/redecheck)
    - ~/Downloads/ReDeCheck - An Automatic Layout Failure Checking Tool for Responsively Designed Web Pages.pdf
    - user-defined layout constraints checked against different viewports

# preserve indexed palette on resize

```bash
convert _ -filter point -resize 50% o50.png
# ||
convert _ -sample 50% o50.png
# With custom sampling point
# Reference: https://imagemagick.org/script/command-line-options.php#sample
convert _ -define sample:offset=75x25 -sample 50% o50.png
```

# apply transformation from color lookup table

```bash
convert -hald:16 hald_16.png
# [Apply transform with e.g. GIMP, take hald_16_processed.png]
convert foo.png hald_16_processed.png -hald-clut foo_processed.jpg
```

- [IM equivalent of GIMP \- Levels \- Output \- ImageMagick](https://legacy.imagemagick.org/discourse-server/viewtopic.php?f=1&t=25913)

# levels

http://www.imagemagick.org/discourse-server/viewtopic.php?t=27719

# reversing gaussian blur

With G'MIC plugin:

Details > Sharpening

- Richardson-Lucy Deconvolution
- Gold-Meinel Deconvolution

# lossless rotation

```bash
# Orientation values:
# - 1 = Horizontal (normal)
# - 2 = Mirror horizontal
# - 3 = Rotate 180
# - 4 = Mirror vertical
# - 5 = Mirror horizontal and rotate 270 CW
# - 6 = Rotate 90 CW
# - 7 = Mirror horizontal and rotate 90 CW
# - 8 = Rotate 270 CW
# References:
# - https://exiftool.org/TagNames/EXIF.html
exiftool -n -Orientation=8 -o output.jpg input.jpg
```

# aligning rotations

[By FFT, what rotation?](http://im.snibgo.com/whatrotfft.htm)

# unskew

Perspective Tool

# untwist

Filters > Distorts > Whirl and Pinch...

# frequency domain

[Frequency Domain Image Compression and Filtering | Hacker News](https://news.ycombinator.com/item?id=24997191)

# seam carving, content aware resizing

- [GitHub \- esimov/caire: Content aware image resize library](https://github.com/esimov/caire)

- [Content\-aware image resizing in JavaScript \| Trekhleb](https://trekhleb.dev/blog/2021/content-aware-image-resizing-in-javascript/)
- [Improved seam carving with forward energy](https://avikdas.com/2019/07/29/improved-seam-carving-with-forward-energy.html)

# ocr

- ~/code/snippets/graphics/redpwnCTF2019-dedication.py
    - [CTFtime\.org / redpwnCTF 2019 / Dedication / Writeup](https://ctftime.org/writeup/16173)

# small size / lossy compression

```bash
svgo foo.svg

pngquant --quality 40-60 -s1 --skip-if-larger -f foo.png && \
  ect -9 --allfilters --pal_sort=20 --mt-deflate foo-fs8.png
# ||
mogrify -strip PNG8:foo.png
# ||
cwebp -psnr 40 foo.png -o foo.webp
```
