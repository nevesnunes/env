# pip install Pillow
from PIL import Image

# The image we sent
im = Image.open("orig.png")
pix = im.load()

# The image they return (indexed)
im_mod = Image.open("mod.png")
im_mod = im_mod.convert("RGB")
pix_mod = im_mod.load()

for i in xrange(im.size[0]):
  for j in xrange(im.size[1]):
    print("{0} x {1}: {2} {3}".format(i,j,pix[i,j],pix_mod[i,j]))
