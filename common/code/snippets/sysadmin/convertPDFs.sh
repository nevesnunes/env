#!/bin/bash

# I am the convertPDFs.sh script

# ARGUMENTS
# $1 - PDF to convert
# $2 - Pixel Density
# $3 - Scale (in %)
# $4 - Shadow opacity
# $5 - Shadow sigma
# $6 - Relative distance of shadow (%)

# Convert PDF to PNGs (one image per page)
convert -density $2 $1 -profile /usr/share/ghostscript/9.15/iccprofiles/default_cmyk.icc -profile /usr/share/color/icc/OpenICC/sRGB.icc -scale $3% ${1%.pdf}_%03d.png

# Add shadow
for i in ${1%.pdf}*.png
 do
  convert $i \( +clone -background black -shadow $4x$5+$6x$6% \) +swap -background white -layers merge ${i%png}shadow.png
 done

# Mount into one image one after the other
montage -tile x1 -geometry +1+1 ${1%.pdf}*.shadow.png ${1%pdf}jpg

# Remove temporary unnecessary PNG files
rm -f ${1/.pdf/}*.png
