#!/bin/bash

# I am the convertPDFs.sh script

# ARGUMENTS
# $1 - PDF to convert
# $2 - Pixel Density
# $3 - Scale (in %)

# Convert PDF to PNGs (one image per page)
magick convert -density $2 $1 -scale $3% ${1%.pdf}_%03d.png
