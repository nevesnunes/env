# Copyright Alexander Jerneck 2014
# Licensed under the MIT license (http://opensource.org/licenses/MIT)
#!/bin/bash

# Script to batch ocr pdfs, by first converting them to tifs.
echo "usage: ocr PATTERN where PATTERN is a glob matching pdf files to be converted."
echo "example: ./ocr file-20*.pdf"

for x in $@
do
# pdfseparate to separate the pages
    echo "separating pages for $x"
    pdfseparate "$x" .tmp-%d.pdf

    for f in $(ls .tmp-*.pdf | sort -n -t - -k 2)
    do
        echo "converting $f to $f.tif ..."

        convert -colorspace Gray -normalize -density 300 -depth 8 -resample 200x200 -background white -flatten +matte  "$f" "$f.tif"
        tesseract "$f.tif" "$f.txt"

        cat "$f.txt.txt" >> "$x.txt"
        rm "$f.tif"
        rm "$f.txt.txt"

    done

    echo "cleaning up..."
    rm .tmp-*.pdf
    echo "text output saved to $x.txt"

done
