#!/usr/bin/env bash


# Split double-wide pages
mutool poster -x 2 The-Van-Conversion-Bible_North-America{,-PageSplit}.pdf

# Remove a few known blank or duplicated pages in the source PDF, reaarrange rest
pages=$(python -c 'for x in range(9,350,2): import sys; sys.stdout.write(f"{x+1} {x} ")')
mutool clean -gggg The-Van-Conversion-Bible_North-America-PageSplit.pdf The-Van-Conversion-Bible_North-America-Readable.pdf 1,2,5,7,"$pages"
