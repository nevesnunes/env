#!/usr/bin/env bash

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 filename"
    exit 1
fi

# upper limit of lines to display for text files
nlines=150

head -$nlines "$1" | pygmentize
