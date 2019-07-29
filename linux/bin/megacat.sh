#!/usr/bin/env bash

find . -maxdepth 1 -name "*.txt" -exec basename {} \; > megacat_filenames.txt

while IFS='' read -r line || [[ -n "$line" ]]; do
    echo "####"
    echo "#### $line"
    echo "####"
    printf "\n"
    cat "$line"
    printf "\n\n"
done < "megacat_filenames.txt"

rm megacat_filenames.txt
