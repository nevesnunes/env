#!/usr/bin/env bash

# Print help
while getopts ":h" option; do
    case "${option}" in
        h | \?) printf "%s\n"\
            "Usage: da-extractor [OPTION]..."\
            "By default da-extractor saves the image in the user's Downloads folder." ""\
            "Options:"\
            " -f            Open image in Firefox"\
            " -b BROWSER    Open image in BROWSER"\
            " -d DIRECTORY  Save image in DIRECTORY"\
            " -h            Show this help";;
    esac
    exit
done 

for ((;;)) do

echo "Enter URL:"
read input_url
curl "$input_url" >> ./page.html

# Break sed output until we have only an url
partone=$(sed -n -e 's/ShareTumblr/usr/p' ./page.html)
parttwo=$(echo "$partone"|awk -F'openurl=' '{print $2}')
partthree=$(echo "$parttwo"|awk -F'source=' '{print $2}')
partfour=$(echo "$partthree"|awk -F'&amp' '{print $1}')

# Fix url
fixed_slash=${partfour/usr/"%2F"/"/"}
fixed_url=${fixed_slash/usr/"%3A"/":"}

# What to do with url
while getopts "f:b:d:" option; do
    case "${option}" in
        f) firefox -new-tab $fixed_url;;
        b) $(${OPTARG} $fixed_url);;
        d) curl -o "${OPTARG}/$(date +%s).jpg" $fixed_url;
    esac
done 
if [ $# -eq 0 ]; then
    curl -o "${HOME}/Downloads/$(date +%s).jpg" $fixed_url;
fi

# Clean up
sleep 1
rm ./page.html

done
