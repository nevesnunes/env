#!/bin/bash

source bin-utils.sh

state=$HOME'/bin/txt-wiz.data'
find . -maxdepth 1 -name "*.txt" -exec basename {} \; > "$state"
while IFS='' read -r line || [[ -n "$line" ]]; do
    clear
    echo "####"
    echo "#### $line"
    echo "####"
    printf "\n"
    head "$line" | cut -c1-800
    printf "\n"

    # Must redirect to tty due to prompting inside read loop
    (   
      # Build new name
      read -p "Rename file (leave empty to skip): " newname
      if [ -z "$newname" ]; then
        newname=$line
      else
        newname+=".txt"
      fi
      printf "\n"

      filename="$(choose_location)"
      
      # Skip bad filename
      if [ -z "$filename" ]; then
        echo "Bad filename. Skipping..."
        read -n1 -r -p "Press any key to continue..." key
        exit 1
      fi

      filename+="/$newname"

      # Skip existing file
      if [ -f "$filename" ]; then
        echo $filename" already exists. Skipping..."
        read -n1 -r -p "Press any key to continue..." key
        exit 1
      fi

      mv "$line" "$filename"
    ) </dev/tty
  
    printf "\n"
done < "$state"

rm "$state"
