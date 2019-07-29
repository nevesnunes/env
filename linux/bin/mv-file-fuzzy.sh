#!/usr/bin/env bash

source bin-choosers.sh
source bin-utils.sh

function make_filename() {
  input="$1"
  if [[ "$input" == "" ]]; then
    echo "No filename. Skipping..."
    read -n1 -p "Press any key to continue..."
    exit 1
  fi
  if ! [[ -f "$input" ]] && ! [[ -d "$input" ]]; then
    echo "Filename doesn't exist. Skipping..."
    read -n1 -p "Press any key to continue..."
    exit 1
  fi

  # Extract basename, since a new path will be prepended
  cd $(dirname "$input")
  input=$(basename "$input")

  # Add default extension if none was supplied
  extension="${input##*.}"
  if [ "$extension" == "$input" ]; then
    extension=".txt"
  fi
  mime=$(xdg-mime query filetype "$input")

  # Build name
  name=$input
  if [[ -z $(match "$mime" "image") ]] &&
      [[ -z $(match "$mime" "video") ]]; then
      read -p "Rename $name? (default = NO): " newname
      if [ -n "$newname" ]; then
        newname+=$extension
        name="$newname"
      fi
      printf "\n"
  fi

  filename="$2"
  if [[ "$filename" == "" ]]; then
    if [[ -n $(match "$mime" "image/") ]]; then
      filename="$(choose_image_location)"
    else
      filename="$(choose_location)"
    fi
  fi

  # Skip bad filename
  if [ -z "$filename" ]; then
    echo "Bad filename. Skipping..."
    read -n1 -p "Press any key to continue..."
    exit 1
  fi

  dir="$filename"
  filename+="/$name"

  # Skip existing file
  if [[ -f "$filename" ]] || [[ -d "$filename" ]]; then
    echo "$filename already exists. Skipping..."
    read -n1 -p "Press any key to continue..."
    exit 1
  fi

  # Also move folder associated with html file
  if [[ -n $(match "$mime" "application/x-extension-html") ]] ||
    [[ -n $(match "$mime" "text/html") ]] ; then
    htmlfolder="${input%.*}_files"
    mv "$htmlfolder" "$dir/."
  fi
  mv "$input" "$filename"

  printf "\n"
}

function usage() {
  echo "Usage: [-d|--dir DIRECTORY] FILE"
}

input_filename=""
input_dir=""
while [ "$1" != "" ]; do
    case $1 in
        -d | --dir )
					shift
          input_dir=$1
          ;;
        -h | --help )
					usage
          exit
          ;;
        * )
					input_filename=$1
    esac
    shift
done

make_filename "$input_filename" "$input_dir"
