#!/bin/bash

tmp_dir="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"
mkdir -p "$tmp_dir"
chmod 700 "$tmp_dir"
state="$tmp_dir/img-wiz.data"

cleanup() {
  err=$?
  rm -f "$state"
  trap '' EXIT
  exit $err
}
trap cleanup EXIT INT QUIT TERM

find . -maxdepth 1 -type f \( \
  -name "*.bmp" \
  -o -name "*.gif" \
  -o -name "*.jpg" \
  -o -name "*.jpeg" \
  -o -name "*.png" \
  -o -name "*.svg" \
  \) -exec basename {} \; > "$state"
while IFS='' read -r line || [ -n "$line" ]; do
  clear
  echo "####"
  echo "#### $line"
  echo "####"
  printf "\n"

  viewnior "$line" &
  sleep 3
  pkill viewnior

  # Must redirect to tty due to prompting inside read loop
  (
    filename="$(choose_image_location)"

    # Skip bad filename
    if [ -z "$filename" ]; then
      echo "Bad filename. Skipping..."
      read -n1 -r -p "Press any key to continue..."
      exit 1
    fi

    filename+="/$line"

    # Skip existing file
    if [ -f "$filename" ]; then
      echo "$filename already exists. Skipping..."
      read -n1 -r -p "Press any key to continue..."
      exit 1
    fi

    mv "$line" "$filename"
  ) < /dev/tty

  printf "\n"
done < "$state"
