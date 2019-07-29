#!/usr/bin/env bash

set -eu

add_files() {
  playlist=$1
  while read -r i; do {
    if ! file --mime-type "$i" | grep -qi '\(audio\|octet-stream\)'; then
      continue
    fi

    track=$(exiftool -Track -TrackNumber -s -s -s "$i" | \
      head -n1 | \
      sed 's/\s*//g; s/[^[:alnum:]\.].*//g')
    if [ -n "$track" ]; then
      while [ "$track" != "${track#0}" ]; do
        track=${track#0}
      done
      # Handle track numbers with letters
      if ! echo "$track" | grep -q '[^0-9]'; then
        track=$(printf "%02d" "$track")
      fi
    fi

    # Handle bad formatting from printf
    if echo "$track" | grep -q '^0*$'; then
      track=''
    fi

    regex_invalid_chars='s/"//g'
    regex_invalid_chars+='; s/[<>:\/\\\|\?\*]\([^\s]\)/-\1/g'
    regex_invalid_chars+='; s/[<>:\/\\\|\?\*]//g'
    artist=$(exiftool -Artist -s -s -s "$i" | \
      sed "$regex_invalid_chars")
    title=$(exiftool -Title -s -s -s "$i" | \
      sed "$regex_invalid_chars")

    filename=$(basename -- "$i")
    extension="${filename##*.}"
    filename="${filename%.*}"
    has_track_in_filename=$(echo "$filename" | grep -iE '^[A-Za-z]*[0-9]+')
    fullname="$track. $artist - $title.$extension"
    has_fullname=$(echo "$i" | grep "$fullname")
    if [ -n "$track" ] && \
        [ -n "$artist" ] && \
        [ -n "$title" ] && \
        [ -z "$has_fullname" ]; then
      # Make full filename from exif metadata
      ! [ -f "$fullname" ]
      mv "$i" "$fullname"
      echo "$fullname" >> "$playlist"
    elif [ -n "$track" ] && [ -z "$has_track_in_filename" ]; then
      # Use track number from exif metadata
      new_file="$track. $i"
      ! [ -f "$new_file" ]
      mv "$i" "$new_file"
      echo "$new_file" >> "$playlist"
    elif [ -n "$has_track_in_filename" ]; then
      # Use track number from filename
      echo "$i" >> "$playlist"
      continue
    else
      # Can't guess track order
      rm -f "$playlist"
      return
    fi
  } || true
  done <<< "$(find . -maxdepth 1 -type f | sed 's/^\.\///')"
}

while read -r dir; do (
  album_dir=$(realpath "$dir")
  cd "$dir"
  [ -n "$(find . -maxdepth 1 -iname '*.m3u')" ] && exit 0
  album_name=$(basename "$album_dir" | sed \
    -e 's/\s*\(\[\|(\)[[:alnum:]\ ,_-]*\(\]\|)\)\s*$//' \
    -e 's/^\s*\(\[\|(\)[[:alnum:]\ ,_-]*\(\]\|)\)\s*//' \
    -e 's/^\s*\[[^\]]*\]\s*//')
  playlist="$album_name".m3u
  rm -f "$playlist"
  add_files "$playlist"
  if [ -f "$playlist" ]; then
    tmp_file=$(mktemp)
    sort -V "$playlist" > "$tmp_file" && mv "$tmp_file" "$playlist"
  fi
  ) &
done <<< "$(find . -type d)"
