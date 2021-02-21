#!/usr/bin/env bash

# References:
# - https://en.wikipedia.org/wiki/M3U#Extended_M3U

set -eu

add_files() {
  playlist=$1
  while read -r i; do
    {
      if ! file --mime-type "$i" \
        | awk -F':' '{print $NF}' \
        | grep -qi '\(audio\|octet-stream\)'; then
        continue
      fi

      disk=$(exiftool -Disk -DiskNumber -s -s -s "$i" \
        | head -n1 \
        | sed 's/\s*//g; s/[^[:alnum:]\.].*//g; s/of[0-9]\+//g')
      track=$(exiftool -Track -TrackNumber -s -s -s "$i" \
        | head -n1 \
        | sed 's/\s*//g; s/[^[:alnum:]\.].*//g; s/of[0-9]\+//g')
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

      # Only keep characters compatible with common filesystems (e.g. NTFS)
      regex_invalid_chars='s/"//g'
      regex_invalid_chars+='; s/[<>:\/\\\|\?\*]\([^\s]\)/-\1/g'
      regex_invalid_chars+='; s/[<>:\/\\\|\?\*]//g'
      artist=$(exiftool -Artist -s -s -s "$i" \
        | sed "$regex_invalid_chars")
      title=$(exiftool -Title -s -s -s "$i" \
        | sed "$regex_invalid_chars")

      # Using `decimal-floating-point` duration format from HLS specification.
      # References:
      # - [ffmpeg \- How to get video duration in seconds? \- Super User](https://superuser.com/questions/650291/how-to-get-video-duration-in-seconds/945604)
      # - [RFC 8216 \- HTTP Live Streaming \- Attribute Lists](https://tools.ietf.org/html/rfc8216#section-4.2)
      track_runtime=$(ffprobe \
        -v error \
        -select_streams a:0 \
        -show_entries stream=duration \
        -of default=noprint_wrappers=1:nokey=1 \
        "$i")
      if echo "$track_runtime" | grep -q '[^0-9\.]\+'; then
        track_runtime=0
      fi

      filename=$(basename -- "$i")
      extension="${filename##*.}"
      filename="${filename%.*}"
      has_track_in_filename=$(echo "$filename" | grep -iE '^[A-Za-z]*[0-9]+')
      fullname="$disk$track. $artist - $title.$extension"
      has_fullname=$(echo "$i" | grep "$fullname")
      if [ -n "$track" ] \
        && [ -n "$artist" ] \
        && [ -n "$title" ] \
        && [ -z "$has_fullname" ]; then
        # Make full filename from exif metadata
        ! [ -f "$fullname" ]
        mv "$i" "$fullname"
        echo "#EXTINF:$track_runtime,$artist - $title"$'\x1e'"$fullname" >> "$playlist"
      elif [ -n "$track" ] && [ -z "$has_track_in_filename" ]; then
        # Use track number from exif metadata
        new_file="$track. $i"
        ! [ -f "$new_file" ]
        mv "$i" "$new_file"
        echo "#EXTINF:$track_runtime,$i"$'\x1e'"$new_file" >> "$playlist"
      elif [ -n "$has_track_in_filename" ]; then
        # Use track number from filename
        track_name=$(echo "$i" | sed 's/^[^\.]*\.\s*//')
        echo "#EXTINF:$track_runtime,$track_name"$'\x1e'"$i" >> "$playlist"
        continue
      else
        # Can't guess track order
        rm -f "$playlist"
        return
      fi
    } || true
  done <<< "$(find . -maxdepth 1 -type f | sed 's/^\.\///')"
}

while read -r dir; do
  (
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
      echo "#EXTM3U" > "$tmp_file"
      sort -V -t $'\x1e' -k 2 "$playlist" \
        | sed 's/\x1e/\n/g' >> "$tmp_file" \
        && mv "$tmp_file" "$playlist"
    fi
  ) &
done <<< "$(find . -type d)"
