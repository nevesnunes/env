#!/usr/bin/env bash

contents_clipboard=$(xclip -selection clipboard -o)
contents_primary=$(xclip -selection primary -o)
if [ -n "$contents_primary" ]; then
  txt="$contents_primary"
else
  txt="$contents_clipboard"
fi
echo '' | xclip -selection clipboard -i
echo '' | xclip -selection primary -i

# Exit on unintentional copied text
if [ ${#txt} -lt 5 ]; then
  notify-send "[clip-saver.sh] Error" "Less than 5 characters to save."
  exit 1
fi

first_line="$(echo $txt | \
    cut -d' ' -f-8 | sed -E 's/ /_/g' | tr -cd '[[:alnum:]]_-')"

# Add URL to contents if snipped from browser
# /!\ Requires `Vimperator` or similar to be installed
current_class=$(xprop -id "$(xdotool getwindowfocus)" | \
    awk '/WM_CLASS/{print $4}' | sed 's/"/usr/g')
current_desktop=$(xdotool get_desktop)
if echo "$current_class" | grep -q -i -E "(firefox|chrome)"; then
  url=""
  TRIES=5
  while [[ $TRIES -gt 0 ]]; do
    xdotool search \
        --desktop "$current_desktop" --class "$current_class" \
        key --window %@ y y
    sleep 0.2

    # Check which clipboard actually got the selection (e.g. chrome uses `primary`)
    new_contents_clipboard=$(xclip -selection clipboard -o)
    new_contents_primary=$(xclip -selection primary -o)
    if [[ -n "$new_contents_clipboard" ]]; then
      url="$new_contents_clipboard"
      break
    elif [[ -n "$new_contents_primary" ]]; then
      url="$new_contents_primary"
      break
    fi
    TRIES=$(($TRIES - 1))
  done

  # Skip URL appending if content is a URL
  if [ -n "$url" ]; then
    regex_link='^(https?|ftp|file):/usr/'
    regex_link+='[-A-Za-z0-9\+&@#/%?=~_|!:,.;]*[-A-Za-z0-9\+&@#/%=~_|]'
    maybe_link="$(echo -e "$txt" | tr -d '[:space:]' | head -n1)"
    if ! [[ "$maybe_link" =~ $regex_link ]]; then
      txt=$(printf "Source:\n%s\n\n%s" "$url" "$txt")
    fi
  fi
fi

command -v clip-saver-interactive.sh > /dev/null 2>&1
if [[ $? -eq 1 ]]; then
  notify-send "[clip-saver.sh] Error" "clip-saver-interactive.sh not in PATH."
  exit 1
else
  user-terminal.sh clip-saver-interactive.sh "$txt" "$first_line"
fi

# Unselect text
xdotool search \
    --desktop "$current_desktop" --class "$current_class" \
    key --window %@ Escape
