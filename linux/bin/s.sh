#!/usr/bin/env bash

# Kill server:
# netstat -tulpn 2>&1 | grep 5000 | sed 's/.* \([0-9]*\)\/python.*/\1/' | xargs kill

args="$*"

if ! s_client.py localhost 5000 -z; then
  s_server.py &disown
fi
tries=5
while ((tries > 0)); do
  if s_client.py localhost 5000 -z; then
    break
  fi
  sleep 1
  tries=$((tries-1))
done

if [[ -n "$args" ]]; then
  args="$args "
fi
result=$(echo 'l' | s_client.py localhost 5000 | \
    fzf -0 -1 \
    -q "'$args" \
    --preview 'echo {} | s_client.py localhost 5000' \
    --preview-window down:10)
if [[ $result == "" ]]; then
  exit 1
fi

txt=$(echo "$result" | s_client.py localhost 5000)

# Edit placeholders if they exist
if echo "$txt" | grep -q -i '%%%'; then
  tmp_file=$(mktemp)
  trap 'rm -f "$tmp_file"' EXIT

  echo -n "$txt" > "$tmp_file"
  gvim -v -c "execute '/%%%' | call feedkeys('nvE', 'n')" "$tmp_file"
  txt=$(cat "$tmp_file")
fi
echo "$txt"
