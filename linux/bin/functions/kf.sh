function kpf() {
  local args="$*"

  # Extract pdf contents
  local current_files=$(find "$PWD" -maxdepth 1 -not -path ".")
  local page_buffer=$(mktemp)
  local contents=""
  printf '%s\n' "$current_files" | while IFS= read -r file; do
    # Check if file is a pdf
    local mime=$(xdg-mime query filetype "$file")
    if echo "$mime" | grep -q -i "application/pdf"; then
      pdftotext -layout "$file" "$page_buffer"
      while IFS= read -r line; do
        if [ -n "$line" ]; then
          contents+="$file:$line\n"
        fi
      done <"$page_buffer"
    fi
  done

  # Match generated contents
  local previewer=(--preview "echo -n {}" \
      --preview-window down:10)

  local result=$(echo "$contents" | fzf -0 -1 -q "'$args " "${previewer[@]}")
  if [[ $? -eq 1 ]] || [[ $result == "" ]]; then
    return 1
  fi

  # Open in pdf reader
  result=$(echo -n "$result" | tr -d '\t\n\r' | cut -d':' -f1 )
  xdg-open "${result}" &
}

function kf() {
  local args="$*"

  local previewer=(--preview "peeker.sh {}" \
      --preview-window down:10)
  command -v peeker.sh > /dev/null 2>&1
  if [[ $? -eq 1 ]]; then
    previewer=()
  fi

  local result=$(grep --line-buffered --no-messages --color=never -riIHn \
      -- "$args" * | fzf -0 -1 -q "'$args " "${previewer[@]}")
  if [[ $? -eq 1 ]] || [[ $result == "" ]]; then
    return 1
  fi

  lineno=$(echo -n "$result" | tr -d '\t\n\r' | cut -d':' -f2 )
  result=$(echo -n "$result" | tr -d '\t\n\r' | cut -d':' -f1 )
  if [ ! -f "$result" ]; then
    echo "Bad filename: $result"
    exit 1
  fi

  local magicmime=$(file -b --mime-type $result)
  local mime=$(xdg-mime query filetype $result)
  if [[ $mime == "" ]]; then
    return 1
  fi

  # text 
  if echo "$result" | grep -qiE "(docx?|odt)$" &&
      echo "$mime" | grep -qiE "application/zip"; then
    libreoffice "${result}" &
  elif echo "$mime" | grep -qiE "(application/javascript|text/|shell)(.*)$" ||
      echo "$magicmime" | grep -qiE "(text/plain)$"; then
    gvim -v "+${lineno}" "${result}"

  # archives
  elif echo "$result" | grep -qiE "(tar\.bz2|tbz2)$"; then
    tar xvjf "${result}"
  elif echo "$result" | grep -qiE "(tar\.gz|tgz)$"; then
    tar xvzf "${result}"
  elif echo "$result" | grep -qiE "(\.bz2)$"; then
    bunzip2 "${result}"
  elif echo "$result" | grep -qiE "(\.rar)$"; then
    unrar x "${result}"
  elif echo "$result" | grep -qiE "(\.gz)$"; then
    gunzip "${result}"
  elif echo "$result" | grep -qiE "(\.tar)$"; then
    tar xvf "${result}"
  elif echo "$result" | grep -qiE "(\.zip)$"; then
    unzip "${result}"
  elif echo "$result" | grep -qiE "(\.Z)$"; then
    uncompress "${result}"
  elif echo "$result" | grep -qiE "(\.7z)$"; then
    7z x "${result}"

  # anything
  else
    xdg-open "${result}" &
  fi
}
