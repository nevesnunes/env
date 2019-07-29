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

  local mime=$(xdg-mime query filetype $result)

  # text 
  if [[ $(match $result "(docx?|odt)$") != "" ]] &&
       [[ $(match $mime "application/zip") != "" ]]; then
    libreoffice "${result}" &
  elif [[ $(match $mime \
      "(application/javascript|text/|shell)(.*)$") != "" ]]; then
    gvim -v "+""$lineno" "${result}"
      
  # archives
  elif [[ $(match $result "(tar\.bz2|tbz2)$") != "" ]]; then
    tar xvjf "${result}"
  elif [[ $(match $result "(tar\.gz|tgz)$") != "" ]]; then
    tar xvzf "${result}"
  elif [[ $(match $result "(\.bz2)$") != "" ]]; then
    bunzip2 "${result}"
  elif [[ $(match $result "(\.rar)$") != "" ]]; then
    unrar x "${result}"
  elif [[ $(match $result "(\.gz)$") != "" ]]; then
    gunzip "${result}"
  elif [[ $(match $result "(\.tar)$") != "" ]]; then
    tar xvf "${result}"
  elif [[ $(match $result "(\.zip)$") != "" ]]; then
    unzip "${result}"
  elif [[ $(match $result "(\.Z)$") != "" ]]; then
    uncompress "${result}"
  elif [[ $(match $result "(\.7z)$") != "" ]]; then
    7z x "${result}"

  # anything
  else
    xdg-open "${result}" &
  fi
}

function match() {
  echo "$1" | grep -i -E "$2"
}
