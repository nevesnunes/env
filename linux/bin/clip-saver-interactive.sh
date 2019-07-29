#!/usr/bin/env bash

source ~/bin/bin-choosers.sh
source ~/bin/bin-colors.sh

logfile=$XDG_RUNTIME_DIR/clip-saver.log
touch "$logfile"

function report {
  if [ -n "$logfile" ]; then
    cat "$logfile"
    read -n1 -r -p "Press any key to exit..."
  fi
}

function display_notification {
  (
    printf "\n"
    echo "$1"
    echo "$2"
    printf "\n"
  ) >/dev/tty
  read -n1 -r -p "Press any key to continue..."
}

function display_contents {
  clear
  echo "${fg_magenta}${bold}Clipboard contents:${reset}"
  printf "\n"
  echo "$txt" | head -n 30 | cut -c-80
  printf "\n"
}

txt=$1
first_line=$2

has_location=false
while [[ $has_location = false ]]; do
  display_contents

  is_name_choosen=false
  regex_link='^(https?|ftp|file):/usr/'
  regex_link+='[-A-Za-z0-9\+&@#/%?=~_|!:,.;]*[-A-Za-z0-9\+&@#/%=~_|]'
  maybe_link="$(echo -e "$txt" | tr -d '[:space:]' | head -n1)"
  if [[ "$maybe_link" =~ $regex_link ]]; then
    fg_red="$(tput setaf 1)"
    bold="$(tput bold)"
    reset="$(tput sgr0)"
    line="/!\\ This is a link, the file will be downloaded."
    colored_line="${fg_red}${bold}$line${reset}"
    printf "%s\n\n" "$colored_line"

    if [[ "$maybe_link" =~ .*\.(gif|jpe?g|png|svg|mp[34]|wav|webm)$ ]]; then
      is_name_choosen=true
    fi
  fi

  location="$(choose_location)"
  filename="$location"
  while [ "$filename" == edit ]; do
    tmp_file=$(mktemp)

    echo -n "$txt" > "$tmp_file"
    gvim -v "$tmp_file"
    txt=$(cat "$tmp_file")
    rm -f "$tmp_file"

    display_contents

    location="$(choose_location)"
    filename="$location"
  done

  # Exit on bad option
  if [ -z "$filename" ]; then
    title="Clipboard NOT saved!"
    sample="No valid location selected."
    display_notification "$title" "$sample"
  else
    has_location=true
  fi
done

# Build new name
mkdir -p "$filename"
printf "\n"
(
  original_filename=$filename
  while [[ $is_name_choosen = false ]]; do
    read -r -p "Rename file (default = NO): " newname
    if [ -z "$newname" ]; then
      # Grab a few words, convert spaces to underscores and
      # remove non-alphanumeric
      filename="$original_filename/$first_line"
    else
      filename="$original_filename/$newname"
    fi

    # Add default extension if none was supplied
    extension="${filename##*.}"
    if [[ "$extension" == "$filename" ]]; then
      filename+=".txt"
    fi

    # Skip existing file
    if [ -f "$filename" ]; then
      title="$filename already exists. Skipping..."
      sample=""
      display_notification "$title" "$sample"
    else
      is_name_choosen=true
    fi
  done

  if [[ "$maybe_link" =~ $regex_link ]]; then
    cd "$location"

    is_single_file=""
    if [[ "$maybe_link" =~ .*\.(gif|jpe?g|png|svg|mp[34]|wav|webm)$ ]]; then
      is_single_file="y"
    else
      read -r -p "Single file (default = NO): " is_single_file
    fi

    # Minimize dialog when downloading files
    xdotool getactivewindow windowminimize

    is_tumblr_link=""
    regex_tumblr_link='^https?:/usr/.*tumblr\.com.*'
    # TODO: Fix errors
    # if [[ "$maybe_link" =~ $regex_tumblr_link ]]; then
    #   is_tumblr_link="y"
    #   tmp_html_file="$(mktemp).html"
    #   node ~/bin/save_pages/tumblr_selenium.js "$maybe_link" \
    #       > "$tmp_html_file" || report
    #   server_port=51234
    #   python -m SimpleHTTPServer "$server_port" &
    #   server_pid=$!
    #   maybe_link="http:/usr/localhost:$server_port/$tmp_html_file"
    # fi
    # TODO: Maybe add:
    # --warc-file="$(date +'%s')" \
    if [ -z "$is_single_file" ]; then
      wget \
          --no-use-server-timestamps \
          --adjust-extension \
          --page-requisites \
          --no-use-server-timestamps \
          --span-hosts \
          --convert-links \
          --backup-converted \
          --limit-rate=500k --random-wait --wait=0.5 \
          -e robots=off \
          "$maybe_link" &> "$logfile" || report
    else
      wget \
          --no-use-server-timestamps \
          "$maybe_link" &> "$logfile" || report
    fi
    if [ -n "$is_tumblr_link" ]; then
      rm "$tmp_html_file"
      kill "$server_pid"
    fi
  else
    touch "$filename"
    echo "$txt" > "$filename"
  fi
) >/dev/tty
