#!/bin/sh

set -eu

parse() {
  message=$1
  var=$2
  is_password=$3
  input=
  stty -icanon -echo
  while true; do
    # Clear line, move cursor to begin, then print prompt
    if [ "$is_password" -eq 1 ]; then
      printf '\33[2K\r'"$message "
    else
      printf '\33[2K\r'"$message $input"
    fi
    # Read 1 character
    i=$(dd bs=1 count=1 2>/dev/null)
    # Was a backspace read?
    if echo "$i" | grep -qP '\x7f'; then
      # Remove last character
      input=$(echo "$input" | sed 's/.$//')
    # Only add read character if limit wasn't reached
    elif [ ${#input} -lt 3 ]; then
      input=$input$i
    fi
    # Was a newline read?
    if [ -z "$i" ]; then
      break
    fi
  done
  stty icanon echo
  eval "$var=$input"
}

echo "Please enter your credentials below"
parse "Please enter your username:" "usern" 0
printf "\n%s\n" "Read username: $usern"
parse "Please enter your password:" "userp" 1
printf "\n%s\n" "Read password: $userp"
