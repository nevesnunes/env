#!/usr/bin/env bash

input=$1
file=$(echo -n "$input" | tr -d '\t\n\r' | cut -d':' -f1 )
lineno=$(echo -n "$input" | tr -d '\t\n\r' | cut -d':' -f2 )

# Validate input
number='^[0-9]+$'
if ! [[ $lineno =~ $number ]] || ! [[ -f $file ]]; then
  echo "bad input"
  exit 1
fi

# Define the range of the preview snippet
before=$(($lineno > 2 ? $(($lineno - 2)) : 1))
one_before=$(($lineno > 1 ? $(($lineno - 1)) : 1))
one_after=$(($lineno + 1))
after=$(($lineno + 2))

line=$(sed -n "$lineno"p < "$file")

# Color the matching line
fg_red="$(tput setaf 1)"
bold="$(tput bold)"
reset="$(tput sgr0)"
colored_line="${fg_red}${bold}$line${reset}"

# Workaround leftover escape sequence
# See `altcharset` in man terminfo 
colored_line=$(tr -d '\017' <<< "$colored_line")

sed -n "$before","$one_before"p';'"$one_before"q < "$file"
echo -e "$colored_line"
sed -n "$one_after","$after"p';'"$after"q < "$file"
