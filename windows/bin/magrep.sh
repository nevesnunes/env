#!/usr/bin/env bash

# TODO:
# - n words
# - bisect blocks to get exact lines

word1=$1
word2=$2
input=$3

# Group lines into blocks
count_lines=5
blocks=()
while true; do
  out=()
  for (( i=0; i<$count_lines; i++ )); do
    read -r && out+=( "$REPLY" )
  done
  if (( ${#out[@]} > 0 )); then
    output_lines=$(printf '%s ' "${out[@]}")
    blocks+=("$output_lines")
  fi
  if (( ${#out[@]} < $count_lines )); then break; fi
done < "$input"

# Find words in blocks
fg_red="$(tput setaf 1)"
bold="$(tput bold)"
reset="$(tput sgr0)"
max_count_lines=$(wc -l "$input" | cut -d' ' -f1)
for (( i=0; i<${#blocks[@]}; i++ )); do
  matched=$(echo "${blocks[$i]}" | \
      agrep ".*($word1.*$word2|$word2.*$word1).*")
  if [[ -n "$matched" ]]; then
    # Calculate line numbers from block index
    range_begin=$(($(($i * $count_lines)) + 1))
    range_end="$(($(($i + 1)) * $count_lines))"
    if [[ $range_end -gt $max_count_lines ]]; then
      range_end=$max_count_lines
    fi
    range="$range_begin,$range_end"

    # Header
    echo "${bold}$input[$range]:${reset}"

    # Color matching words
    range_output=$(sed -n "$range""p" "$input")
    range_output=$(echo "$range_output" | sed \
        "s/$word1/${fg_red}${bold}$word1${reset}/g")
    range_output=$(echo "$range_output" | sed \
        "s/$word2/${fg_red}${bold}$word2${reset}/g")

    # Lines
    echo "$range_output"
  fi
done
